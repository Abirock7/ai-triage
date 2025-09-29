from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from app.core.auth import require_api_key
from app.core.db import init_db, insert_scan, list_scans, get_scan
from app.core.nmap_parser import parse_nmap_xml
from app.core.llm_adapter import generate_triage
from app.core.nmap_runner import run_nmap_scan, InvalidTarget, NmapNotFound, NmapFailed
from fastapi import Body
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse  # (we’ll use this in part B)
from datetime import datetime
import os, json

app = FastAPI(title="AI-Powered Security Triage - Pilot")
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version="0.1.0",
        description="AI-Powered Security Triage - Pilot",
        routes=app.routes,
    )
    # Add API key security scheme
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["ApiKeyAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": "x-api-key",
    }
    # Apply it globally so /docs shows the Authorize lock icon
    openapi_schema["security"] = [{"ApiKeyAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.on_event("startup")
async def startup_event():
    await init_db()

@app.get("/health")
def health(api_user: str = Depends(require_api_key)):
    return {"status": "ok", "user": api_user}

@app.post("/scan")
async def upload_scan(
    file: UploadFile = File(...),
    api_user: str = Depends(require_api_key)
):
    if not file.filename.lower().endswith(".xml"):
        raise HTTPException(status_code=400, detail="Please upload an Nmap XML file (.xml)")

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(UPLOAD_DIR, f"scan_{ts}.xml")

    # Save uploaded XML
    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)

    # Parse Nmap XML
    try:
        parsed = parse_nmap_xml(dest)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse XML: {e}")

    # Extract first IP if present
    ip = None
    if parsed.get("hosts"):
        ip = parsed["hosts"][0].get("address")

    # Generate triage (mock LLM)
    triage = generate_triage(parsed)
    llm_summary_text = json.dumps(triage)

    # Store in DB
    scan_id = await insert_scan(
        ip=ip,
        created_at=datetime.utcnow().isoformat(),
        xml_path=dest,
        parsed_json=json.dumps(parsed),
        llm_summary=llm_summary_text
    )

    return JSONResponse({"scan_id": scan_id, "ip": ip, "hosts": len(parsed.get("hosts", []))})
@app.post("/scan/run")
async def run_scan(
    payload: dict = Body(...),
    api_user: str = Depends(require_api_key)
):
    """
    Runs nmap on a single IP, parses + triages, stores, returns scan_id.
    Body: { "ip": "1.2.3.4" }
    """
    ip = (payload.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="Body must include 'ip'")

    # run nmap safely
    try:
        xml_path = run_nmap_scan(ip)
    except InvalidTarget as e:
        raise HTTPException(status_code=400, detail=str(e))
    except NmapNotFound as e:
        raise HTTPException(status_code=500, detail=str(e))
    except NmapFailed as e:
        raise HTTPException(status_code=500, detail=str(e))

    # parse & triage
    try:
        parsed = parse_nmap_xml(xml_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse XML: {e}")

    # pull first host ip if present
    ip_from_xml = None
    if parsed.get("hosts"):
        ip_from_xml = parsed["hosts"][0].get("address") or ip

    triage = generate_triage(parsed)
    llm_summary_text = json.dumps(triage)

    # store
    scan_id = await insert_scan(
        ip=ip_from_xml,
        created_at=datetime.utcnow().isoformat(),
        xml_path=xml_path,
        parsed_json=json.dumps(parsed),
        llm_summary=llm_summary_text
    )

    return JSONResponse({"scan_id": scan_id, "ip": ip_from_xml, "hosts": len(parsed.get("hosts", []))})

@app.get("/scans")
async def scans(api_user: str = Depends(require_api_key)):
    return await list_scans()
@app.get("/ui", response_class=HTMLResponse)
def ui_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>AI Security Triage - Pilot</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  body { font-family: system-ui, Arial, sans-serif; margin: 24px; }
  .row { display:flex; gap:16px; align-items:center; margin-bottom: 12px; }
  input, button { padding:8px; font-size:14px; }
  button { cursor:pointer; }
  .grid { display:grid; grid-template-columns: 1fr 2fr; gap: 24px; margin-top: 16px; }
  .card { border:1px solid #ddd; border-radius:10px; padding:16px; }
  .badge { padding:2px 8px; border-radius:999px; font-size:12px; display:inline-block; }
  .Low { background:#eef6ff; color:#1d4ed8; }
  .Medium { background:#fff7ed; color:#c2410c; }
  .High { background:#fef2f2; color:#b91c1c; }
  .Critical { background:#111827; color:#fde68a; }
  table { width:100%; border-collapse: collapse; }
  th, td { border-bottom:1px solid #eee; padding: 8px; text-align:left; font-size: 14px;}
  pre { background:#f6f8fa; padding:12px; border-radius:8px; overflow:auto; }
</style>
</head>
<body>
  <h1>AI-Powered Security Triage — Pilot</h1>
  <div class="row">
    <input id="apikey" placeholder="x-api-key (e.g., demo-key-1)" size="32" />
    <button onclick="loadScans()">Load Scans</button>
    <label for="file">Upload Nmap XML:</label>
    <input type="file" id="file" accept=".xml" />
    <button onclick="uploadScan()">Upload</button>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Scans</h3>
      <div id="scans">No scans yet.</div>
    </div>
    <div class="card">
      <h3>Details</h3>
      <div id="detail">Select a scan to view details.</div>
    </div>
  </div>

<script>
async function loadScans() {
  const key = document.getElementById('apikey').value.trim();
  if(!key) { alert('Enter API key'); return; }
  const res = await fetch('/scans', { headers: {'x-api-key': key }});
  if(!res.ok){ document.getElementById('scans').textContent = 'Error: '+res.status; return; }
  const data = await res.json();
  if(!data.length){ document.getElementById('scans').textContent = 'No scans found'; return; }
  document.getElementById('scans').innerHTML = data.map(
    s => `<div><a href="#" onclick="viewScan(${s.id});return false;">#${s.id}</a> — ${s.ip ?? '(no ip)'} <small>${s.created_at}</small></div>`
  ).join('');
}

async function viewScan(id) {
  const key = document.getElementById('apikey').value.trim();
  const res = await fetch('/scans/'+id, { headers: {'x-api-key': key }});
  const d = await res.json();
  if(!res.ok){ document.getElementById('detail').textContent = 'Error '+res.status+': '+(d.detail||''); return; }

  const parsedHosts = (d.parsed?.hosts||[]).map(h => {
    const ports = (h.ports||[]).map(p => 
      `<tr><td>${p.port}</td><td>${p.protocol||''}</td><td>${p.state||''}</td><td>${p.service_name||''}</td></tr>`
    ).join('');
    return `<h4>Host ${h.address || '(unknown)'}</h4>
            <table>
              <thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead>
              <tbody>${ports}</tbody>
            </table>`;
  }).join('');

  const findings = (d.triage?.findings||[]).map(f => `
    <div style="margin-bottom:12px;">
      <div><span class="badge ${f.severity}">${f.severity}</span> Port ${f.port} — ${f.service||''} — ${f.host||''}</div>
      <div><small>${f.evidence||''}</small></div>
      <ul>${(f.recommendations||[]).map(r=>`<li>${r}</li>`).join('')}</ul>
    </div>
  `).join('');

  document.getElementById('detail').innerHTML = `
    <p><b>Scan #${d.id}</b> — IP: ${d.ip ?? '(none)'} — <small>${d.created_at}</small></p>
    <p><b>Summary:</b> ${d.triage?.summary || '—'}</p>
    <h4>Triage Findings</h4>
    ${findings || '<em>No findings.</em>'}
    <h4>Parsed</h4>
    ${parsedHosts || '<em>No hosts.</em>'}
    <details>
      <summary>Raw JSON</summary>
      <pre>${escapeHTML(JSON.stringify(d, null, 2))}</pre>
    </details>
  `;
}

function escapeHTML(s){ return s.replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

async function uploadScan(){
  const key = document.getElementById('apikey').value.trim();
  const f = document.getElementById('file').files[0];
  if(!key){ alert('Enter API key'); return; }
  if(!f){ alert('Choose an .xml file'); return; }
  const form = new FormData(); form.append('file', f);
  const res = await fetch('/scan', { method:'POST', headers: {'x-api-key': key }, body: form });
  const data = await res.json();
  if(!res.ok){ alert('Upload failed: '+(data.detail||res.status)); return; }
  alert('Uploaded scan_id='+data.scan_id);
  loadScans();
}
</script>
</body>
</html>
    """

@app.get("/scans/{scan_id}")
async def scan_detail(scan_id: int, api_user: str = Depends(require_api_key)):
    row = await get_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")

    parsed = json.loads(row["parsed_json"]) if row.get("parsed_json") else None
    triage_obj = json.loads(row["llm_summary"]) if row.get("llm_summary") else None

    return {
        "id": row["id"],
        "ip": row["ip"],
        "created_at": row["created_at"],
        "xml_path": row["xml_path"],
        "parsed": parsed,
        "triage": triage_obj
    }
