# main.py
from __future__ import annotations

import os, io, csv, json, re, asyncio, datetime as dt
from pathlib import Path
from typing import List, Dict, Any, Optional
from enum import Enum
import os, logging  # (keep your other imports)

API_KEYS = set(os.getenv("API_KEYS", "demo-key-1").split(","))
TRIAGE_PROVIDER = os.getenv("TRIAGE_PROVIDER", "rules").lower()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")

# If Gemini is requested but no key is present, fall back gracefully.
if TRIAGE_PROVIDER == "gemini" and not GOOGLE_API_KEY:
    logging.warning("GOOGLE_API_KEY not set; falling back to 'rules' triage provider.")
    TRIAGE_PROVIDER = "rules"

# XML parsing (defused for safety)
from defusedxml import ElementTree as ET

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query, Header
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
import aiosqlite

# Optional Gemini (Google) analysis
try:
    import google.generativeai as genai  # pip install google-generativeai==0.7.2
except Exception:
    genai = None

# -----------------------------
# Paths & config
# -----------------------------
DATA_DIR = Path(os.getenv("DB_DIR", "/app/data"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/app/uploads"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.getenv("DB_PATH", DATA_DIR / "triage.db"))
TRIAGE_PROVIDER = os.getenv("TRIAGE_PROVIDER", "rules").lower()  # rules | gemini | mock

API_KEYS = [k.strip() for k in os.getenv("API_KEYS", "demo-key-1,team-key-2").split(",") if k.strip()]
if not API_KEYS:
    API_KEYS = ["demo-key-1"]
USER_FOR_KEY = {API_KEYS[0]: "user"}
if len(API_KEYS) > 1:
    USER_FOR_KEY[API_KEYS[1]] = "team"

app = FastAPI(title="AI-Powered Security Triage — Pilot")

# Perf middlewares
app.add_middleware(GZipMiddleware, minimum_size=512)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# -----------------------------
# DB setup / helpers
# -----------------------------
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    created_at TEXT,
    xml_path TEXT,
    parsed_json TEXT,
    llm_summary TEXT,
    source TEXT
);
"""
CREATE_IDX = [
    "CREATE INDEX IF NOT EXISTS idx_scans_id_desc ON scans(id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)"
]

async def ensure_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA temp_store=MEMORY")
        await db.execute(CREATE_SQL)
        # migrate: ensure 'source' exists
        cur = await db.execute("PRAGMA table_info(scans)")
        cols = [r[1] for r in await cur.fetchall()]
        if "source" not in cols:
            await db.execute("ALTER TABLE scans ADD COLUMN source TEXT")
        for sql in CREATE_IDX:
            await db.execute(sql)
        await db.commit()

@app.on_event("startup")
async def _startup():
    await ensure_db()

async def insert_scan(ip: str, xml_path: Optional[str], parsed: dict, triage: dict, source: str) -> int:
    now = dt.datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO scans (ip, created_at, xml_path, parsed_json, llm_summary, source) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, now, xml_path or "", json.dumps(parsed), json.dumps(triage), source),
        )
        await db.commit()
        return cur.lastrowid

async def list_scans(limit: int = 200, offset: int = 0, ip: Optional[str] = None) -> List[Dict[str, Any]]:
    sql = "SELECT id, ip, created_at, source FROM scans"
    args: list[Any] = []
    if ip:
        sql += " WHERE ip = ?"
        args.append(ip)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(sql, tuple(args))
        rows = await cur.fetchall()
    return [{"id": r[0], "ip": r[1], "created_at": r[2], "source": r[3] or ""} for r in rows]

async def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id, ip, created_at, xml_path, parsed_json, llm_summary, source FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = await cur.fetchone()
    if not row:
        return None
    return {"id": row[0], "ip": row[1], "created_at": row[2], "xml_path": row[3],
            "parsed_json": row[4], "llm_summary": row[5], "source": row[6] or ""}

# -----------------------------
# Auth
# -----------------------------
def require_api_key(x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return USER_FOR_KEY.get(x_api_key, "user")

# -----------------------------
# Utils
# -----------------------------
def now_ts() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S")

def is_ip_or_host(target: str) -> bool:
    return bool(target) and re.match(r"^[A-Za-z0-9\.\-:]+$", target) is not None

async def run_cmd_async(*cmd: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await proc.communicate()
    return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

def _safe_float(x: Optional[str]) -> Optional[float]:
    try:
        if x is None: return None
        return float(str(x).strip())
    except Exception:
        return None


# -----------------------------
# Parsers
# -----------------------------
def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall(".//host"):
        st = h.find("status")
        if st is not None and st.get("state") == "down":
            continue
        addr_node = h.find("address[@addrtype='ipv4']") or h.find("address")
        address = addr_node.get("addr") if addr_node is not None else ""
        ports_arr = []
        for p in h.findall(".//ports/port"):
            try:
                portid = int(p.get("portid"))
            except Exception:
                continue
            proto = p.get("protocol") or "tcp"
            state = (p.find("state").get("state") if p.find("state") is not None else "")
            svc = p.find("service")
            service_name = svc.get("name") if svc is not None else ""
            product = svc.get("product") if svc is not None else ""
            version = svc.get("version") if svc is not None else ""
            if state == "open":
                ports_arr.append({
                    "port": portid, "protocol": proto, "state": state,
                    "service_name": service_name, "product": product, "version": version
                })
        hosts.append({"address": address, "ports": ports_arr})
    return {"hosts": hosts}

def parse_nessus(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    hosts = []
    findings = []
    for host in root.findall(".//ReportHost"):
        hostname = host.get("name") or ""
        ip = hostname
        for tag in host.findall("HostProperties/tag"):
            if tag.get("name") == "host-ip":
                ip = (tag.text or hostname).strip()
        for item in host.findall("ReportItem"):
            sev_int = int(item.get("severity", "0"))
            severity = {0:"Low",1:"Low",2:"Medium",3:"High",4:"Critical"}.get(sev_int, "Low")
            port = int(item.get("port","0") or 0)
            proto = item.get("protocol","")
            svc = item.get("svc_name","") or item.get("service_name","")
            plugin = item.get("pluginName","") or ""
            cves = [c.text.strip() for c in item.findall("cve") if (c.text or "").strip()]
            cvss3 = _safe_float(item.findtext("cvss3_base_score")) or _safe_float(item.get("cvss3_base_score"))
            cvss2 = _safe_float(item.findtext("cvss_base_score")) or _safe_float(item.get("cvss_base_score"))
            cvss = cvss3 if cvss3 is not None else (cvss2 if cvss2 is not None else None)
            desc_node = item.find("description")
            desc = (desc_node.text or plugin).strip() if desc_node is not None else plugin
            findings.append({
                "host": ip, "port": port, "protocol": proto, "service": svc,
                "severity": severity, "evidence": desc, "recommendations": [],
                "cves": cves, "cvss": cvss
            })
        hosts.append({"address": ip, "ports": []})
    return {"hosts": hosts, "findings": findings}

# -----------------------------
# Rule-based triage (fast, offline)
# -----------------------------
def rules_triage(parsed: Dict[str, Any]) -> Dict[str, Any]:
    findings = []
    for h in parsed.get("hosts", []):
        addr = h.get("address","")
        for p in h.get("ports", []):
            port = p.get("port")
            svc = (p.get("service_name") or "").lower()
            sev = "Low"; recs: List[str] = []; evid = ""
            if port in (23, 3389, 445): sev = "High"
            if port in (21, 25, 110):   sev = "Medium"
            if port == 22:              sev = "Medium"; recs.append("Harden SSH (key auth, disable root).")
            if port in (80, 8080):      recs.append("Force HTTPS; review headers/HSTS.")
            if port == 443:             recs.append("Tighten TLS; disable weak ciphers.")
            if svc in ("telnet","vnc","mysql","mssql"): sev = "High"
            if port == 3389:
                evid = "RDP exposed; ensure NLA; patch CVE-2019-0708."
                recs.append("Restrict to VPN; enable NLA.")
            est_cvss = {"Low":3.3, "Medium":5.5, "High":8.8, "Critical":9.8}.get(sev, 3.3)
            findings.append({
                "host": addr, "port": port, "service": p.get("service_name",""),
                "severity": sev, "evidence": evid, "recommendations": recs,
                "cvss": est_cvss
            })
    host_cnt = len(parsed.get("hosts", []))
    open_ports = sum(len(h.get("ports", [])) for h in parsed.get("hosts", []))
    top = findings[0] if findings else None
    top_str = f"{top.get('service') or 'service'} on {top.get('host')} (port {top.get('port')})" if top else "none"
    return {"summary": f"{host_cnt} host(s) scanned; {open_ports} open port(s). Top concern: {top_str}",
            "risk_overview": "Network surface review based on open ports and common misconfigurations.",
            "findings": findings}

# -----------------------------
# Gemini provider (optional)
# -----------------------------
GEM_MODEL = "gemini-1.5-pro"

def gemini_model():
    if genai is None:
        raise RuntimeError("google-generativeai is not installed")
    api = os.getenv("GOOGLE_API_KEY")
    if not api:
        raise RuntimeError("GOOGLE_API_KEY not set")
    genai.configure(api_key=api)
    return genai.GenerativeModel(GEM_MODEL)

def build_gemini_prompt(scan_obj: dict) -> str:
    # Plain string (not f-string in HTML response to avoid backslash issues elsewhere)
    scan_json = json.dumps(scan_obj, ensure_ascii=False)
    prompt = (
        "You are a security analyst. Given a network scan JSON, produce:\n"
        "1) A short risk_overview paragraph (business impact).\n"
        "2) findings[]: items with fields: host, port, service, severity (Low/Medium/High/Critical),\n"
        "   evidence (1-2 sentences), recommendations (array, concise), optional cvss (0-10 float).\n"
        "3) summary: short executive sentence.\n\n"
        "Output STRICTLY this JSON schema:\n"
        "{\n"
        '  "summary": "...",\n'
        '  "risk_overview": "...",\n'
        '  "findings": [\n'
        "    {\n"
        '      "host": "ip or hostname",\n'
        '      "port": 443,\n'
        '      "service": "https",\n'
        '      "severity": "High",\n'
        '      "evidence": "TLS RC4 supported",\n'
        '      "recommendations": ["Disable RC4", "Enable modern ciphers"],\n'
        '      "cvss": 7.1\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Here is the scan json:\n"
        f"{scan_json}"
    )
    return prompt

async def analyze_with_gemini(scan_obj: dict) -> dict:
    mdl = gemini_model()
    prompt = build_gemini_prompt(scan_obj)
    resp = await asyncio.to_thread(mdl.generate_content, prompt)
    text = getattr(resp, "text", "") or ""
    triage = {}
    try:
        triage = json.loads(text)
        if not isinstance(triage, dict):
            triage = {}
    except Exception:
        triage = {}
    findings = triage.get("findings") or []
    norm = []
    cvss_by_host: Dict[str, float] = {}
    for f in findings:
        host = str(f.get("host") or scan_obj.get("ip") or "")
        port = int(str(f.get("port") or "0") or 0)
        svc  = str(f.get("service") or "")
        sev  = str(f.get("severity") or "Low").title()
        ev   = str(f.get("evidence") or "")
        recs = f.get("recommendations") or []
        cvss = f.get("cvss")
        if isinstance(cvss, (int, float)):
            try:
                cv = float(cvss)
                cvss_by_host[host] = max(cvss_by_host.get(host, 0.0), cv)
            except Exception:
                pass
        norm.append({
            "host": host, "port": port, "service": svc,
            "severity": sev, "evidence": ev, "recommendations": recs
        })
    return {
        "summary": triage.get("summary") or "",
        "risk_overview": triage.get("risk_overview") or "",
        "findings": norm,
        "cvss_by_host": cvss_by_host
    }

async def run_triage(scan_ip: str, parsed: dict, source: str) -> dict:
    # Provider switch
    if TRIAGE_PROVIDER == "gemini":
        try:
            scan_obj = {"id": 0, "ip": scan_ip, "created_at": dt.datetime.utcnow().isoformat(),
                        "parsed": parsed, "source": source}
            return await analyze_with_gemini(scan_obj)
        except Exception as e:
            # fail safe back to rules
            return rules_triage(parsed)
    elif TRIAGE_PROVIDER == "rules":
        return rules_triage(parsed)
    else:
        # mock/demo
        return {"summary":"Demo triage (mock).","risk_overview":"Demo only.","findings":[]}

# -----------------------------
# Scan types
# -----------------------------
class ScanType(str, Enum):
    tcp_full = "tcp_full"
    udp = "udp"
    advanced = "advanced"

class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = ScanType.tcp_full
    advanced_flags: Optional[str] = None

def flags_for_scan_type(req: ScanRequest) -> list[str]:
    common = ["-T4", "--version-light", "-Pn", "--host-timeout", "20s"]
    if req.scan_type == ScanType.tcp_full:
        return ["-sV", "-p-", *common]
    if req.scan_type == ScanType.udp:
        return ["-sU", "-F", "--reason", *common]
    # advanced
    extra = (req.advanced_flags or "").split()
    disallow = {"--script", "-iR", "--dns-servers"}
    extra = [f for f in extra if f not in disallow]
    return [*extra, *common]

# -----------------------------
# CSV flattener
# -----------------------------
def _flatten_findings(scan_obj: dict):
    findings = (scan_obj.get("triage") or {}).get("findings") or []
    if not findings:
        yield [scan_obj["id"], scan_obj["ip"], scan_obj["created_at"], "", "", "", "", ""]
        return
    for f in findings:
        yield [
            scan_obj["id"], scan_obj["ip"], scan_obj["created_at"],
            str(f.get("host") or ""), str(f.get("port") or ""),
            str(f.get("service") or ""), str(f.get("severity") or ""),
            str(f.get("evidence") or "")
        ]

# -----------------------------
# API endpoints
# -----------------------------
@app.get("/health")
async def health(user: str = Depends(require_user)):
    return {"status": "ok", "user": user}

@app.get("/readyz")
async def readyz():
    # super lightweight readiness; no auth, so CI can hit it
    return {"status": "ok"}

@app.get("/scans")
async def scans(api_user: str = Depends(require_api_key), limit: int = 200, offset: int = 0, ip: Optional[str] = None):
    return await list_scans(limit, offset, ip)

@app.get("/scans/{scan_id}")
async def scan_detail(scan_id: int, api_user: str = Depends(require_api_key)):
    row = await get_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    parsed = json.loads(row["parsed_json"]) if row.get("parsed_json") else None
    triage_obj = json.loads(row["llm_summary"]) if row.get("llm_summary") else None
    return {"id": row["id"], "ip": row["ip"], "created_at": row["created_at"], "source": row.get("source") or "",
            "parsed": parsed, "triage": triage_obj}

@app.post("/scan/run")
async def run_scan(req: ScanRequest, api_user: str = Depends(require_api_key)):
    target = (req.target or "").strip()
    if not is_ip_or_host(target):
        raise HTTPException(status_code=400, detail="Invalid IP/hostname")
    ts = now_ts()
    out_path = UPLOAD_DIR / f"nmap_{target}_{ts}.xml"
    flags = flags_for_scan_type(req)
    cmd = ["nmap", *flags, target, "-oX", str(out_path)]
    code, _out, err = await run_cmd_async(*cmd)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"nmap error: {err[-400:]}")
    xml_text = out_path.read_text(encoding="utf-8", errors="ignore")
    parsed = parse_nmap_xml(xml_text)
    triage = await run_triage(target, parsed, source="nmap")
    sid = await insert_scan(target, str(out_path), parsed, triage, source="nmap")
    return {"scan_id": sid, "ip": target, "hosts": len(parsed.get("hosts", []))}

@app.post("/upload")
async def upload_nmap_xml(file: UploadFile = File(...), api_user: str = Depends(require_api_key)):
    if not file.filename.lower().endswith(".xml"):
        raise HTTPException(status_code=400, detail="Expected an Nmap XML file")
    ts = now_ts()
    out_path = UPLOAD_DIR / f"upload_nmap_{ts}.xml"
    out_path.write_bytes(await file.read())
    xml_text = out_path.read_text(encoding="utf-8", errors="ignore")
    parsed = parse_nmap_xml(xml_text)
    ip = parsed.get("hosts", [{}])[0].get("address","") or "unknown"
    triage = await run_triage(ip, parsed, source="nmap")
    sid = await insert_scan(ip, str(out_path), parsed, triage, source="nmap")
    return {"scan_id": sid, "ip": ip}

@app.post("/upload/nessus")
async def upload_nessus(file: UploadFile = File(...), api_user: str = Depends(require_api_key)):
    if not (file.filename.lower().endswith(".nessus") or file.filename.lower().endswith(".xml")):
        raise HTTPException(status_code=400, detail="Expected a Nessus .nessus (XML) file")
    ts = now_ts()
    out_path = UPLOAD_DIR / f"upload_nessus_{ts}.nessus"
    out_path.write_bytes(await file.read())
    xml_text = out_path.read_text(encoding="utf-8", errors="ignore")
    parsed_nessus = parse_nessus(xml_text)
    findings = parsed_nessus.get("findings", [])
    host_set = {f.get("host","") for f in findings if f.get("host")}
    host_cnt = len(host_set)
    triage = {"summary": f"Nessus: {len(findings)} finding(s) across {host_cnt} host(s).",
              "risk_overview": "Imported from Nessus.",
              "findings": findings}
    ip = next(iter(host_set), "nessus-multi")
    sid = await insert_scan(ip, str(out_path), {"hosts": parsed_nessus.get("hosts", [])}, triage, source="nessus")
    return {"scan_id": sid, "ip": ip, "findings": len(findings)}

# CSV export: single scan
@app.get("/scans/{scan_id}/export.csv")
async def export_scan_csv(scan_id: int, api_user: str = Depends(require_api_key)):
    row = await get_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    parsed = json.loads(row["parsed_json"]) if row.get("parsed_json") else None
    triage_obj = json.loads(row["llm_summary"]) if row.get("llm_summary") else None
    scan_obj = {"id": row["id"], "ip": row["ip"], "created_at": row["created_at"], "parsed": parsed, "triage": triage_obj}
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["scan_id","ip","created_at","host","port","service","severity","evidence"])
    for r in _flatten_findings(scan_obj): w.writerow(r)
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'})

# CSV export: all scans (optionally can filter with ?ip=)
@app.get("/scans/export.csv")
async def export_all_csv(api_user: str = Depends(require_api_key),
                         limit: int = Query(5000, ge=1, le=50000),
                         offset: int = Query(0, ge=0),
                         ip: Optional[str] = None):
    scans = await list_scans(limit=limit, offset=offset, ip=ip)
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["scan_id","ip","created_at","host","port","service","severity","evidence"])
    for s in scans:
        row = await get_scan(s["id"])
        if not row: continue
        parsed = json.loads(row["parsed_json"]) if row.get("parsed_json") else None
        triage_obj = json.loads(row["llm_summary"]) if row.get("llm_summary") else None
        scan_obj = {"id": row["id"], "ip": row["ip"], "created_at": row["created_at"], "parsed": parsed, "triage": triage_obj}
        for r in _flatten_findings(scan_obj): w.writerow(r)
    buf.seek(0)
    name = f'scans_export{"_"+ip if ip else ""}.csv'
    return StreamingResponse(buf, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})

# Stats endpoint driving the dashboard (supports ?ip= filter)
@app.get("/stats")
async def stats(
    api_user: str = Depends(require_api_key),
    limit: int = 1000,
    offset: int = 0,
    ip: Optional[str] = Query(None, description="Optional IP filter for charts")
):
    scans = await list_scans(limit=limit, offset=offset)
    ids = [s["id"] for s in scans]

    severity = {"Low":0,"Medium":0,"High":0,"Critical":0}
    sources = {"nmap":0, "nessus":0, "other":0}
    ports: Dict[int,int] = {}
    hosts_set = set()
    total_findings = 0
    last = None
    scan_count = 0
    host_cvss: Dict[str, float] = {}

    for sid in ids:
        row = await get_scan(sid)
        if not row:
            continue
        parsed = json.loads(row["parsed_json"]) if row.get("parsed_json") else {}
        triage = json.loads(row["llm_summary"]) if row.get("llm_summary") else {"findings":[]}

        include = True
        if ip:
            include = (row["ip"] == ip)
            if not include:
                for h in parsed.get("hosts", []):
                    if h.get("address") == ip:
                        include = True; break
            if not include:
                for f in triage.get("findings", []):
                    if f.get("host") == ip:
                        include = True; break
        if not include:
            continue

        if last is None:
            last = {"id": row["id"], "ip": row["ip"], "created_at": row["created_at"]}
        scan_count += 1

        src = (row.get("source") or "").lower()
        if src in sources: sources[src] += 1
        else: sources["other"] = sources.get("other",0) + 1

        for h in parsed.get("hosts", []):
            if h.get("address"): hosts_set.add(h["address"])
            for p in h.get("ports", []):
                if p.get("port") is not None:
                    ports[p["port"]] = ports.get(p["port"],0)+1

        for f in triage.get("findings", []):
            sev = f.get("severity")
            if sev in severity: severity[sev] += 1
            total_findings += 1
            host = f.get("host") or ""
            score = f.get("cvss")
            if isinstance(score, (int,float)):
                host_cvss[host] = max(host_cvss.get(host, 0.0), float(score))

    top_ports = sorted(ports.items(), key=lambda kv: kv[1], reverse=True)[:10]
    cvss_by_host = sorted(host_cvss.items(), key=lambda kv: kv[1], reverse=True)[:10]
    cvss_list = [{"host": h, "score": round(s, 1)} for h, s in cvss_by_host]

    if ip:
        hosts_set = {ip} if scan_count else set()

    return {
        "total_scans": scan_count if ip else len(scans),
        "unique_hosts": len(hosts_set),
        "total_findings": total_findings,
        "severity": severity,
        "sources": sources,
        "top_ports": [{"port": k, "count": v} for k,v in top_ports],
        "cvss_by_host": cvss_list,
        "last_scan": last,
        "filter_ip": ip or ""
    }

# -----------------------------
# Web UI (single page app)
# -----------------------------
@app.get("/ui", response_class=HTMLResponse)
def ui_page():
    # NOTE: plain string literal (not f-string) to avoid f-string/backslash issues.
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>AI Security Triage — Pilot</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/jspdf@2.5.1/dist/jspdf.umd.min.js"></script>
  <style>
    :root{
      --bg:#eaf4ff; --panel:#ffffff; --text:#0f172a; --muted:#5b6473; --border:#e6e8ef; --accent:#2563eb;
      --low:#16a34a; --med:#f59e0b; --high:#f97316; --crit:#ef4444; --chip:#eef2ff; --paneH: 420px;
    }
    *{ box-sizing:border-box; }
    body{ margin:0; background:var(--bg); color:var(--text);
      font-family:Inter, ui-sans-serif, system-ui, Segoe UI, Roboto, Ubuntu, Arial;
      font-size:16px; line-height:1.35; }
    header{ background:#fff; border-bottom:1px solid var(--border); padding:18px 22px; position:sticky; top:0; z-index:10;}
    h1{ margin:0; font-weight:700; font-size:22px; }
    h3{ margin:0 0 8px 0; font-size:18px; }
    .toolbar{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; padding:14px 22px; }
    input[type=text]{ background:#fff; border:1px solid var(--border); color:var(--text); padding:10px 12px; border-radius:10px;}
    input[type=file]{ color:var(--muted); }
    select{ padding:9px 10px; border:1px solid var(--border); border-radius:10px; background:#fff; }
    button{ background:var(--chip); border:1px solid var(--border); color:var(--text);
      padding:10px 14px; border-radius:10px; cursor:pointer;}
    button:hover{ border-color:var(--accent); }
    .grid{ display:grid; grid-template-columns: repeat(12, 1fr); gap:16px; padding:0 22px 22px; }
    .col-12{ grid-column: span 12; } .col-6{ grid-column: span 6; } .col-4{ grid-column: span 4; } .col-8{ grid-column: span 8; }
    @media (max-width:1100px){ .col-6,.col-8,.col-4{grid-column:span 12;} }
    .panel{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px 16px;
      box-shadow:0 2px 6px rgba(15,23,42,0.05);}
    .cards{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
    @media (max-width:1100px){ .cards{ grid-template-columns:repeat(2,1fr); } }
    .card{ background:#fff; border:1px solid var(--border); border-radius:12px; padding:12px 14px; }
    .big{ font-size:28px; font-weight:700; }
    .small{ color:var(--muted); font-size:14px; }
    .badge{ display:inline-block; font-size:12px; padding:3px 8px; border-radius:999px; margin-right:6px; color:#fff; }
    .Low{ background:var(--low); } .Medium{ background:var(--med); } .High{ background:var(--high); } .Critical{ background:var(--crit); }
    .list{ max-height:var(--paneH); overflow:auto; }
    table{ width:100%; border-collapse:collapse; font-size:14px; }
    th, td{ padding:6px 8px; border-bottom:1px solid var(--border); text-align:left; }
    .panel canvas{ max-height:280px !important; }
    .mutebar{ color:var(--muted); }
    a{ color:#1d4ed8; text-decoration:none;} a:hover{ text-decoration:underline; }
    .pill{ background:#dbeafe; border:1px solid #bfdbfe; color:#1e3a8a; padding:6px 10px; border-radius:999px; }
  </style>
</head>
<body>
  <header>
    <h1>AI-Powered Security Triage — Pilot</h1>
  </header>

  <div class="toolbar">
    <input id="apikey" type="text" placeholder="x-api-key (e.g., demo-key-1)" size="22" />
    <button onclick="loadAll()">Load</button>

    <span class="mutebar">•</span>
    <span class="small">Scan target:</span>
    <input id="scanTarget" type="text" placeholder="8.8.8.8 or scanme.nmap.org" size="22" />
    <label>Type:
      <select id="scanType">
        <option value="tcp_full">TCP Full</option>
        <option value="udp">UDP (fast)</option>
        <option value="advanced">Advanced</option>
      </select>
    </label>
    <input id="advancedFlags" placeholder="e.g. -sS -p 1-1000 --top-ports 200" size="26" style="display:none;">
    <button onclick="scanTargetBtn()">Scan Target</button>

    <span class="mutebar">•</span>
    <span class="small">Nmap XML:</span>
    <input type="file" id="fileNmap" accept=".xml" />
    <button onclick="uploadXml()">Upload</button>

    <span class="mutebar">•</span>
    <span class="small">Nessus:</span>
    <input type="file" id="fileNessus" accept=".nessus,.xml" />
    <button onclick="uploadNessus()">Upload</button>

    <span style="flex:1 1 auto"></span>
    <span id="filterIndicator" class="pill" style="display:none;"></span>
    <button id="clearBtn" onclick="clearFilter()" style="display:none;">Clear Filter</button>

    <span class="mutebar">•</span>
    <select id="dlFmt">
      <option value="pdf" selected>PDF</option>
      <option value="png">PNG</option>
    </select>
    <button onclick="downloadScanReport()">Download (scan)</button>
    <button onclick="downloadIpReport()">Download (IP)</button>
    <button onclick="downloadDashboardReport()">Download (all)</button>

    <span class="mutebar">•</span>
    <button onclick="downloadAllCsv()">Download CSV (all)</button>
    <button onclick="downloadCurrentCsv()">Download CSV (current)</button>
  </div>

  <div id="dashwrap" class="grid">
    <div class="col-12 panel">
      <div class="cards">
        <div class="card"><div class="small">Total Scans</div><div id="kpi_scans" class="big">0</div></div>
        <div class="card"><div class="small">Unique Hosts</div><div id="kpi_hosts" class="big">0</div></div>
        <div class="card"><div class="small">Total Findings</div><div id="kpi_findings" class="big">0</div></div>
        <div class="card"><div class="small">Last Scan</div><div id="kpi_last" class="big small">—</div></div>
      </div>
    </div>

    <div class="col-6 panel">
      <h3 id="sevTitle">Severity (all scans)</h3>
      <div class="small">
        <span class="badge Low">Low</span>
        <span class="badge Medium">Medium</span>
        <span class="badge High">High</span>
        <span class="badge Critical">Critical</span>
      </div>
      <canvas id="sevAllBar" height="190"></canvas>
    </div>

    <div class="col-6 panel">
      <h3 id="srcTitle">Sources</h3>
      <canvas id="srcPie" height="210"></canvas>
    </div>

    <div class="col-12 panel">
      <h3 id="cvssTitle">CVSS by Host (max per host, 0–10)</h3>
      <canvas id="cvssBar" height="210"></canvas>
    </div>

    <div class="col-12 panel">
      <h3 id="portsTitle">Top Open Ports</h3>
      <canvas id="portsBar" height="200"></canvas>
    </div>

    <div class="col-4 panel list">
      <h3>Scans</h3>
      <div id="scans" class="small">No scans yet.</div>
    </div>

    <div class="col-8 panel list">
      <h3>Details</h3>
      <div id="detail" class="small">Select a scan to view details.</div>
    </div>
  </div>

<script>
Chart.defaults.font.size = 15;
Chart.defaults.animation = false;

const sevOrder=['Low','Medium','High','Critical'];
const sevColors={ Low:'rgba(22,163,74,0.85)', Medium:'rgba(245,158,11,0.90)', High:'rgba(249,115,22,0.95)', Critical:'rgba(239,68,68,0.95)' };
const sevBorders={ Low:'rgba(22,163,74,1)',   Medium:'rgba(245,158,11,1)',   High:'rgba(249,115,22,1)',   Critical:'rgba(239,68,68,1)' };

function colorForScore(s){
  if(s >= 9.0) return 'rgba(239,68,68,0.95)';
  if(s >= 7.0) return 'rgba(249,115,22,0.95)';
  if(s >= 4.0) return 'rgba(245,158,11,0.90)';
  return 'rgba(22,163,74,0.85)';
}
function getKey(){ return (document.getElementById('apikey')?.value||'').trim(); }
(function initKey(){ const el=document.getElementById('apikey'); const s=localStorage.getItem('apiKey'); if(s && !el.value) el.value=s; el.addEventListener('change',()=>localStorage.setItem('apiKey', getKey())); })();

let currentScanId=null, cache=new Map(), filterIp=localStorage.getItem('filterIp')||'';
let sevAllBar=null, srcPie=null, portsBar=null, cvssBar=null;

let inflight=null;
async function api(path,opts={}){
  if(inflight) inflight.abort();
  inflight=new AbortController();
  const headers=Object.assign({},opts.headers||{}, {'x-api-key':getKey()});
  return fetch(path,Object.assign({},opts,{headers,signal:inflight.signal,cache:'no-store'}));
}

function setKPI(id,val){ document.getElementById(id).textContent=val; }
function upsertChart(inst, cfg){ if(inst) inst.destroy(); return new Chart(cfg.ctx, cfg.opts); }

function setFilterIndicator(){
  const badge=document.getElementById('filterIndicator');
  const btn=document.getElementById('clearBtn');
  if(filterIp){
    badge.style.display='inline-block';
    badge.textContent='Filter: '+filterIp;
    btn.style.display='inline-block';
  }else{
    badge.style.display='none';
    btn.style.display='none';
  }
}
function setTitles(ip){
  document.getElementById('sevTitle').textContent = ip ? `Severity (${ip})` : 'Severity (all scans)';
  document.getElementById('cvssTitle').textContent = ip ? `CVSS for ${ip} (0–10)` : 'CVSS by Host (max per host, 0–10)';
  document.getElementById('portsTitle').textContent = ip ? `Top Open Ports for ${ip}` : 'Top Open Ports';
  document.getElementById('srcTitle').textContent = ip ? `Sources (${ip})` : 'Sources';
}

function updateDashCharts(stats){
  const sevCounts = [stats.severity.Low||0, stats.severity.Medium||0, stats.severity.High||0, stats.severity.Critical||0];
  sevAllBar = upsertChart(sevAllBar,{
    ctx: document.getElementById('sevAllBar'),
    opts:{
      type:'bar',
      data:{ labels:sevOrder, datasets:[{label:'Findings', data:sevCounts,
        backgroundColor:sevOrder.map(s=>sevColors[s]), borderColor:sevOrder.map(s=>sevBorders[s]), borderWidth:1.25, maxBarThickness:44 }]},
      options:{ responsive:true, maintainAspectRatio:true, aspectRatio:2.1, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true, ticks:{precision:0}}} }
    }
  });

  const srcLabels=[], srcVals=[], srcCols=['#3b82f6','#22c55e','#64748b','#f59e0b','#ef4444'];
  for(const [k,v] of Object.entries(stats.sources||{})){ srcLabels.push(k); srcVals.push(v); }
  srcPie = upsertChart(srcPie,{
    ctx: document.getElementById('srcPie'),
    opts:{ type:'doughnut', data:{ labels:srcLabels, datasets:[{ data:srcVals, backgroundColor:srcCols.slice(0,srcVals.length) }]},
      options:{ responsive:true, maintainAspectRatio:true, aspectRatio:1.2, plugins:{legend:{position:'bottom'}} } }
  });

  const pLabels=(stats.top_ports||[]).map(x=>x.port);
  const pVals=(stats.top_ports||[]).map(x=>x.count);
  portsBar = upsertChart(portsBar,{
    ctx: document.getElementById('portsBar'),
    opts:{ type:'bar', data:{ labels:pLabels, datasets:[{ label:'Count', data:pVals, backgroundColor:'#60a5fa', borderColor:'#2563eb', borderWidth:1.2, maxBarThickness:38 }]},
      options:{ responsive:true, maintainAspectRatio:true, aspectRatio:3.5, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true, ticks:{precision:0}}} } }
  });

  const cvLabels=(stats.cvss_by_host||[]).map(x=>x.host);
  const cvVals=(stats.cvss_by_host||[]).map(x=>x.score);
  const cvCols=cvVals.map(colorForScore);
  cvssBar = upsertChart(cvssBar,{
    ctx: document.getElementById('cvssBar'),
    opts:{ type:'bar', data:{ labels:cvLabels, datasets:[{ label:'CVSS (max)', data:cvVals, backgroundColor:cvCols, borderColor:cvCols.map(c=>c.replace('0.95','1')), borderWidth:1.2, maxBarThickness:40 }]},
      options:{ responsive:true, maintainAspectRatio:true, aspectRatio:3.0, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true, suggestedMax:10, ticks:{stepSize:2}}} } }
  });
}

async function loadStats(){
  const q=filterIp ? ('?ip='+encodeURIComponent(filterIp)) : '';
  const r=await api('/stats'+q);
  if(!r.ok) return;
  const s=await r.json();
  setTitles(s.filter_ip||'');
  setFilterIndicator();
  setKPI('kpi_scans', s.total_scans||0);
  setKPI('kpi_hosts', s.unique_hosts||0);
  setKPI('kpi_findings', s.total_findings||0);
  setKPI('kpi_last', s.last_scan ? `#${s.last_scan.id} • ${s.last_scan.ip}` : '—');
  updateDashCharts(s);
}

async function loadScans(){
  const r=await api('/scans');
  const box=document.getElementById('scans');
  if(!r.ok){ box.textContent='Error '+r.status; return; }
  const data=await r.json();
  if(!data.length){ box.textContent='No scans yet.'; return; }
  box.innerHTML=data.map(s =>
    `<div style="margin:6px 0;">
       <a href="#" onclick="viewScan(${s.id});return false;">#${s.id}</a> — ${s.ip}
       <span class="small"> ${s.created_at}</span>
       ${s.source?`<span class="badge" style="background:#111827;color:#fff">${s.source}</span>`:''}
     </div>`
  ).join('');
}

async function loadAll(){ await Promise.all([loadStats(), loadScans()]); }

const scanTypeSel = document.getElementById('scanType');
const adv = document.getElementById('advancedFlags');
scanTypeSel.addEventListener('change', () => { adv.style.display = scanTypeSel.value === 'advanced' ? 'inline-block' : 'none'; });

async function scanTargetBtn(){
  const target=(document.getElementById('scanTarget').value||'').trim();
  if(!target){ alert('Enter a target'); return; }
  const st = document.getElementById('scanType').value;
  const af = document.getElementById('advancedFlags').value.trim();
  const res=await api('/scan/run', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({target, scan_type:st, advanced_flags:(st==='advanced'?af:null)})});
  const d=await res.json();
  if(!res.ok){ alert('Scan failed: '+(d.detail||res.status)); return; }
  await viewScan(d.scan_id);
}

async function uploadXml(){
  const f=document.getElementById('fileNmap').files[0];
  if(!f){ alert('Choose Nmap XML'); return; }
  const fd=new FormData(); fd.append('file', f);
  const res=await api('/upload', {method:'POST', body:fd});
  const d=await res.json();
  if(!res.ok){ alert('Upload failed: '+(d.detail||res.status)); return; }
  await viewScan(d.scan_id);
}

async function uploadNessus(){
  const f=document.getElementById('fileNessus').files[0];
  if(!f){ alert('Choose Nessus .nessus'); return; }
  const fd=new FormData(); fd.append('file', f);
  const res=await api('/upload/nessus', {method:'POST', body:fd});
  const d=await res.json();
  if(!res.ok){ alert('Upload failed: '+(d.detail||res.status)); return; }
  await viewScan(d.scan_id);
}

function escapeHTML(s){ return (s||'').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function setFilterIp(ip){
  filterIp = ip || '';
  if(filterIp) localStorage.setItem('filterIp', filterIp);
  else localStorage.removeItem('filterIp');
  loadStats();
}
function clearFilter(){ setFilterIp(''); }

async function viewScan(id){
  currentScanId=id;
  if(cache.has(id)) renderDetail(cache.get(id));
  const r=await api('/scans/'+id);
  const d=await r.json();
  if(r.ok){
    cache.set(id,d);
    renderDetail(d);
    setFilterIp(d.ip||'');  // keep dashboard aligned to opened scan
  } else {
    document.getElementById('detail').textContent='Error '+r.status+': '+(d.detail||'');
  }
}

function renderDetail(d){
  const findings=(d.triage?.findings)||[];
  const parsedHosts=(d.parsed?.hosts||[]).map(h=>{
    const rows=(h.ports||[]).map(p=>`<tr><td>${p.port}</td><td>${p.protocol||''}</td><td>${p.state||''}</td><td>${p.service_name||''}</td></tr>`).join('');
    return `<h4>Host ${h.address||'(unknown)'}</h4>
      <table>
        <thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead>
        <tbody>${rows||'<tr><td colspan="4">(no open ports)</td></tr>'}</tbody>
      </table>`;
  }).join('');

  const sevBadges=(()=>{ const c={Low:0,Medium:0,High:0,Critical:0}; findings.forEach(f=>{ if(c[f.severity]!=null)c[f.severity]++;});
    return Object.keys(c).map(k=>`<span class="badge ${k}">${k}: ${c[k]}</span>`).join(' ');
  })();

  const risk = d.triage?.risk_overview ? `<p><b>Risk overview:</b> ${escapeHTML(d.triage.risk_overview)}</p>` : '';
  const triageHtml = findings.map(f=>`
    <div style="margin-bottom:10px;">
      <span class="badge ${f.severity}">${f.severity}</span>
      Port ${f.port||'?'} — ${f.service||''} — ${f.host||''}
      ${typeof f.cvss==='number' ? `<span class="badge" style="background:#1f2937;color:#fff;margin-left:6px;">CVSS ${f.cvss.toFixed(1)}</span>` : ''}
      <div class="small">${(f.evidence||'').replace(/</g,'&lt;')}</div>
      ${(f.recommendations&&f.recommendations.length)?'<ul>'+f.recommendations.map(r=>`<li>${r}</li>`).join('')+'</ul>':''}
      ${(f.cves&&f.cves.length)?'<div class="small">CVEs: '+f.cves.join(', ')+'</div>':''}
    </div>`).join('');

  document.getElementById('detail').innerHTML = `
    <p><b>Scan #${d.id}</b> — IP: ${d.ip||'(none)'} — <span class="small">${d.created_at}</span> ${d.source?`<span class="badge" style="background:#111827;color:#fff">${d.source}</span>`:''}</p>
    <p><b>Summary:</b> ${d.triage?.summary||'—'}</p>
    ${risk}
    <p>${sevBadges}</p>
    <h4>Triage Findings</h4>
    ${triageHtml || '<em>No findings.</em>'}
    <h4>Parsed</h4>
    ${parsedHosts || '<em>No hosts.</em>'}
    <details><summary>Raw JSON</summary><pre>${escapeHTML(JSON.stringify(d,null,2))}</pre></details>
  `;
}

/* ---- Downloads (PDF/PNG) ---- */
async function exportElement(format, element, filename){
  const canvas = await html2canvas(element, {scale: 2, backgroundColor: '#ffffff', useCORS: true});
  if(format === 'png'){
    const a=document.createElement('a');
    a.href = canvas.toDataURL('image/png');
    a.download = filename + '.png';
    a.click();
    return;
  }
  const { jsPDF } = window.jspdf;
  const pdf = new jsPDF('p','mm','a4');
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const imgWidth = pageWidth - 20; // margins
  const imgHeight = canvas.height * imgWidth / canvas.width;
  const imgData = canvas.toDataURL('image/jpeg', 0.95);

  let heightLeft = imgHeight;
  let position = 10;

  pdf.addImage(imgData, 'JPEG', 10, position, imgWidth, imgHeight);
  heightLeft -= (pageHeight - 20);

  while(heightLeft > 0){
    position = heightLeft - imgHeight + 10;
    pdf.addPage();
    pdf.addImage(imgData, 'JPEG', 10, position, imgWidth, imgHeight);
    heightLeft -= (pageHeight - 20);
  }
  pdf.save(filename + '.pdf');
}
function getFmt(){ return (document.getElementById('dlFmt')?.value || 'pdf'); }
async function downloadScanReport(){
  const el=document.getElementById('detail');
  if(!el || !el.innerText.trim()){ alert('Open a scan first.'); return; }
  const fmt=getFmt();
  await exportElement(fmt, el, 'scan_'+(currentScanId||'detail'));
}
async function downloadDashboardReport(){
  const el=document.getElementById('dashwrap');
  const fmt=getFmt();
  await exportElement(fmt, el, 'dashboard'+(filterIp?('_'+filterIp):''));
}
async function downloadIpReport(){
  const ip=(document.getElementById('scanTarget').value||filterIp||'').trim();
  if(!ip){ alert('Enter an IP/host or open a scan.'); return; }
  const prev=filterIp;
  setFilterIp(ip);
  await loadStats(); // refresh charts to this IP
  setTimeout(async ()=>{
    await downloadDashboardReport();
    setFilterIp(prev);
    await loadStats();
  }, 250);
}

/* ---- CSV ---- */
async function downloadAllCsv(){
  const q = filterIp ? ('?ip='+encodeURIComponent(filterIp)) : '';
  const res=await api('/scans/export.csv'+q);
  const blob=await res.blob(); const a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download='scans_export'+(filterIp?('_'+filterIp):'')+'.csv'; a.click(); URL.revokeObjectURL(a.href);
}
async function downloadCurrentCsv(){
  if(!currentScanId){ alert('Open a scan first.'); return; }
  const res=await api(`/scans/${currentScanId}/export.csv`);
  const blob=await res.blob(); const a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download=`scan_${currentScanId}.csv`; a.click(); URL.revokeObjectURL(a.href);
}

loadAll(); // boot
</script>
</body></html>
""")

@app.get("/", response_class=HTMLResponse)
def root():
    return HTMLResponse('<html><body><h3>AI Security Triage API</h3><p>Open <a href="/ui">/ui</a> or <a href="/docs">/docs</a>.</p></body></html>')
