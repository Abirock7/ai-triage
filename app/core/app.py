from fastapi import FastAPI, Depends
from app.core.auth import require_api_key

app = FastAPI(title="AI-Powered Security Triage - Pilot")

@app.get("/health")
def health(api_user: str = Depends(require_api_key)):
    return {"status": "ok", "user": api_user}
