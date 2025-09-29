# app/core/auth.py
import os
from fastapi import Header, HTTPException
from typing import Optional

def _load_keys():
    # Comma or newline separated keys in env API_KEYS. Example: "demo-key-1,team-key-2"
    raw = os.getenv("API_KEYS", "demo-key-1")
    keys = [k.strip() for k in raw.replace("\n", ",").split(",") if k.strip()]
    return {k: "user" for k in keys}

API_KEYS = _load_keys()

def require_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key is None or x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return API_KEYS[x_api_key]
