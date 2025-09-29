# app/core/nmap_runner.py
import os
import shutil
import subprocess
import datetime
import ipaddress

UPLOAD_DIR = "uploads"

class NmapNotFound(Exception): ...
class InvalidTarget(Exception): ...
class NmapFailed(Exception): ...

def _ensure_nmap():
    if shutil.which("nmap") is None:
        raise NmapNotFound("nmap is not installed or not on PATH")

def _validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise InvalidTarget(f"Invalid IPv4/IPv6 address: {ip}")

def run_nmap_scan(ip: str, timeout_sec: int = 120) -> str:
    """
    Fast, safe single-IP scan. Writes XML to uploads/ and returns the path.
    -F : top 100 ports
    --version-light : quicker service probes
    -T4 : faster timing (still reasonable)
    -Pn : skip host discovery (works if ICMP blocked)
    """
    _ensure_nmap()
    target = _validate_ip(ip)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(UPLOAD_DIR, f"run_{target.replace(':','_')}_{ts}.xml")

    cmd = ["nmap", "-F", "--version-light", "-T4", "-Pn", "-oX", dest, target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        raise NmapFailed(f"nmap timed out after {timeout_sec}s")
    if proc.returncode != 0:
        raise NmapFailed(f"nmap failed: rc={proc.returncode} stderr={proc.stderr[:500]}")
    if not os.path.exists(dest) or os.path.getsize(dest) == 0:
        raise NmapFailed("nmap did not produce XML output")
    return dest

