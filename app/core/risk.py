# app/core/risk.py

from typing import List, Optional

# Severity ranking helper
_SEV_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

def max_sev(a: str, b: str) -> str:
    """
    Return the higher (worse) severity between a and b.
    """
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


def score_port(
    port: Optional[int],
    state: Optional[str],
    service_name: Optional[str] = None,
    script_output: str = ""
) -> str:
    """
    Return severity: 'Low' | 'Medium' | 'High' | 'Critical'
    Simple heuristics suitable for an MVP triage. Ports not open => Low.
    """
    # Guard rails
    if state is None:
        return "Low"
    if state.lower() != "open":
        return "Low"

    sev = "Low"
    svc = (service_name or "").lower()
    text = (script_output or "").lower()

    # Remote desktop / mgmt surfaces
    if port in (3389, 5900, 5985, 5986):              # RDP, VNC, WinRM
        sev = max_sev(sev, "High")

    # Common infra ports
    if port in (22, 23, 21):                           # SSH, Telnet, FTP
        sev = max_sev(sev, "Medium")
    if port in (80, 443, 8080, 8443):                  # Web
        sev = max_sev(sev, "Medium")
    if port in (1433, 1521, 3306, 5432):               # MSSQL, Oracle, MySQL, Postgres
        sev = max_sev(sev, "High")

    # Service-based bumps
    if svc in ("telnet", "rpcbind", "vnc"):
        sev = max_sev(sev, "High")
    if svc in ("mysql", "mariadb", "mssql", "oracle"):
        sev = max_sev(sev, "High")

    # Script clues (upgrade to Critical if explicit vuln text)
    if "cve-" in text or "vuln" in text or "unauthorized" in text or "default credentials" in text:
        sev = max_sev(sev, "Critical")

    return sev


def remediation_for(
    port: Optional[int],
    service_name: Optional[str],
    severity: str
) -> List[str]:
    """
    Return a list of short, actionable remediation steps based on port/service/severity.
    """
    steps: List[str] = []
    svc = (service_name or "").lower()

    if severity in ("High", "Critical"):
        steps.append("Restrict access at firewall to trusted sources or VPN.")

    # SSH
    if port == 22 or svc == "ssh":
        steps += [
            "Disable password auth; use SSH keys.",
            "Enforce MFA via bastion/jump host.",
            "Update server & SSH daemon to latest."
        ]

    # RDP
    if port == 3389 or svc == "ms-wbt-server":
        steps += [
            "Disable RDP if unused.",
            "Require RD Gateway or VPN; enable NLA.",
            "Apply latest Windows patches and audit RDP logs."
        ]

    # Web
    if svc in ("http", "https") or port in (80, 443, 8080, 8443):
        steps += [
            "Force TLS 1.2+; disable weak ciphers.",
            "Patch the web server/app; run dependency updates.",
            "Enable WAF or basic rate limiting if exposed."
        ]

    # Databases
    if port in (1433, 1521, 3306, 5432) or svc in ("mysql", "mariadb", "mssql", "oracle", "postgresql"):
        steps += [
            "Bind DB to private interfaces only.",
            "Enforce strong auth; rotate credentials.",
            "Apply latest security patches."
        ]

    return steps or ["Validate business need; close if unnecessary."]
