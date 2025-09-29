from .risk import score_port, remediation_for

def generate_triage(parsed: dict) -> dict:
    findings = []
    hosts = parsed.get("hosts", [])
    for host in hosts:
        addr = host.get("address")
        for p in host.get("ports", []):
            port = p.get("port")
            state = p.get("state")
            svc = p.get("service_name")
            # Collect any script outputs if you later add them
            script_output = ""  # placeholder for future expansion

            sev = score_port(port=port, state=state, service_name=svc, script_output=script_output)
            if state == "open":
                findings.append({
                    "host": addr,
                    "port": port,
                    "service": svc,
                    "severity": sev,
                    "evidence": f"state={state}, service={svc}",
                    "recommendations": remediation_for(port, svc, sev),
                })

    # Sort by severity High→Low
    order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    findings.sort(key=lambda f: order.get(f["severity"], 0), reverse=True)

    total_open = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
    summary = f"{len(hosts)} host(s) scanned; {total_open} open port(s). Top concern: " + \
              (findings[0]["service"] + f" on {findings[0]['host']} (port {findings[0]['port']})"
               if findings else "None")

    return {
        "summary": summary,
        "findings": findings,
        "confidence": "low (rule-based mock)",
    }
