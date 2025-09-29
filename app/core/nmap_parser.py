from defusedxml import ElementTree as ET

def parse_nmap_xml(path: str) -> dict:
    """
    Minimal parser:
      - hosts[].address
      - hosts[].hostnames
      - hosts[].ports[] = {port, protocol, state, service_name}
    Safe for MVP; expand later with scripts/CVEs.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    hosts_out = []
    for host in root.findall("host"):
        # address
        addr = None
        for a in host.findall("address"):
            # prefer IPv4 if present
            if a.get("addrtype") == "ipv4":
                addr = a.get("addr")
                break
            addr = a.get("addr") or addr

        # hostnames
        hnames = [hn.get("name") for hn in host.findall("hostnames/hostname") if hn.get("name")]

        # ports
        ports = []
        for p in host.findall("ports/port"):
            portid = p.get("portid")
            proto = p.get("protocol")
            state_el = p.find("state")
            state = state_el.get("state") if state_el is not None else None
            service_el = p.find("service")
            svc_name = service_el.get("name") if service_el is not None else None

            ports.append({
                "port": int(portid) if portid else None,
                "protocol": proto,
                "state": state,
                "service_name": svc_name
            })

        hosts_out.append({
            "address": addr,
            "hostnames": hnames,
            "ports": ports
        })

    return {"hosts": hosts_out}
