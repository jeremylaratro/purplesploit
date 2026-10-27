"""Reusable offline Nmap XML parser and legacy datastore projection.

Only explicit up hosts with valid IP addresses become host observations; only
explicit open ports become service observations. TCP and UDP retain identities.
"""

from hashlib import sha256
import ipaddress
from pathlib import Path

import defusedxml.ElementTree as ET

from purplesploit.core.execution import Observation


SERVICE_ALIASES = {"microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp",
                   "ms-sql-s": "mssql", "wsman": "winrm", "domain": "dns", "ldaps": "ldap"}


def _scripts(parent):
    """Keep both human output and structured NSE table/element data."""
    def node(element):
        return {"tag": element.tag, "attributes": dict(element.attrib), "text": element.text or "",
                "children": [node(child) for child in element]}
    return [{"id": item.get("id"), "output": item.get("output", ""),
             "data": [node(child) for child in item]} for item in parent.findall("script")]


def observations_for_hosts(hosts, *, source_execution_id="", module_path="recon/nmap", metadata=None):
    observations = []
    for host in hosts:
        target = host["ip"]
        if not _valid_ip(target):
            continue
        common = {**(metadata or {}), "source_tool": "nmap", "hostname": host.get("hostname"),
                  "hostnames": host.get("hostnames", []), "scripts": host.get("scripts", []),
                  "os_matches": host.get("os_matches", [])}
        observations.append(Observation(kind="host", target=target, attributes={**common, "state": "up"},
                                        source_execution_id=source_execution_id, module_path=module_path))
        for service in host.get("services", {}).values():
            raw_name = service.get("service", "unknown")
            name = SERVICE_ALIASES.get(raw_name, raw_name)
            if name == "http" and service.get("tunnel") in {"ssl", "tls"}:
                name = "https"
            attributes = {**common, **service, "raw_service": raw_name,
                          "hostname": service.get("hostname") or host.get("hostname")}
            observations.append(Observation(kind="service", target=target, port=service["port"],
                                            protocol=service.get("protocol", "tcp"), service=name,
                                            version=service.get("version"), attributes=attributes,
                                            source_execution_id=source_execution_id, module_path=module_path))
    return observations


def parse_nmap_xml(xml_path, *, source_execution_id="", module_path="recon/nmap") -> dict:
    """Read one XML artifact once. Errors propagate so callers can report them."""
    path = Path(xml_path)
    data = path.read_bytes()
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError(f"Failed to parse Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Expected nmaprun XML root")
    hosts = []
    for element in root.findall("host"):
        status = element.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = [address.get("addr") for address in element.findall("address")
                     if address.get("addrtype") in {"ipv4", "ipv6"}]
        address = next((value for value in addresses if _valid_ip(value)), None)
        if address is None:
            continue
        hostnames = [dict(item.attrib) for item in element.findall("hostnames/hostname")]
        host = {"ip": address, "hostname": hostnames[0].get("name") if hostnames else None,
                "hostnames": hostnames, "addresses": addresses, "open_ports": [], "services": {},
                "scripts": _scripts(element.find("hostscript")) if element.find("hostscript") is not None else [],
                "os_matches": [dict(item.attrib) for item in element.findall("os/osmatch")]}
        for port in element.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            protocol = port.get("protocol", "tcp")
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                continue
            if not 1 <= number <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                continue
            service = port.find("service")
            attributes = dict(service.attrib) if service is not None else {}
            product, version = attributes.get("product", ""), attributes.get("version", "")
            key = f"{number}/{protocol}"
            host["open_ports"].append(key)
            host["services"][key] = {**attributes, "service": attributes.get("name", "unknown"),
                                      "product": product, "service_version": version,
                                      "version": f"{product} {version}".strip(), "port": number,
                                      "protocol": protocol, "state": "open", "scripts": _scripts(port)}
        hosts.append(host)
    metadata = {"source_file": str(path), "source_tool_version": root.get("version"),
                "source_schema": "nmap/xml", "artifact_sha256": sha256(data).hexdigest()}
    source = source_execution_id or "nmap:" + metadata["artifact_sha256"]
    observations = observations_for_hosts(hosts, source_execution_id=source, module_path=module_path, metadata=metadata)
    with_ports = [host for host in hosts if host["open_ports"]]
    return {"hosts": with_ports, "discovered_hosts": hosts, "total_hosts": len(hosts),
            "hosts_with_ports": len(with_ports), "observations": [item.to_dict() for item in observations]}


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def import_discovered_hosts(framework, parsed, *, models_db=None, log=None, auto_add=True):
    """Project into legacy stores; observations retain richer endpoint metadata.

    Legacy stores key on target/service/port and cannot distinguish TCP from UDP.
    First-class observations retain both without claiming that schema supports it.
    """
    targets_added, services_found = 0, 0
    for host in parsed.get("discovered_hosts", parsed.get("hosts", [])):
        target = host["ip"]
        if not _valid_ip(target):
            continue
        if auto_add:
            try:
                if framework.add_target(target_type="network", identifier=target, name=host.get("hostname") or target):
                    targets_added += 1
                framework.database.mark_target_verified(target)
            except Exception as exc:
                if log:
                    log(f"Target import failed for {target}: {exc}", "warning")
        for service in host.get("services", {}).values():
            name = SERVICE_ALIASES.get(service["service"], service["service"])
            port, version = service["port"], service.get("version")
            framework.session.services.add_service(target=target, service=name, port=port)
            framework.database.add_service(target=target, service=name, port=port, version=version)
            if models_db is not None:
                try:
                    models_db.add_service(target=target, service=name, port=port, version=version)
                except Exception as exc:
                    if log:
                        log(f"Models service import failed: {exc}", "warning")
            services_found += 1
    return {"hosts_processed": parsed.get("total_hosts", len(parsed.get("hosts", []))),
            "services_found": services_found, "targets_added": targets_added}
