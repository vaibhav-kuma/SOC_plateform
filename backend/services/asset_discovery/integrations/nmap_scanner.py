import asyncio
import xml.etree.ElementTree as ET
from typing import List, Optional
from services.asset_discovery.models.schemas import AssetDiscoveryResult
from core.config import settings


class NmapScanner:
    def __init__(self):
        self.timeout = 300

    async def scan(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        scan_type: str = "quick",
    ) -> List[AssetDiscoveryResult]:
        target_str = " ".join(targets)

        nmap_args = ["nmap", "-oX", "-"]
        if scan_type == "quick":
            nmap_args.extend(["-sn", "-T4"])
        elif scan_type == "full":
            nmap_args.extend(["-sS", "-sV", "-O", "-T4", "-p-"])
        elif scan_type == "stealth":
            nmap_args.extend(["-sS", "-sV", "-T2"])
        elif scan_type == "vulnerability":
            nmap_args.extend(["-sS", "-sV", "-O", "--script", "vuln", "-T4"])

        if ports and scan_type != "quick":
            nmap_args.extend(["-p", ports])

        nmap_args.append(target_str)

        try:
            proc = await asyncio.create_subprocess_exec(
                *nmap_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
        except FileNotFoundError:
            # Nmap not installed, return mock data for development
            return self._mock_scan(targets)
        except asyncio.TimeoutError:
            return []

        return self._parse_nmap_output(stdout.decode())

    def _parse_nmap_output(self, xml_output: str) -> List[AssetDiscoveryResult]:
        results = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                result = AssetDiscoveryResult()

                # IP
                addr = host.find("address")
                if addr is not None:
                    addr_type = addr.get("addrtype", "")
                    if addr_type == "ipv4":
                        result.ip_address = addr.get("addr", "")
                    elif addr_type == "mac":
                        result.mac_address = addr.get("addr", "")

                # Hostname
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        result.hostname = hn.get("name", "")

                # OS
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        result.os = osmatch.get("name", "")
                        result.os_version = osmatch.get("osclass", "")

                # Ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = int(port.get("portid", 0))
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            result.open_ports.append(port_id)
                            service = port.find("service")
                            if service is not None:
                                result.services.append({
                                    "port": port_id,
                                    "protocol": port.get("protocol", ""),
                                    "name": service.get("name", ""),
                                    "product": service.get("product", ""),
                                    "version": service.get("version", ""),
                                })

                if result.ip_address:
                    results.append(result)

        except ET.ParseError:
            pass

        return results

    def _mock_scan(self, targets: List[str]) -> List[AssetDiscoveryResult]:
        import random
        results = []
        for target in targets[:5]:
            results.append(AssetDiscoveryResult(
                hostname=f"host-{target.replace('.', '-')}",
                ip_address=target,
                mac_address=":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
                os="Linux Ubuntu 22.04 LTS",
                os_version="22.04",
                open_ports=[22, 80, 443, 3306],
                services=[
                    {"port": 22, "protocol": "tcp", "name": "ssh", "product": "OpenSSH", "version": "8.9"},
                    {"port": 80, "protocol": "tcp", "name": "http", "product": "nginx", "version": "1.24"},
                    {"port": 443, "protocol": "tcp", "name": "https", "product": "nginx", "version": "1.24"},
                ],
                asset_type="host",
            ))
        return results
