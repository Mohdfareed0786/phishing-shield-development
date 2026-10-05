import asyncio
import ipaddress
import socket
from dataclasses import dataclass


@dataclass
class DnsResult:
    status: str
    details: str
    addresses: list[str]
    private_addresses: list[str]


class DnsAnalyzer:
    async def analyze(self, hostname: str, *, is_ip: bool) -> DnsResult:
        if is_ip:
            try:
                address = ipaddress.ip_address(hostname)
                if address.is_global:
                    return DnsResult('PASS', 'The URL uses a public IP literal; no DNS lookup was needed.', [str(address)], [])
                return DnsResult('DANGER', 'The IP address is not globally routable.', [str(address)], [str(address)])
            except ValueError:
                return DnsResult('UNKNOWN', 'The IP address could not be validated.', [], [])

        try:
            records = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM), timeout=4.0)
        except (OSError, asyncio.TimeoutError):
            return DnsResult('UNKNOWN', 'DNS lookup did not return an address.', [], [])

        addresses = sorted({record[4][0] for record in records})
        private_addresses = []
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw)
                if not address.is_global:
                    private_addresses.append(raw)
            except ValueError:
                continue

        if private_addresses:
            return DnsResult('DANGER', 'DNS resolved to a non-public address. The destination was not contacted.', addresses, private_addresses)
        if addresses:
            return DnsResult('PASS', f'DNS returned {len(addresses)} public address(es). No connection to the destination was made.', addresses, [])
        return DnsResult('UNKNOWN', 'DNS returned no usable address.', [], [])
