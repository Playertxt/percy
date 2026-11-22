"""Minimal DNS A-record client over UDP, enough to test resolvers."""
from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
TYPE_A = 1
CLASS_IN = 1


class DnsError(RuntimeError):
    pass


@dataclass(frozen=True)
class DnsAnswer:
    rcode: int
    addresses: tuple[str, ...]

    @property
    def nxdomain(self) -> bool:
        return self.rcode == RCODE_NXDOMAIN

    @property
    def blocked(self) -> bool:
        """How AdGuard/Pi-hole answer a blocked name: NXDOMAIN or 0.0.0.0."""
        return self.nxdomain or (bool(self.addresses) and all(a == "0.0.0.0" for a in self.addresses))


def build_query(name: str, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # recursion desired
    labels = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.strip(".").split("."))
    return header + labels + b"\x00" + struct.pack("!HH", TYPE_A, CLASS_IN)


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        if offset >= len(data):
            raise DnsError("Truncated DNS name")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def parse_response(data: bytes, query_id: int) -> DnsAnswer:
    if len(data) < 12:
        raise DnsError("DNS reply too short")
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id:
        raise DnsError("DNS reply ID mismatch")
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset) + 4
    addresses = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("Truncated DNS answer")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == TYPE_A and rdlen == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += rdlen
    return DnsAnswer(rcode=flags & 0x000F, addresses=tuple(addresses))


def resolve_a(name: str, server: str, timeout: float = 3.0, port: int = 53) -> DnsAnswer:
    query_id = secrets.randbelow(0xFFFF)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_query(name, query_id), (server, port))
            data, _ = sock.recvfrom(4096)
        except OSError as exc:
            raise DnsError(f"No DNS answer from {server}: {exc}") from exc
    return parse_response(data, query_id)
