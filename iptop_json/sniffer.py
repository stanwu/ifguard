import argparse
import fcntl
import json
import select
import socket
import struct
import time
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, Optional, Tuple

ETH_P_ALL = 0x0003
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN_8021Q = 0x8100
ETHERTYPE_VLAN_8021AD = 0x88A8
IPPROTO_TCP = 6
SIOCGIFADDR = 0x8915
MAX_PACKET = 65535


@dataclass
class Counters:
    in_bytes: int = 0
    out_bytes: int = 0
    in_pkts: int = 0
    out_pkts: int = 0

    @property
    def total_bytes(self) -> int:
        return self.in_bytes + self.out_bytes

    @property
    def total_pkts(self) -> int:
        return self.in_pkts + self.out_pkts


def _ioctl_iface_ipv4(iface: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("ascii", "ignore")[:15])
    res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    return socket.inet_ntoa(res[20:24])


def _parse_ipv4_tcp(pkt: bytes) -> Optional[Tuple[str, str]]:
    if len(pkt) < 14:
        return None

    eth_type = int.from_bytes(pkt[12:14], "big")
    l2_offset = 14

    if eth_type in (ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD):
        if len(pkt) < 18:
            return None
        eth_type = int.from_bytes(pkt[16:18], "big")
        l2_offset = 18

    if eth_type != ETHERTYPE_IPV4:
        return None
    if len(pkt) < l2_offset + 20:
        return None

    ihl = (pkt[l2_offset] & 0x0F) * 4
    if ihl < 20:
        return None
    if len(pkt) < l2_offset + ihl:
        return None

    proto = pkt[l2_offset + 9]
    if proto != IPPROTO_TCP:
        return None

    src = socket.inet_ntoa(pkt[l2_offset + 12 : l2_offset + 16])
    dst = socket.inet_ntoa(pkt[l2_offset + 16 : l2_offset + 20])
    return src, dst


def _to_rows(stats: Dict[str, Counters], topn: int) -> Iterable[dict]:
    rows = []
    for ip, c in stats.items():
        row = {"ip": ip, **asdict(c), "total_bytes": c.total_bytes, "total_pkts": c.total_pkts}
        rows.append(row)
    rows.sort(key=lambda r: r["total_bytes"], reverse=True)
    if topn > 0:
        rows = rows[:topn]
    return rows


def run(
    iface: str,
    interval: float = 10.0,
    topn: int = 20,
    cumulative: bool = False,
    local_ip: Optional[str] = None,
) -> None:
    if interval <= 0:
        raise ValueError("interval must be > 0")
    if local_ip is None:
        local_ip = _ioctl_iface_ipv4(iface)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.setblocking(False)

    stats: Dict[str, Counters] = {}
    next_emit = time.time() + interval

    while True:
        timeout = max(0.0, next_emit - time.time())
        ready, _, _ = select.select([sock], [], [], timeout)

        if ready:
            pkt = sock.recv(MAX_PACKET)
            parsed = _parse_ipv4_tcp(pkt)
            if parsed is not None:
                src, dst = parsed
                if src == local_ip:
                    peer = dst
                    c = stats.setdefault(peer, Counters())
                    c.out_bytes += len(pkt)
                    c.out_pkts += 1
                elif dst == local_ip:
                    peer = src
                    c = stats.setdefault(peer, Counters())
                    c.in_bytes += len(pkt)
                    c.in_pkts += 1

        now = time.time()
        if now >= next_emit:
            payload = {
                "ts": int(now),
                "iface": iface,
                "local_ip": local_ip,
                "interval_sec": interval,
                "mode": "cumulative" if cumulative else "window",
                "top": _to_rows(stats, topn),
            }
            print(json.dumps(payload, ensure_ascii=False), flush=True)
            if not cumulative:
                stats = {}
            next_emit = now + interval


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ifguard-iptop",
        description="Read TCP packets and output per-IP counters as JSON lines.",
    )
    p.add_argument("-i", "--iface", required=True, help="network interface, e.g. eth0")
    p.add_argument("-t", "--interval", type=float, default=10.0, help="emit interval in seconds (default: 10)")
    p.add_argument("-n", "--topn", type=int, default=20, help="top N IPs by bytes (0 = all)")
    p.add_argument(
        "--cumulative",
        action="store_true",
        help="keep accumulating counters instead of resetting each interval",
    )
    p.add_argument(
        "--local-ip",
        default=None,
        help="override interface IPv4 used to determine in/out direction",
    )
    return p
