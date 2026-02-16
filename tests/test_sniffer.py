import unittest

from iptop_json.sniffer import Counters, _parse_ipv4_tcp, _to_rows


def build_eth_ipv4_packet(src_ip: str, dst_ip: str, proto: int = 6, vlan: bool = False) -> bytes:
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x11\x22\x33\x44\x55\x66"
    if vlan:
        eth_hdr = dst_mac + src_mac + b"\x81\x00" + b"\x00\x01" + b"\x08\x00"
    else:
        eth_hdr = dst_mac + src_mac + b"\x08\x00"

    version_ihl = 0x45
    total_length = 20
    identification = 0
    flags_fragment = 0
    ttl = 64
    checksum = 0
    src = bytes(map(int, src_ip.split(".")))
    dst = bytes(map(int, dst_ip.split(".")))

    ip_hdr = bytes(
        [
            version_ihl,
            0,
            (total_length >> 8) & 0xFF,
            total_length & 0xFF,
            (identification >> 8) & 0xFF,
            identification & 0xFF,
            (flags_fragment >> 8) & 0xFF,
            flags_fragment & 0xFF,
            ttl,
            proto,
            (checksum >> 8) & 0xFF,
            checksum & 0xFF,
        ]
    ) + src + dst
    return eth_hdr + ip_hdr


class TestParseIpv4Tcp(unittest.TestCase):
    def test_parse_tcp_packet(self) -> None:
        pkt = build_eth_ipv4_packet("10.0.0.1", "10.0.0.2", proto=6)
        self.assertEqual(_parse_ipv4_tcp(pkt), ("10.0.0.1", "10.0.0.2"))

    def test_parse_non_tcp_packet_returns_none(self) -> None:
        pkt = build_eth_ipv4_packet("10.0.0.1", "10.0.0.2", proto=17)
        self.assertIsNone(_parse_ipv4_tcp(pkt))

    def test_parse_vlan_tcp_packet(self) -> None:
        pkt = build_eth_ipv4_packet("192.168.1.10", "1.1.1.1", proto=6, vlan=True)
        self.assertEqual(_parse_ipv4_tcp(pkt), ("192.168.1.10", "1.1.1.1"))

    def test_parse_short_packet_returns_none(self) -> None:
        self.assertIsNone(_parse_ipv4_tcp(b"\x00\x01\x02"))


class TestRowsAndCounters(unittest.TestCase):
    def test_counters_totals(self) -> None:
        c = Counters(in_bytes=10, out_bytes=7, in_pkts=2, out_pkts=3)
        self.assertEqual(c.total_bytes, 17)
        self.assertEqual(c.total_pkts, 5)

    def test_to_rows_sort_and_topn(self) -> None:
        stats = {
            "1.1.1.1": Counters(in_bytes=100, out_bytes=30, in_pkts=1, out_pkts=1),
            "2.2.2.2": Counters(in_bytes=20, out_bytes=10, in_pkts=1, out_pkts=1),
            "3.3.3.3": Counters(in_bytes=60, out_bytes=50, in_pkts=1, out_pkts=1),
        }
        rows = list(_to_rows(stats, topn=2))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ip"], "1.1.1.1")
        self.assertEqual(rows[0]["total_bytes"], 130)
        self.assertEqual(rows[1]["ip"], "3.3.3.3")
        self.assertEqual(rows[1]["total_bytes"], 110)


if __name__ == "__main__":
    unittest.main()
