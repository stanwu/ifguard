# ifguard-iptop-json

Minimal `iftop`-like CLI that reads raw TCP packets on Linux and prints per-IP counters as JSON Lines.

## Features

- Reads packets with `AF_PACKET` raw socket (requires root / `CAP_NET_RAW`)
- Tracks per-peer IP counters (`in_bytes`, `out_bytes`, `in_pkts`, `out_pkts`)
- Emits JSON every N seconds
- Supports window mode (reset each interval) and cumulative mode

## Requirements

- Linux
- Python 3.9+
- Root privileges for sniffing

## Install

```bash
cd /home/stan/ifguard
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
sudo .venv/bin/ifguard-iptop -i eth0 --cumulative
```

Window mode (reset every 10 seconds by default):

```bash
sudo .venv/bin/ifguard-iptop -i eth0
```

Output top 50 peers:

```bash
sudo .venv/bin/ifguard-iptop -i eth0 -n 50 --cumulative
```

## Output Example

```json
{
  "ts": 1739700000,
  "iface": "eth0",
  "local_ip": "192.168.1.10",
  "interval_sec": 10.0,
  "mode": "cumulative",
  "top": [
    {
      "ip": "1.1.1.1",
      "in_bytes": 1040,
      "out_bytes": 890,
      "in_pkts": 8,
      "out_pkts": 6,
      "total_bytes": 1930,
      "total_pkts": 14
    }
  ]
}
```

## Notes

- Current implementation focuses on IPv4 TCP packets.
- For more exact on-wire behavior, NIC offload settings can affect capture semantics.

## Make Targets

```bash
make install
make test
make run IFACE=eth0
```

## CI

- GitHub Actions workflow at `.github/workflows/ci.yml` runs `make test` on every push and pull request.

## License

- MIT (see `LICENSE`)
