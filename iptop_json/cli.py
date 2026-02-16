from iptop_json.sniffer import build_parser, run


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    run(
        iface=args.iface,
        interval=args.interval,
        topn=args.topn,
        cumulative=args.cumulative,
        local_ip=args.local_ip,
    )


if __name__ == "__main__":
    main()
