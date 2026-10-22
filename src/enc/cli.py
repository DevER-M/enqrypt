"""Command line entry point: ``enc serve``."""

from __future__ import annotations

import argparse
import socket

DEFAULT_PORT = 8080


def _lan_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    return sorted(address for address in addresses if not address.startswith("127."))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enc",
        description="Server-hosted 1:1 chat with browser-side post-quantum encryption.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the chat server")
    serve.add_argument(
        "--host",
        default="0.0.0.0",
        help="bind address (default: 0.0.0.0, all interfaces)",
    )
    serve.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    serve.add_argument(
        "--db",
        default="enc.db",
        help="SQLite database file for accounts (default: enc.db)",
    )
    serve.add_argument(
        "--secure-cookies",
        action="store_true",
        help="mark the session cookie Secure (set this when serving over HTTPS)",
    )
    serve.add_argument(
        "--log-level",
        default="info",
        choices=("critical", "error", "warning", "info", "debug"),
        help="uvicorn log level",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        import uvicorn

        from enc.server import create_app

        print()
        print("  enc chat server")
        print(f"  local:   http://127.0.0.1:{args.port}")
        for address in _lan_addresses():
            print(f"  network: http://{address}:{args.port}")
        print()
        print("  Plain HTTP. Message contents stay encrypted in the browser, but")
        print("  anyone who can tamper with this network can also serve modified")
        print("  JavaScript. Put it behind HTTPS (and pass --secure-cookies) for")
        print("  anything beyond a trusted LAN.")
        print()

        uvicorn.run(
            create_app(db_path=args.db, secure_cookies=args.secure_cookies),
            host=args.host,
            port=args.port,
            log_level=args.log_level,
        )


if __name__ == "__main__":
    main()
