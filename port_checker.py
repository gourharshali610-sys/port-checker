#!/usr/bin/env python3
"""
port_checker.py - Check whether a TCP port is open or closed on a host.

How it works:
    The script tries to complete a TCP "three-way handshake" (SYN -> SYN/ACK -> ACK)
    with the target host and port using a normal socket connection.

    - Connection succeeds        -> a service is listening: port is OPEN
    - Connection refused (RST)   -> host reachable, nothing listening: port is CLOSED
    - No reply before timeout    -> usually a firewall silently dropping packets: FILTERED

Usage:
    python port_checker.py 80                      # checks localhost:80
    python port_checker.py 443 --host example.com  # checks a remote host
    python port_checker.py 22 -H 192.168.1.10 -t 3
    python port_checker.py                         # interactive prompts

Only scan systems you own or have permission to test.
"""

import argparse
import socket
import sys


def check_port(host: str, port: int, timeout: float = 2.0) -> str:
    """Return 'open', 'closed', or 'filtered' for the given TCP port."""
    try:
        # create_connection resolves the hostname and handles IPv4/IPv6
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {host}")
    except OSError as exc:
        # e.g. network unreachable, no route to host
        raise ConnectionError(f"Network error while connecting: {exc}")


def service_name(port: int) -> str:
    """Look up the common service name for a port (e.g. 80 -> http)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def valid_port(value: str) -> int:
    """Validate that the port is an integer between 1 and 65535."""
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid number")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description="Check if a TCP port is open or closed.")
    parser.add_argument("port", nargs="?", type=valid_port, help="port number (1-65535)")
    parser.add_argument("-H", "--host", default="127.0.0.1",
                        help="target host or IP (default: 127.0.0.1)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="timeout in seconds (default: 2.0)")
    args = parser.parse_args()

    # Fall back to interactive input if no port was given
    port = args.port
    if port is None:
        try:
            port = valid_port(input("Enter port number (1-65535): ").strip())
        except argparse.ArgumentTypeError as exc:
            print(f"Error: {exc}")
            return 2

    try:
        status = check_port(args.host, port, args.timeout)
    except (ValueError, ConnectionError) as exc:
        print(f"Error: {exc}")
        return 2

    label = f"{args.host}:{port} ({service_name(port)})"
    messages = {
        "open": f"[OPEN]     {label} - a service is accepting connections.",
        "closed": f"[CLOSED]   {label} - host reachable, but nothing is listening.",
        "filtered": f"[FILTERED] {label} - no response; likely blocked by a firewall.",
    }
    print(messages[status])
    return 0 if status == "open" else 1


if __name__ == "__main__":
    sys.exit(main())
