#!/usr/bin/env python3
"""Find devices on a local /24 network and flag untrusted devices.


Usage:
    python netwatch.py --trust        # save currently visible devices as trusted
    python netwatch.py                # one scan, flag unknown devices
    python netwatch.py --ports        # also check devices for risky open ports
    python netwatch.py --watch 300    # rescan every 5 minutes, log + beep on new devices
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

KNOWN_FILE = Path("known_devices.json")
LOG_FILE = Path("netwatch.log")

# Ports used to detect devices that ignore pings (62078 = iPhone sync service).
PROBE_PORTS = (80, 443, 22, 445, 53, 62078)
# Services that are worth a second look if a device exposes them.
RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------- discovery ----------

def local_subnet() -> ipaddress.IPv4Network:
    """Find this machine's IP and assume a /24 network around it."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))  # no packets sent; just picks the right interface
        ip = s.getsockname()[0]
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def ping(ip: str) -> bool:
    """Ping once. Returns True only if the device actually replied."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    elif system == "Darwin":  # macOS: -W is in milliseconds
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
    else:  # Linux: -W is in seconds
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return "ttl=" in result.stdout.lower()


def tcp_alive(ip: str) -> bool:
    """Catch devices that block pings: an open OR refused port both mean 'alive'."""
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=0.3):
                return True
        except ConnectionRefusedError:
            return True  # the device answered with "nothing here"
        except OSError:
            continue  # timed out or unreachable
    return False


def is_alive(ip: str) -> bool:
    return ping(ip) or tcp_alive(ip)


def arp_output() -> str:
    """Get the ARP table as text, trying `arp`, then `ip neigh`, then /proc."""
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            return subprocess.run(cmd, capture_output=True, text=True).stdout
        except FileNotFoundError:
            continue
    proc = Path("/proc/net/arp")
    if proc.exists():
        return proc.read_text()
    raise SystemExit(
        "Couldn't read the ARP table: neither 'arp' nor 'ip' is available. "
        "Run this on your own computer, not a cloud sandbox."
    )


def read_arp_table(subnet: ipaddress.IPv4Network) -> dict:
    """Return {mac: ip} for devices in the subnet, parsed from the ARP table."""
    devices = {}
    for line in arp_output().splitlines():
        ip_match, mac_match = IP_RE.search(line), MAC_RE.search(line)
        if not (ip_match and mac_match):
            continue
        ip = ip_match.group()
        try:
            if ipaddress.ip_address(ip) not in subnet:
                continue
        except ValueError:
            continue
        mac = mac_match.group().lower().replace("-", ":")
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
            continue  # skip broadcast / multicast
        devices[mac] = ip
    return devices


def scan() -> dict:
    subnet = local_subnet()
    print(f"Scanning {subnet} ...")
    hosts = [str(host) for host in subnet.hosts()]
    alive = set()
    for attempt in range(2):  # extra pass catches devices that are slow to wake
        with ThreadPoolExecutor(max_workers=32) as pool:
            replies = list(pool.map(is_alive, hosts))
        alive.update(ip for ip, ok in zip(hosts, replies) if ok)
        print(f"  pass {attempt + 1}/2: {len(alive)} devices replied so far")
    # The ARP table keeps old entries for minutes, so only trust entries for
    # devices that actually answered during this scan.
    return {mac: ip for mac, ip in read_arp_table(subnet).items() if ip in alive}


# ---------- reporting ----------

def hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "unknown"


def open_risky_ports(ip: str) -> list:
    def check(port):
        with socket.socket() as s:
            s.settimeout(0.5)
            return port if s.connect_ex((ip, port)) == 0 else None

    with ThreadPoolExecutor(max_workers=len(RISKY_PORTS)) as pool:
        return [(port, RISKY_PORTS[port]) for port in pool.map(check, RISKY_PORTS) if port]


def log(message: str) -> None:
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}"
    print(line)
    with LOG_FILE.open("a") as f:
        f.write(line + "\n")


def report(found: dict, known: dict, check_ports: bool) -> None:
    print(f"\n{len(found)} devices found ({datetime.now():%Y-%m-%d %H:%M})\n")
    print(f"{'STATUS':<8} {'IP':<16} {'MAC':<18} HOSTNAME")
    for mac, ip in sorted(found.items(), key=lambda kv: ipaddress.ip_address(kv[1])):
        status = "ok" if mac in known else "NEW"
        print(f"{status:<8} {ip:<16} {mac:<18} {hostname(ip)}")
        if check_ports:
            for port, name in open_risky_ports(ip):
                print(f"         ! port {port} ({name}) is open on this device")

    new = [mac for mac in found if mac not in known]
    if new:
        print(f"\n{len(new)} unrecognized device(s). If they're yours, run with --trust.")
    else:
        print("\nAll devices recognized.")


def watch(known: dict, interval: int) -> None:
    alerted = set()
    print(f"Watching every {interval}s. Press Ctrl+C to stop.")
    try:
        while True:
            for mac, ip in scan().items():
                if mac not in known and mac not in alerted:
                    alerted.add(mac)
                    log(f"NEW DEVICE {ip} {mac} ({hostname(ip)})")
                    print("\a", end="")  # terminal beep
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")


# ---------- main ----------

def main() -> None:
    parser = argparse.ArgumentParser(description="Home network watcher")
    parser.add_argument(
        "--trust", action="store_true", help="save all currently visible devices as trusted"
    )
    parser.add_argument(
        "--ports", action="store_true", help="check found devices for risky open ports"
    )
    parser.add_argument(
        "--watch", type=int, metavar="SECONDS", help="rescan repeatedly and log new devices"
    )
    args = parser.parse_args()

    known = json.loads(KNOWN_FILE.read_text()) if KNOWN_FILE.exists() else {}

    if args.watch:
        watch(known, args.watch)
        return

    found = scan()
    report(found, known, args.ports)

    if args.trust:
        for mac, ip in found.items():
            known.setdefault(mac, {"first_seen": datetime.now().isoformat(), "ip": ip})
        KNOWN_FILE.write_text(json.dumps(known, indent=2))
        print(f"Saved {len(known)} trusted devices to {KNOWN_FILE}")


if __name__ == "__main__":
    main()