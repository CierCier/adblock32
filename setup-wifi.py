#!/usr/bin/env python3
"""
setup-wifi.py – Configure WiFi on an adblock32 board via serial.

Scans available WiFi networks using NetworkManager (nmcli), prompts the
user to select one, asks for a password if the network is secured, then
sends the credentials to the board over a hidden serial protocol.

Usage:
    ./setup-wifi.py [<serial-port>]
    ./setup-wifi.py --clear [<serial-port>]

If no port is given the script auto-detects the first adblock32 device.
Use --clear to erase saved credentials on the board.
"""

from __future__ import annotations

import argparse
import glob
import re
import subprocess
import sys
import time
from typing import NamedTuple

import serial  # pip install pyserial


SERIAL_BAUD = 115200
MAGIC = b"\x02\xAD\x32"  # hidden command prefix (STX + magic bytes)


class Network(NamedTuple):
    ssid: str
    security: str
    signal: str


# ── Port detection ──────────────────────────────────────────────────────────


def find_adblock32_port() -> str | None:
    for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*", "/dev/ttyAMA*"):
        for path in sorted(glob.glob(pattern)):
            try:
                s = serial.Serial(path, SERIAL_BAUD, timeout=1.5)
                time.sleep(0.3)
                s.reset_input_buffer()
                s.write(b"\nhelp\n")
                time.sleep(0.5)
                data = s.read_all()
                s.close()
                if b"adblock32" in data or b"filter" in data:
                    return path
            except (serial.SerialException, OSError):
                continue
    return None


# ── Network scanning via NetworkManager ─────────────────────────────────────


def scan_nmcli() -> list[Network] | None:
    try:
        result = subprocess.run(
            ["nmcli", "-f", "SSID,SECURITY,SIGNAL", "-t", "device", "wifi", "list"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    seen: set[str] = set()
    nets: list[Network] = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split(":")
        ssid = parts[0] if parts[0] else ""
        security = parts[1] if len(parts) > 1 else ""
        signal = parts[2] if len(parts) > 2 else ""
        if not ssid or ssid == "\x00":
            continue
        if ssid not in seen:
            seen.add(ssid)
            nets.append(Network(ssid, security, signal))
    return nets


def scan_iwd() -> list[Network] | None:
    """Fallback: IWD station get-networks."""
    try:
        subprocess.run(["iwctl", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    try:
        r = subprocess.run(
            ["iwctl", "device", "list"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.split("\n"):
            m = re.search(r"^\s*(\w+)\s+", line)
            if m:
                station = m.group(1)
                break
        else:
            return None
    except Exception:
        return None

    try:
        result = subprocess.run(
            ["iwctl", "station", station, "get-networks"],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    nets: list[Network] = []
    for line in result.stdout.split("\n"):
        m = re.match(r"\s{2,}(\S.+?)\s{2,}(\S+)", line)
        if m:
            ssid = m.group(1).strip()
            sec = m.group(2).strip()
            if ssid and ssid != "Network":
                nets.append(Network(ssid, sec, ""))
    return nets


def scan_networks() -> list[Network]:
    nets = scan_nmcli()
    if nets:
        return nets
    nets = scan_iwd()
    if nets:
        return nets
    print("error: no WiFi scanning backend found (needs nmcli or iwctl)", file=sys.stderr)
    sys.exit(1)


# ── Serial communication ────────────────────────────────────────────────────


def send_command(s: serial.Serial, command: str, timeout: float = 5) -> str:
    """Send a hidden command and return the full response within *timeout* seconds.

    Unlike the old send_hidden, this reads without stopping at the first newline
    so it captures all output including connection dots.
    """
    s.reset_input_buffer()
    s.write(MAGIC + command.encode() + b"\n")
    s.flush()
    deadline = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < deadline:
        try:
            if s.in_waiting:
                buf += s.read(s.in_waiting)
        except serial.SerialException:
            break
        time.sleep(0.05)
    return buf.decode(errors="replace").strip()


def wait_for_board(s: serial.Serial, timeout: float = 8) -> bool:
    """Wait until the board prints its boot banner."""
    deadline = time.monotonic() + timeout
    s.reset_input_buffer()
    s.write(b"\n")
    while time.monotonic() < deadline:
        try:
            data = s.read_all()
            if b"adblock32" in data or b"help" in data or b"commands" in data:
                return True
        except serial.SerialException:
            return False
        time.sleep(0.2)
    return False


# ── Main logic ──────────────────────────────────────────────────────────────


def pick_network(nets: list[Network]) -> Network:
    print("\navailable WiFi networks:\n")
    for i, net in enumerate(nets):
        lock = "\U0001F512" if net.security.lower() not in ("", "--", "open") else "  "
        print(f"  [{i}] {lock} {net.ssid:<30s} {net.security:<15s} {net.signal}")
    print()

    while True:
        try:
            idx = int(input("select network [0-{}]: ".format(len(nets) - 1)))
            if 0 <= idx < len(nets):
                return nets[idx]
        except (ValueError, EOFError):
            pass
        print("invalid selection")


def get_password(net: Network) -> str:
    if net.security.lower() in ("", "--", "open"):
        return ""
    while True:
        pw = input(f"password for '{net.ssid}': ")
        if pw:
            return pw


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure WiFi on adblock32")
    parser.add_argument("port", nargs="?", help="serial port (auto-detect if omitted)")
    parser.add_argument("--clear", action="store_true", help="erase saved WiFi credentials on the board")
    args = parser.parse_args()

    port = args.port or find_adblock32_port()
    if not port:
        print(
            "error: could not find adblock32 device.\n"
            "  Provide a serial port, e.g. ./setup-wifi.py /dev/ttyACM0",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"connecting to {port} ...")
    s = serial.Serial(port, SERIAL_BAUD, timeout=2)
    s.setDTR(False)
    time.sleep(0.3)

    if not wait_for_board(s):
        print("warning: board did not respond; attempting anyway")

    if args.clear:
        resp = send_command(s, "wifi clear", timeout=5)
        print(resp)
        s.close()
        return

    # 1 – scan networks
    nets = scan_networks()
    if not nets:
        print("error: no WiFi networks found", file=sys.stderr)
        s.close()
        sys.exit(1)

    net = pick_network(nets)
    pw = get_password(net)

    # 2 – check current state; if already connected to the chosen network, skip
    resp = send_command(s, "wifi status", timeout=3)
    if f"ssid={net.ssid}" in resp and "status=3" in resp:
        print(f"\nalready connected to '{net.ssid}'.")
        s.close()
        return

    # 3 – send credentials via hidden protocol (pipe-delimited: ssid|password)
    #    The board blocks for up to 15 s while connecting, so use a long timeout.
    print(f"\nsending credentials for '{net.ssid}' ...")
    resp = send_command(s, f"wifi set {net.ssid}|{pw}", timeout=20)
    for line in resp.split("\n"):
        line = line.strip()
        if line:
            print(f"  {line}")

    # 4 – check result
    connected = False
    for _ in range(3):
        time.sleep(1)
        resp = send_command(s, "wifi status", timeout=3)
        if "status=3" in resp or ("ip=" in resp and "0.0.0.0" not in resp):
            connected = True
            break

    if connected:
        print("\nsuccess: board connected to WiFi.\n")
        for line in resp.split("\n"):
            line = line.strip()
            if line:
                print(f"  {line}")
    else:
        print("\nfailed: board could not connect. check SSID and password.", file=sys.stderr)

    s.close()


if __name__ == "__main__":
    main()
