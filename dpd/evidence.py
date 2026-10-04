"""Evidence collection. Probes record what happened; interpretation lives in analysis.py."""
import ipaddress
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

IS_WINDOWS = platform.system() == "Windows"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RTT_RE = re.compile(r"<?\s*([\d.]+)\s*ms", re.I)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Observation:
    probe: str
    status: str  # ok | refused | timeout | failed | unavailable
    summary: str
    data: dict = field(default_factory=dict)
    command: str = ""
    at: str = field(default_factory=utc_now)


def validate_target(raw):
    """Return a normalised hostname or IP literal, or raise ValueError."""
    target = (raw or "").strip()
    if not target or len(target) > 253:
        raise ValueError("Enter a hostname or IP address.")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if not HOSTNAME_RE.match(target):
        raise ValueError(f"'{target}' is not a valid hostname or IP address.")
    return target.lower()


def parse_ports(raw):
    ports = []
    for part in str(raw or "").replace(" ", "").split(","):
        if not part:
            continue
        if not part.isdigit() or not 1 <= int(part) <= 65535:
            raise ValueError(f"'{part}' is not a valid port (1-65535).")
        ports.append(int(part))
    ports = list(dict.fromkeys(ports))
    if len(ports) > 5:
        raise ValueError("Probe at most 5 ports.")
    return ports or [443, 80]


def resolve(target):
    """Return (observation, address to probe or None)."""
    try:
        ipaddress.ip_address(target)
        return Observation("dns", "ok", "Target is an IP literal; no DNS lookup needed.",
                           {"addresses": [target]}), target
    except ValueError:
        pass
    command = f"getaddrinfo({target})"
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return Observation("dns", "failed", f"System resolver could not resolve {target}: {exc.strerror or exc}",
                           {"error": str(exc)}, command), None
    ms = (time.perf_counter() - start) * 1000
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    chosen = next((a for a in addresses if ":" not in a), addresses[0])
    return Observation("dns", "ok", f"{target} resolved to {', '.join(addresses)} in {ms:.0f} ms",
                       {"addresses": addresses, "ms": round(ms, 1)}, command), chosen


def tcp_probe(address, port, timeout=3.0):
    """Attempt a full TCP handshake. A refusal (RST) still proves the host is reachable."""
    command = f"connect({address}, {port}), timeout {timeout:g}s"
    data = {"port": port}
    start = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            data["ms"] = round((time.perf_counter() - start) * 1000, 1)
            return Observation("tcp", "ok", f"Port {port} completed the TCP handshake in {data['ms']:.0f} ms.", data, command)
    except ConnectionRefusedError:
        return Observation("tcp", "refused", f"Port {port} answered with a reset (RST): host reachable, nothing accepting connections.", data, command)
    except (socket.timeout, TimeoutError):
        return Observation("tcp", "timeout", f"No reply to the SYN on port {port} within {timeout:g} s.", data, command)
    except OSError as exc:
        return Observation("tcp", "failed", f"Connect to port {port} failed: {exc.strerror or exc}", {**data, "error": str(exc)}, command)


def _run(probe, args, timeout):
    """Run a diagnostic tool with an argument list (never a shell string)."""
    command = " ".join(args)
    try:
        done = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout)
    except FileNotFoundError:
        return None, Observation(probe, "unavailable", f"'{args[0]}' is not installed or not on PATH.", command=command)
    except subprocess.TimeoutExpired:
        return None, Observation(probe, "timeout", f"{args[0]} did not finish within {timeout} s.", command=command)
    return done.stdout, None


def parse_ping(output):
    """Return [(rtt_ms, ttl)] for each echo reply. Handles Windows and Linux/macOS formats."""
    replies = []
    for line in output.splitlines():
        ttl = re.search(r"ttl[=:]\s*(\d+)", line, re.I)
        rtt = re.search(r"time[=<]\s*([\d.]+)\s*ms", line, re.I)
        if ttl and rtt:
            replies.append((float(rtt.group(1)), int(ttl.group(1))))
    return replies


def run_ping(address, count=4):
    args = (["ping", "-n", str(count), "-w", "2000", address] if IS_WINDOWS
            else ["ping", "-c", str(count), "-W", "2", address])
    output, failure = _run("ping", args, timeout=count * 3 + 5)
    if failure:
        return failure
    replies = parse_ping(output)
    data = {"sent": count, "rtts": [r for r, _ in replies], "ttl": replies[-1][1] if replies else None,
            "output_tail": output.strip().splitlines()[-3:]}
    status = "ok" if replies else "timeout"
    return Observation("ping", status, f"{len(replies)} of {count} echo requests answered.", data, " ".join(args))


def parse_traceroute(output):
    """Return [{'hop', 'address' (None if silent), 'rtts'}] from tracert/traceroute output."""
    hops = []
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not match:
            continue
        rest = match.group(2)
        address = IPV4_RE.search(rest)
        hops.append({"hop": int(match.group(1)), "address": address.group(0) if address else None,
                     "rtts": [float(v) for v in RTT_RE.findall(rest)]})
    return hops


def run_traceroute(address, max_hops=15):
    args = (["tracert", "-d", "-h", str(max_hops), "-w", "1000", address] if IS_WINDOWS
            else ["traceroute", "-n", "-m", str(max_hops), "-w", "1", address])
    output, failure = _run("traceroute", args, timeout=max_hops * 4 + 20)
    if failure:
        return failure
    hops = parse_traceroute(output)
    reached = bool(hops) and hops[-1]["address"] == address
    if not hops:
        return Observation("traceroute", "failed", "No hops could be parsed from the tool output.",
                           {"output_tail": output.strip().splitlines()[-3:]}, " ".join(args))
    note = "reached the destination" if reached else "did not reach the destination within the hop limit"
    return Observation("traceroute", "ok", f"{len(hops)} hops recorded; {note}.",
                       {"hops": hops, "reached": reached}, " ".join(args))
