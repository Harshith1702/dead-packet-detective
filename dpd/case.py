"""A case is one investigation: ordered observations plus the findings drawn from them."""
import uuid
from dataclasses import asdict

from dpd import evidence
from dpd.analysis import analyze


def new_case(raw_target, raw_ports):
    """Validate input and open a case. Raises ValueError on bad input."""
    return {"id": uuid.uuid4().hex[:8], "target": evidence.validate_target(raw_target),
            "ports": evidence.parse_ports(raw_ports), "status": "running", "started": evidence.utc_now(),
            "finished": None, "address": None, "observations": [], "findings": [], "error": None}


def run_case(case):
    """Collect evidence in order, appending each observation as soon as it exists."""
    def record(obs):
        case["observations"].append(asdict(obs))

    try:
        obs, address = evidence.resolve(case["target"])
        record(obs)
        if address:
            case["address"] = address
            record(evidence.run_ping(address))
            for port in case["ports"]:
                record(evidence.tcp_probe(address, port))
            record(evidence.run_traceroute(address))
        case["findings"] = analyze(case["target"], case["observations"])
        case["status"] = "done"
    except Exception as exc:  # surfaced to the user, never reported as success
        case["status"], case["error"] = "error", f"{type(exc).__name__}: {exc}"
    finally:
        case["finished"] = evidence.utc_now()
