import socket
import unittest

from dpd import evidence
from dpd.analysis import analyze, rtt_stats
from dpd.report import render_markdown

WIN_PING = """Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57
Request timed out.
Reply from 10.0.0.1: Destination host unreachable.
"""
LINUX_PING = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n"
WIN_TRACE = """Tracing route to 1.1.1.1 over a maximum of 15 hops
  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    13 ms  1.1.1.1
Trace complete.
"""


def obs(probe, status, **data):
    return {"probe": probe, "status": status, "summary": f"{probe} {status}", "data": data, "command": "", "at": "t"}


class ValidationTests(unittest.TestCase):
    def test_accepts_hostname_and_ip(self):
        self.assertEqual(evidence.validate_target(" Example.COM "), "example.com")
        self.assertEqual(evidence.validate_target("8.8.8.8"), "8.8.8.8")

    def test_rejects_injection_and_junk(self):
        for bad in ["", "   ", "-c 100 host", "a b", "host;dir", "bad_name.com", "x" * 300]:
            with self.assertRaises(ValueError, msg=bad):
                evidence.validate_target(bad)

    def test_ports(self):
        self.assertEqual(evidence.parse_ports(""), [443, 80])
        self.assertEqual(evidence.parse_ports("22, 22,8080"), [22, 8080])
        for bad in ["0", "70000", "abc", "1,2,3,4,5,6"]:
            with self.assertRaises(ValueError):
                evidence.parse_ports(bad)


class ParserTests(unittest.TestCase):
    def test_windows_ping_counts_only_real_replies(self):
        self.assertEqual(evidence.parse_ping(WIN_PING), [(12.0, 57), (1.0, 57)])

    def test_linux_ping(self):
        self.assertEqual(evidence.parse_ping(LINUX_PING), [(12.3, 57)])

    def test_empty_output(self):
        self.assertEqual(evidence.parse_ping(""), [])
        self.assertEqual(evidence.parse_traceroute("garbage"), [])

    def test_traceroute_keeps_silent_hop(self):
        hops = evidence.parse_traceroute(WIN_TRACE)
        self.assertEqual([h["address"] for h in hops], ["192.168.1.1", None, "1.1.1.1"])
        self.assertEqual(hops[0]["rtts"], [1.0, 1.0, 1.0])
        self.assertEqual(hops[1]["rtts"], [])


class ProbeTests(unittest.TestCase):
    def test_tcp_ok_and_refused_on_loopback(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            self.assertEqual(evidence.tcp_probe("127.0.0.1", port).status, "ok")
        self.assertEqual(evidence.tcp_probe("127.0.0.1", port).status, "refused")

    def test_dns_failure_is_reported(self):
        observation, address = evidence.resolve("no-such-host.invalid")
        self.assertEqual(observation.status, "failed")
        self.assertIsNone(address)


class AnalysisTests(unittest.TestCase):
    def kinds(self, findings, kind):
        return " ".join(f["text"] for f in findings if f["kind"] == kind)

    def test_rtt_stats(self):
        s = rtt_stats([10.0, 20.0, 10.0], 4)
        self.assertEqual((s["loss_pct"], s["min"], s["avg"], s["jitter"]), (25.0, 10.0, 13.3, 10.0))

    def test_dns_failure_stops_before_network_claims(self):
        out = analyze("x.test", [obs("dns", "failed")])
        self.assertIn("no packet was ever sent", self.kinds(out, "confirmed"))

    def test_icmp_filtered_is_a_hypothesis_not_an_outage(self):
        out = analyze("h", [obs("dns", "ok"), obs("ping", "timeout", sent=4, rtts=[]), obs("tcp", "ok", port=443, ms=20)])
        self.assertIn("ICMP echo is probably filtered", self.kinds(out, "hypothesis"))
        self.assertNotIn("offline", self.kinds(out, "hypothesis"))

    def test_silent_hop_is_not_called_a_fault(self):
        hops = [{"hop": 1, "address": None, "rtts": []}, {"hop": 2, "address": "1.1.1.1", "rtts": [5.0]}]
        out = analyze("1.1.1.1", [obs("dns", "ok"), obs("traceroute", "ok", hops=hops, reached=True)])
        self.assertIn("not evidence of a faulty router", self.kinds(out, "limitation"))

    def test_report_contains_evidence_and_limits(self):
        case = {"target": "h", "address": "1.1.1.1", "started": "s", "finished": "f", "status": "done", "error": None,
                "observations": [obs("dns", "ok")], "findings": analyze("h", [obs("dns", "ok")])}
        text = render_markdown(case)
        self.assertIn("## Evidence log", text)
        self.assertIn("## Limitations", text)


if __name__ == "__main__":
    unittest.main()
