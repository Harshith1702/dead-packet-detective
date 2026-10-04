"""Turns raw observations (dicts) into findings, keeping confirmed facts apart from hypotheses."""

CONFIRMED, HYPOTHESIS, NEXT, LIMIT = "confirmed", "hypothesis", "next", "limitation"

STANDING_LIMITS = [
    "Probes run from this machine only; a different network vantage point may see different results.",
    "Firewalls can drop ICMP or TCP selectively, so a failed probe shows no answer, not why there was none.",
    "Ping and traceroute output is parsed from the OS tools; non-English Windows may need parser changes.",
]


def finding(kind, text):
    return {"kind": kind, "text": text}


def rtt_stats(rtts, sent):
    stats = {"sent": sent, "received": len(rtts), "loss_pct": round(100 * (sent - len(rtts)) / sent, 1)}
    if rtts:
        diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
        stats.update(min=min(rtts), avg=round(sum(rtts) / len(rtts), 1), max=max(rtts),
                     jitter=round(sum(diffs) / len(diffs), 1) if diffs else 0.0)
    return stats


def analyze(target, observations):
    by_probe = lambda name: [o for o in observations if o["probe"] == name]
    dns = by_probe("dns")[0]
    if dns["status"] == "failed":
        return [
            finding(CONFIRMED, "The system resolver returned no address, so no packet was ever sent to the target."),
            finding(HYPOTHESIS, "The name is mistyped or does not exist, or the configured DNS server is unreachable."),
            finding(NEXT, f"Ask a different resolver: nslookup {target} 8.8.8.8 and compare with nslookup {target}."),
        ] + [finding(LIMIT, t) for t in STANDING_LIMITS[:1]]

    out = []
    ping = (by_probe("ping") or [None])[0]
    tcps = by_probe("tcp")
    ping_ok = bool(ping) and ping["status"] == "ok"
    tcp_alive = [t for t in tcps if t["status"] in ("ok", "refused")]
    alive = ping_ok or bool(tcp_alive)

    if ping_ok:
        s = rtt_stats(ping["data"]["rtts"], ping["data"]["sent"])
        out.append(finding(CONFIRMED, f"Host answers ICMP echo: {s['received']}/{s['sent']} replies, "
                                      f"rtt {s['min']}/{s['avg']}/{s['max']} ms (min/avg/max), jitter {s['jitter']} ms."))
        if 0 < s["loss_pct"] < 100:
            out.append(finding(HYPOTHESIS, f"{s['loss_pct']}% echo loss suggests congestion, a lossy link, or ICMP rate limiting."))
            out.append(finding(NEXT, "Repeat with more probes (ping -n 50) and compare at a different time of day."))
    for t in tcps:
        port = t["data"]["port"]
        if t["status"] == "ok":
            out.append(finding(CONFIRMED, f"TCP port {port} accepts connections ({t['data']['ms']} ms handshake)."))
        elif t["status"] == "refused":
            out.append(finding(CONFIRMED, f"Port {port} sent a reset: the host is up and reachable, but nothing is accepting on that port."))
            out.append(finding(NEXT, f"On the server, check the service is running and bound to the right interface (netstat -ano | findstr :{port})."))
        elif t["status"] == "timeout" and alive:
            out.append(finding(HYPOTHESIS, f"Port {port} gave no reply although the host is reachable another way: a firewall is likely dropping SYNs to it."))
    if ping and ping["status"] == "timeout" and tcp_alive:
        out.append(finding(HYPOTHESIS, "ICMP echo is probably filtered; TCP evidence shows the host itself is not down."))
    if not alive and (ping or tcps):
        out.append(finding(CONFIRMED, "No probe received any answer from the target."))
        out.append(finding(HYPOTHESIS, "The host is offline, a firewall drops everything we sent, or this machine has no route out."))
        out.append(finding(NEXT, "Test a known-good target (ping 1.1.1.1) to separate a local connectivity problem from a remote one."))
    if ping and ping["status"] == "unavailable":
        out.append(finding(LIMIT, "ping is not available here, so ICMP evidence was not collected."))

    trace = (by_probe("traceroute") or [None])[0]
    if trace and trace["status"] == "ok":
        hops = trace["data"]["hops"]
        silent = [h["hop"] for h in hops if h["address"] is None]
        if silent:
            out.append(finding(LIMIT, f"Hops {', '.join(map(str, silent))} did not answer. Routers often ignore TTL-expired probes "
                                      "while forwarding traffic normally, so silence is not evidence of a faulty router."))
        if not trace["data"]["reached"] and alive:
            out.append(finding(HYPOTHESIS, "Traceroute stopped short although the host is reachable: probe traffic is likely filtered near the destination."))
    elif trace and trace["status"] in ("unavailable", "timeout", "failed"):
        out.append(finding(LIMIT, f"Route evidence is missing: {trace['summary']}"))
    return out + [finding(LIMIT, t) for t in STANDING_LIMITS]
