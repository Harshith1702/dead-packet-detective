"""Render a case as a Markdown case file."""
import json

SECTIONS = [("confirmed", "Confirmed observations"), ("hypothesis", "Hypotheses (not proven)"),
            ("next", "Next diagnostic steps"), ("limitation", "Limitations")]


def render_markdown(case):
    lines = [f"# Case file: {case['target']}", "",
             f"- Address probed: {case['address'] or 'none (name did not resolve)'}",
             f"- Opened: {case['started']} (UTC)", f"- Closed: {case['finished'] or 'still running'} (UTC)",
             f"- Status: {case['status']}" + (f" ({case['error']})" if case["error"] else ""), "", "## Evidence log", ""]
    if not case["observations"]:
        lines.append("No evidence was collected.")
    for o in case["observations"]:
        lines.append(f"- `{o['at']}` **{o['probe']}** [{o['status']}] {o['summary']}")
        if o["command"]:
            lines.append(f"  - Reproduce: `{o['command']}`")
        if o["data"]:
            lines.append(f"  - Data: `{json.dumps(o['data'])}`")
    for kind, title in SECTIONS:
        items = [f["text"] for f in case["findings"] if f["kind"] == kind]
        if items:
            lines += ["", f"## {title}", ""] + [f"- {t}" for t in items]
    return "\n".join(lines) + "\n"
