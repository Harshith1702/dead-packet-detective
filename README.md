# Dead Packet Detective

A small network-forensics workbench. Give it a hostname or IP and it collects real evidence (DNS, ICMP echo, TCP handshakes, route), keeps confirmed observations apart from hypotheses, and writes a case file you can reproduce.

## Setup (Windows)

1. Install Python 3.10 or newer from python.org.
2. Unzip the project, open a terminal in its folder, run: `python -m dpd`

No packages to install, no accounts, no admin rights. A browser opens at http://127.0.0.1:8765 (bound to localhost only).
Uses the built-in `ping` and `tracert`. Linux/macOS also work if `ping` and `traceroute` are installed.

## Usage

Enter a target and optional TCP ports (default 443, 80), then open the case. Evidence appears row by row as each probe finishes; click a row for the exact command and raw data. When done, read the findings and download the Markdown case file.

Run tests: `python -m unittest discover -v`

## Architecture

| Module | Job |
|---|---|
| `dpd/evidence.py` | Input validation, DNS (`getaddrinfo`), TCP handshake timing (`socket`), ping and tracert via argument lists with timeouts, output parsers |
| `dpd/analysis.py` | Observations in, findings out: confirmed, hypothesis, next step, limitation |
| `dpd/case.py` | Orchestrates one investigation in a worker thread |
| `dpd/report.py` | Markdown case file |
| `dpd/server.py`, `static/index.html` | Local HTTP API and UI that polls for progress |

## Networking concepts it demonstrates

- DNS failure means no packet reaches the target at all.
- TCP SYN / SYN-ACK / ACK: success, a reset (RST, host up, port closed) and silence (dropped or filtered) are three different facts.
- ICMP echo and TTL-expired replies, and why firewalls and routers may ignore them.
- Traceroute works by raising TTL; a silent hop is not a faulty router.

## Limitations

- Single vantage point; no packet capture or PCAP analysis (cut to keep the workflow reliable).
- ping/tracert output is parsed as text and tested on English formats only.
- IPv4 route parsing only; IPv6 targets get DNS, ping and TCP evidence.
- Traceroute takes up to about a minute on unresponsive paths.
- Cases live in memory and vanish when the server stops; download the case file to keep it.

## Demo procedure

1. `example.com`, ports `443, 80`: healthy path; ICMP, TCP, route evidence.
2. `nonexistent.invalid`: DNS fails, so the tool states no packet was sent.
3. `127.0.0.1` with port `9`: connection refused (RST) shows "host up, nothing listening".
4. A silent hop in any traceroute: show the limitation wording, then explain why.
5. Download the case file and walk through the reproduce commands.
