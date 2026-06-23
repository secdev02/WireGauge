#!/usr/bin/env python3
"""
generate_report.py — Build a self-contained HTML peer-review report
from the JSON Lines logs produced by wg_fuzzer.py and wg_monitor.

All CSS and data are inlined so the file opens without a web server.

Usage:
    python3 generate_report.py \
        --fuzzer-log  wg_fuzz_logs/fuzzer.jsonl \
        --monitor-log wg_fuzz_logs/monitor.jsonl \
        --anomaly-log wg_fuzz_logs/anomalies.jsonl \
        --config      wg_fuzz_config.json \
        --output      wg_fuzz_logs/report.html
"""

import argparse
import html
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ── Data loading ──────────────────────────────────────────────────────────────

def load_jsonl(path: str) -> list:
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return records


def load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ── Statistics ────────────────────────────────────────────────────────────────

def compute_stats(fuzzer: list, monitor: list) -> dict:
    total_sent    = sum(1 for r in fuzzer  if r.get("source") == "fuzzer" and "pkt_hex" in r)
    total_anomaly = sum(1 for r in fuzzer  if r.get("anomaly"))
    total_crashes = sum(1 for r in monitor if r.get("severity") == "CRASH")
    total_warns   = sum(1 for r in monitor if r.get("severity") == "WARN")

    by_phase: dict[str, dict] = defaultdict(lambda: {"sent": 0, "anomaly": 0})
    by_strategy: Counter = Counter()
    elapsed_vals = []

    for r in fuzzer:
        if "pkt_hex" not in r:
            continue
        phase    = r.get("phase", "?")
        strategy = r.get("strategy", "?")
        by_phase[phase]["sent"] += 1
        by_strategy[strategy]  += 1
        if r.get("anomaly"):
            by_phase[phase]["anomaly"] += 1
        if r.get("elapsed_ms") is not None:
            elapsed_vals.append(r["elapsed_ms"])

    taint_changes = [r for r in monitor if r.get("event") == "taint_change"]
    final_taint   = 0
    stat_recs     = [r for r in monitor if r.get("source") == "stats"]
    if stat_recs:
        final_taint = stat_recs[-1].get("kernel_taint", 0)

    avg_ms = (sum(elapsed_vals) / len(elapsed_vals)) if elapsed_vals else 0.0
    max_ms = max(elapsed_vals) if elapsed_vals else 0.0

    return {
        "total_sent":      total_sent,
        "total_anomaly":   total_anomaly,
        "total_crashes":   total_crashes,
        "total_warns":     total_warns,
        "by_phase":        dict(by_phase),
        "by_strategy":     by_strategy.most_common(20),
        "taint_changes":   taint_changes,
        "final_taint":     final_taint,
        "avg_response_ms": round(avg_ms, 2),
        "max_response_ms": round(max_ms, 2),
    }


# ── HTML generation ───────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Courier New', monospace;
    background: #0d1117;
    color: #c9d1d9;
    font-size: 13px;
    line-height: 1.6;
}
header {
    background: #161b22;
    border-bottom: 2px solid #30363d;
    padding: 24px 40px;
}
header h1 {
    font-size: 22px;
    color: #58a6ff;
    letter-spacing: 1px;
    font-weight: 600;
}
header .meta {
    color: #8b949e;
    font-size: 12px;
    margin-top: 4px;
}
.container { padding: 32px 40px; max-width: 1400px; }

/* Stat cards */
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}
.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 20px 16px;
    text-align: center;
}
.card .val {
    font-size: 36px;
    font-weight: 700;
    color: #58a6ff;
}
.card .val.red   { color: #f85149; }
.card .val.green { color: #3fb950; }
.card .val.amber { color: #d29922; }
.card .lbl {
    color: #8b949e;
    font-size: 11px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    margin-top: 4px;
}

/* Sections */
h2 {
    font-size: 14px;
    color: #58a6ff;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid #30363d;
    padding-bottom: 8px;
    margin: 32px 0 16px;
}

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin-bottom: 24px;
}
th {
    background: #21262d;
    color: #8b949e;
    text-align: left;
    padding: 8px 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    font-size: 11px;
}
td {
    padding: 7px 12px;
    border-bottom: 1px solid #21262d;
    vertical-align: top;
    word-break: break-all;
}
tr:hover td { background: #161b22; }

.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
}
.badge-red    { background: rgba(248,81,73,0.15); color: #f85149; }
.badge-green  { background: rgba(63,185,80,0.15); color: #3fb950; }
.badge-amber  { background: rgba(210,153,34,0.15); color: #d29922; }
.badge-blue   { background: rgba(88,166,255,0.15); color: #58a6ff; }
.badge-grey   { background: rgba(139,148,158,0.15); color: #8b949e; }

.hex {
    font-family: 'Courier New', monospace;
    color: #79c0ff;
    font-size: 11px;
}
.reason { color: #d29922; font-style: italic; }

/* Phase bars */
.phase-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
}
.phase-bar .lbl { width: 80px; color: #8b949e; }
.bar-track {
    flex: 1;
    background: #21262d;
    border-radius: 3px;
    height: 18px;
    position: relative;
}
.bar-fill {
    height: 100%;
    border-radius: 3px;
    background: linear-gradient(90deg, #1f6feb, #58a6ff);
    min-width: 2px;
}
.bar-fill.anomaly { background: linear-gradient(90deg, #8b1a1a, #f85149); }
.bar-num { color: #c9d1d9; font-size: 11px; min-width: 40px; text-align: right; }

footer {
    border-top: 1px solid #30363d;
    padding: 20px 40px;
    color: #8b949e;
    font-size: 11px;
    margin-top: 32px;
}
"""

def _badge(text: str, color: str) -> str:
    return '<span class="badge badge-{}">{}</span>'.format(color, html.escape(str(text)))


def _card(val: object, label: str, color: str = "blue") -> str:
    return (
        '<div class="card">'
        '<div class="val {}">{}</div>'
        '<div class="lbl">{}</div>'
        '</div>'
    ).format(color, html.escape(str(val)), html.escape(label))


def _phase_bar(label: str, sent: int, max_sent: int, color: str = "") -> str:
    pct = int((sent / max_sent * 100)) if max_sent else 0
    return (
        '<div class="phase-bar">'
        '<span class="lbl">{}</span>'
        '<div class="bar-track"><div class="bar-fill {}" style="width:{}%"></div></div>'
        '<span class="bar-num">{}</span>'
        '</div>'
    ).format(html.escape(label), color, pct, sent)


def build_html(stats: dict, fuzzer: list, monitor: list,
               anomalies: list, config: dict) -> str:

    gen_ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    run_ts  = config.get("run_ts", gen_ts)
    server  = "{}:{}".format(config.get("server_ip", "?"), config.get("server_port", "?"))
    seed    = config.get("seed", "?")
    kernel  = config.get("kernel", "?")

    # ── Summary cards ─────────────────────────────────────────────────────────
    crash_color = "red"   if stats["total_crashes"] else "green"
    anom_color  = "amber" if stats["total_anomaly"]  else "green"
    taint_color = "red"   if stats["final_taint"]    else "green"

    cards_html = (
        '<div class="cards">'
        + _card(stats["total_sent"],       "Packets sent",       "blue")
        + _card(stats["total_anomaly"],    "Anomalies",          anom_color)
        + _card(stats["total_crashes"],    "Kernel crashes",     crash_color)
        + _card(stats["total_warns"],      "Kernel warnings",    "amber" if stats["total_warns"] else "green")
        + _card(stats["final_taint"],      "Kernel taint",       taint_color)
        + _card(stats["avg_response_ms"],  "Avg response ms",    "blue")
        + _card(stats["max_response_ms"],  "Max response ms",    "blue")
        + '</div>'
    )

    # ── Phase breakdown bars ──────────────────────────────────────────────────
    max_sent = max((v["sent"] for v in stats["by_phase"].values()), default=1)
    phase_html = ""
    for phase, pdata in sorted(stats["by_phase"].items()):
        phase_html += _phase_bar(phase, pdata["sent"], max_sent)
        if pdata["anomaly"]:
            phase_html += _phase_bar(
                phase + " anom", pdata["anomaly"], max_sent, "anomaly"
            )

    # ── Strategy table ────────────────────────────────────────────────────────
    strat_rows = ""
    for name, count in stats["by_strategy"]:
        strat_rows += (
            "<tr><td>{}</td><td>{}</td></tr>"
        ).format(html.escape(name), count)

    strat_table = (
        "<table>"
        "<tr><th>Strategy</th><th>Packets</th></tr>"
        "{}</table>"
    ).format(strat_rows)

    # ── Anomaly table ─────────────────────────────────────────────────────────
    anom_rows = ""
    for r in anomalies[:200]:   # cap at 200 rows for browser perf
        resp_len = r.get("resp_len", "")
        anom_rows += (
            "<tr>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td class='hex'>{}</td>"
            "<td class='reason'>{}</td>"
            "</tr>"
        ).format(
            html.escape(r.get("ts",       "?")[:19]),
            _badge(r.get("phase",    "?"), "blue"),
            _badge(r.get("strategy", "?"), "grey"),
            html.escape(str(resp_len)),
            html.escape(r.get("pkt_hex", "")[:48] + "..."),
            html.escape(r.get("reason", "")),
        )

    if not anom_rows:
        anom_rows = "<tr><td colspan='6' style='color:#3fb950;text-align:center'>No anomalies detected</td></tr>"

    anom_table = (
        "<table>"
        "<tr><th>Timestamp</th><th>Phase</th><th>Strategy</th>"
        "<th>Resp len</th><th>Packet (48 B hex)</th><th>Reason</th></tr>"
        "{}</table>"
    ).format(anom_rows)

    # ── Kernel events table ───────────────────────────────────────────────────
    kmsg_rows = ""
    for r in monitor:
        if r.get("source") != "kmsg":
            continue
        sev    = r.get("severity", "?")
        color  = "red" if sev == "CRASH" else "amber"
        kmsg_rows += (
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>"
        ).format(
            html.escape(r.get("ts", "?")[:19]),
            _badge(sev, color),
            html.escape(r.get("msg", "")[:200]),
        )

    if not kmsg_rows:
        kmsg_rows = "<tr><td colspan='3' style='color:#3fb950;text-align:center'>No kernel events detected</td></tr>"

    kmsg_table = (
        "<table>"
        "<tr><th>Timestamp</th><th>Severity</th><th>Message</th></tr>"
        "{}</table>"
    ).format(kmsg_rows)

    # ── Taint change table ────────────────────────────────────────────────────
    taint_rows = ""
    for r in stats["taint_changes"]:
        taint_rows += (
            "<tr><td>{}</td><td>{}</td><td style='color:#f85149'>{}</td></tr>"
        ).format(
            html.escape(r.get("ts", "?")[:19]),
            r.get("prev", "?"),
            r.get("now",  "?"),
        )
    if not taint_rows:
        taint_rows = "<tr><td colspan='3' style='color:#3fb950;text-align:center'>No taint changes — kernel remained clean</td></tr>"

    taint_table = (
        "<table>"
        "<tr><th>Timestamp</th><th>Previous taint</th><th>New taint</th></tr>"
        "{}</table>"
    ).format(taint_rows)

    # ── Final assembly ────────────────────────────────────────────────────────
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WireGuard Fuzz Report</title>
<style>{css}</style>
</head>
<body>

<header>
  <h1>&#x1F50D; WireGuard Protocol Fuzz Report</h1>
  <div class="meta">
    Generated: {gen_ts} &nbsp;|&nbsp;
    Run started: {run_ts} &nbsp;|&nbsp;
    Target: {server} &nbsp;|&nbsp;
    Seed: {seed} &nbsp;|&nbsp;
    Kernel: {kernel}
  </div>
</header>

<div class="container">

  <h2>Summary</h2>
  {cards}

  <h2>Packets by Phase</h2>
  {phase_bars}

  <h2>Packets by Strategy</h2>
  {strat_table}

  <h2>Anomalies ({anom_count})</h2>
  {anom_table}

  <h2>Kernel Messages</h2>
  {kmsg_table}

  <h2>Kernel Taint Changes</h2>
  {taint_table}

</div>

<footer>
  WireGuard Fuzz Harness &nbsp;|&nbsp;
  Audit findings: wireguard_length_offset_audit.md, wireguard_ecc_encryption_audit.md &nbsp;|&nbsp;
  Verify integrity: <code>sha256sum -c manifest.sha256</code>
</footer>
</body>
</html>""".format(
        css=CSS,
        gen_ts=html.escape(gen_ts),
        run_ts=html.escape(run_ts),
        server=html.escape(server),
        seed=html.escape(str(seed)),
        kernel=html.escape(str(kernel)),
        cards=cards_html,
        phase_bars=phase_html,
        strat_table=strat_table,
        anom_count=len(anomalies),
        anom_table=anom_table,
        kmsg_table=kmsg_table,
        taint_table=taint_table,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate self-contained HTML fuzz report")
    p.add_argument("--fuzzer-log",  default="wg_fuzz_logs/fuzzer.jsonl")
    p.add_argument("--monitor-log", default="wg_fuzz_logs/monitor.jsonl")
    p.add_argument("--anomaly-log", default="wg_fuzz_logs/anomalies.jsonl")
    p.add_argument("--config",      default="wg_fuzz_config.json")
    p.add_argument("--output",      default="wg_fuzz_logs/report.html")
    return p.parse_args()


def main() -> int:
    args   = parse_args()
    fuzzer = load_jsonl(args.fuzzer_log)
    mon    = load_jsonl(args.monitor_log)
    anom   = load_jsonl(args.anomaly_log)
    cfg    = load_json(args.config)

    if not fuzzer and not mon:
        print("No log data found — nothing to report.", file=sys.stderr)
        return 1

    stats = compute_stats(fuzzer, mon)
    page  = build_html(stats, fuzzer, mon, anom, cfg)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(page)

    size_kb = os.path.getsize(args.output) // 1024
    print("Report written: {} ({} KB)".format(args.output, size_kb))
    return 0


if __name__ == "__main__":
    sys.exit(main())
