#!/usr/bin/env python3
"""Flappy CDN live dashboard — LAN only. No third-party deps."""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN_HOST = os.environ.get("CDN_DASH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CDN_DASH_PORT", "8090"))
ACCESS_LOG = os.environ.get(
    "CDN_ACCESS_LOG", "/var/log/nginx/cdn.flappy.su.access.log"
)
NGINX_PORT = os.environ.get("CDN_NGINX_PORT", "8080")
ALLOW_PREFIXES = tuple(
    p.strip()
    for p in os.environ.get(
        "CDN_DASH_ALLOW", "192.168.,10.,127.0.0.1,::1"
    ).split(",")
    if p.strip()
)
RECENT_MAX = 200
POLL_SS_SEC = 1.0

# Combined log + optional request_time + optional trailing fields (e.g. xff="…")
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?P<proto> [^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\d+|-) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
    r'(?: (?P<rt>[\d.]+))?'
    r'(?: .*)?$'
)

lock = threading.Lock()
state = {
    "started": time.time(),
    "active": [],
    "recent": deque(maxlen=RECENT_MAX),
    "log_offset": 0,
    "totals": {"bytes": 0, "reqs": 0},
    "by_ip_bytes_1m": {},
    "events_1m": deque(),
}


def client_allowed(addr: str) -> bool:
    if not addr:
        return False
    if addr.startswith("::ffff:"):
        addr = addr[7:]
    for p in ALLOW_PREFIXES:
        if addr.startswith(p) or addr == p:
            return True
    return False


def human_bytes(n: float) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or u == "TB":
            if u == "B":
                return f"{int(n)} {u}"
            return f"{n:.1f} {u}"
        n /= 1024.0
    return f"{n:.1f} TB"


def parse_ss() -> list[dict]:
    rows = []
    try:
        out = subprocess.check_output(
            ["ss", "-tniH", f"sport = :{NGINX_PORT}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return rows

    blocks = []
    cur = None
    for line in out.splitlines():
        if not line.strip():
            continue
        if line[0] not in (" ", "\t"):
            if cur:
                blocks.append(cur)
            cur = {"header": line.strip(), "info": ""}
        else:
            if cur is not None:
                cur["info"] += " " + line.strip()
    if cur:
        blocks.append(cur)

    hdr_re = re.compile(
        r"^(?P<state>\S+)\s+\d+\s+(?P<sendq>\d+)\s+"
        r"(?P<local>\S+):(?P<lport>\d+)\s+(?P<peer>\S+):(?P<pport>\d+)"
    )
    for b in blocks:
        m = hdr_re.match(b["header"])
        if not m:
            continue
        peer = m.group("peer")
        if peer in ("0.0.0.0", "*", "::"):
            continue
        info = b["info"]
        bytes_sent = None
        mbs = re.search(r"bytes_sent:(\d+)", info)
        if mbs:
            bytes_sent = int(mbs.group(1))
        mba = re.search(r"bytes_acked:(\d+)", info)
        bytes_acked = int(mba.group(1)) if mba else None
        rows.append(
            {
                "ip": peer,
                "port": int(m.group("pport")),
                "send_q": int(m.group("sendq")),
                "bytes_sent": bytes_sent,
                "bytes_acked": bytes_acked,
            }
        )
    return rows


def speed_tracker():
    prev = {}
    while True:
        now = time.time()
        cur = parse_ss()
        active = []
        seen = set()
        for r in cur:
            key = (r["ip"], r["port"])
            seen.add(key)
            b = r.get("bytes_acked") or r.get("bytes_sent")
            rate = None
            if b is not None and key in prev:
                pts, pb = prev[key]
                dt = now - pts
                if dt > 0 and b >= pb:
                    rate = (b - pb) / dt
            if b is not None:
                prev[key] = (now, b)
            active.append(
                {
                    "ip": r["ip"],
                    "port": r["port"],
                    "send_q": r["send_q"],
                    "bytes": b,
                    "rate": rate,
                }
            )
        for k in list(prev.keys()):
            if k not in seen:
                del prev[k]
        with lock:
            state["active"] = active
        time.sleep(POLL_SS_SEC)


def ingest_line(line: str):
    line = line.strip()
    if not line:
        return
    m = LOG_RE.match(line)
    if not m:
        return
    d = m.groupdict()
    try:
        nbytes = int(d["bytes"]) if d["bytes"] != "-" else 0
    except ValueError:
        nbytes = 0
    rt = None
    if d.get("rt"):
        try:
            rt = float(d["rt"])
        except ValueError:
            rt = None
    rate = None
    if rt and rt > 0 and nbytes > 0:
        rate = nbytes / rt

    rec = {
        "ts": time.time(),
        "time": d["time"],
        "ip": d["ip"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "bytes": nbytes,
        "ua": d["ua"],
        "rt": rt,
        "rate": rate,
    }
    with lock:
        state["recent"].appendleft(rec)
        state["totals"]["bytes"] += nbytes
        state["totals"]["reqs"] += 1
        state["events_1m"].append((rec["ts"], rec["ip"], nbytes))


def prune_1m():
    cutoff = time.time() - 60
    with lock:
        while state["events_1m"] and state["events_1m"][0][0] < cutoff:
            state["events_1m"].popleft()
        by = {}
        for ts, ip, b in state["events_1m"]:
            by[ip] = by.get(ip, 0) + b
        state["by_ip_bytes_1m"] = by


def log_tailer():
    path = ACCESS_LOG
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - 65536)
            f.seek(start)
            if start:
                f.readline()
            for line in f:
                ingest_line(line)
            state["log_offset"] = f.tell()
    except FileNotFoundError:
        pass

    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                end = f.tell()
                off = state["log_offset"]
                if end < off:
                    off = 0
                f.seek(off)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    ingest_line(line)
                state["log_offset"] = f.tell()
        except FileNotFoundError:
            pass
        prune_1m()
        time.sleep(0.5)


def snapshot() -> dict:
    prune_1m()
    with lock:
        active = list(state["active"])
        recent = list(state["recent"])[:80]
        totals = dict(state["totals"])
        by_ip = dict(state["by_ip_bytes_1m"])
        ev = list(state["events_1m"])
    bytes_1m = sum(b for _, _, b in ev)
    active_ips = sorted({a["ip"] for a in active})
    return {
        "now": time.time(),
        "uptime_sec": int(time.time() - state["started"]),
        "nginx_port": NGINX_PORT,
        "active": active,
        "active_count": len(active),
        "active_ips": active_ips,
        "recent": recent,
        "totals": totals,
        "bytes_1m": bytes_1m,
        "rate_1m": bytes_1m / 60.0,
        "by_ip_1m": [
            {"ip": ip, "bytes": b, "rate": b / 60.0}
            for ip, b in sorted(by_ip.items(), key=lambda x: -x[1])
        ],
    }


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Flappy CDN · live</title>
<style>
  :root {
    --bg:#0e1116; --panel:#171b22; --border:#2a3140;
    --text:#e7ecf3; --mute:#8b95a8; --ok:#3dd68c; --acc:#6ea8fe;
  }
  * { box-sizing: border-box; }
  body {
    margin:0; font:14px/1.45 system-ui,Segoe UI,sans-serif;
    background:var(--bg); color:var(--text);
  }
  header {
    padding:14px 18px; border-bottom:1px solid var(--border);
    display:flex; flex-wrap:wrap; gap:12px; align-items:baseline;
    justify-content:space-between;
  }
  h1 { font-size:16px; margin:0; font-weight:650; letter-spacing:.02em; }
  .mute { color:var(--mute); }
  .ok { color:var(--ok); }
  .err { color:#ff6b6b; }
  .grid {
    display:grid; gap:12px; padding:14px;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  }
  .card {
    background:var(--panel); border:1px solid var(--border);
    border-radius:10px; padding:12px 14px;
  }
  .card .v { font-size:22px; font-weight:650; margin-top:4px; }
  .card .l { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--mute); }
  main { padding:0 14px 24px; display:grid; gap:14px; grid-template-columns: 1fr; }
  @media (min-width: 960px) { main { grid-template-columns: 1fr 1.2fr; } }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
  th { color:var(--mute); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
  tr:hover td { background:rgba(255,255,255,.02); }
  .mono { font-family: ui-monospace, Consolas, monospace; font-size:12px; }
  .pill {
    display:inline-block; padding:2px 8px; border-radius:999px;
    background:#243044; color:var(--acc); font-size:12px;
  }
</style>
</head>
<body>
<header>
  <div>
    <h1>Flappy CDN · live</h1>
    <div class="mute">nginx :<span id="nport">—</span> · LAN-only · refresh 1s</div>
  </div>
  <div class="mute">uptime <span id="up">—</span> · <span id="clk" class="ok">…</span></div>
</header>
<div class="grid">
  <div class="card"><div class="l">Active streams</div><div class="v" id="ac">—</div></div>
  <div class="card"><div class="l">Active clients</div><div class="v" id="ai">—</div></div>
  <div class="card"><div class="l">Throughput (1 min)</div><div class="v" id="r1">—</div></div>
  <div class="card"><div class="l">Volume (1 min)</div><div class="v" id="b1">—</div></div>
  <div class="card"><div class="l">Completed (session)</div><div class="v" id="tr">—</div></div>
</div>
<main>
  <section class="card">
    <div class="l" style="margin-bottom:8px">Live connections</div>
    <table>
      <thead><tr><th>Client</th><th>Port</th><th>Speed</th><th>Bytes (TCP)</th><th>SendQ</th></tr></thead>
      <tbody id="act"></tbody>
    </table>
    <p class="mute" style="margin:10px 0 0">Live speed from TCP counters. File name appears when the request finishes (access log).</p>
  </section>
  <section class="card">
    <div class="l" style="margin-bottom:8px">Clients last 60s (completed)</div>
    <table>
      <thead><tr><th>IP</th><th>Volume</th><th>Avg</th></tr></thead>
      <tbody id="ips"></tbody>
    </table>
  </section>
  <section class="card" style="grid-column:1/-1">
    <div class="l" style="margin-bottom:8px">Recent completed requests</div>
    <table>
      <thead><tr><th>When</th><th>Client</th><th>St</th><th>File</th><th>Size</th><th>Speed</th><th>UA</th></tr></thead>
      <tbody id="rec"></tbody>
    </table>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
function hb(n){
  if(n==null||isNaN(n)) return '—';
  const u=['B','KB','MB','GB','TB']; let i=0, x=+n;
  while(x>=1024 && i<u.length-1){ x/=1024; i++; }
  return (i? x.toFixed(1):Math.round(x))+' '+u[i];
}
function hr(n){ return (n==null||n<0)?'—':hb(n)+'/s'; }
function esc(s){ return String(s??'').replace(/[&<>"']/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }
async function tick(){
  try{
    const r = await fetch('/api/live', {cache:'no-store'});
    if(!r.ok) throw new Error(r.status);
    const d = await r.json();
    $('clk').textContent = 'live';
    $('clk').className = 'ok';
    $('nport').textContent = d.nginx_port;
    $('up').textContent = Math.floor(d.uptime_sec/60)+'m';
    $('ac').textContent = d.active_count;
    $('ai').textContent = (d.active_ips||[]).length;
    $('r1').textContent = hr(d.rate_1m);
    $('b1').textContent = hb(d.bytes_1m);
    $('tr').textContent = d.totals.reqs + ' · ' + hb(d.totals.bytes);

    const act = (d.active||[]);
    $('act').innerHTML = act.length ? act.map(a => `<tr>
      <td class="mono">${esc(a.ip)}</td>
      <td class="mono">${esc(a.port)}</td>
      <td>${esc(hr(a.rate))}</td>
      <td>${esc(hb(a.bytes))}</td>
      <td class="mono">${esc(a.send_q)}</td>
    </tr>`).join('') : '<tr><td colspan="5" class="mute">No active downloads</td></tr>';

    const ips = d.by_ip_1m||[];
    $('ips').innerHTML = ips.length ? ips.map(x => `<tr>
      <td class="mono">${esc(x.ip)}</td><td>${esc(hb(x.bytes))}</td><td>${esc(hr(x.rate))}</td>
    </tr>`).join('') : '<tr><td colspan="3" class="mute">—</td></tr>';

    const rec = d.recent||[];
    $('rec').innerHTML = rec.length ? rec.map(x => {
      const path = (x.path||'').length>70 ? '…'+(x.path||'').slice(-69) : (x.path||'');
      const ua = (x.ua||'').includes('Flappy') ? '<span class="pill">launcher</span>' : esc((x.ua||'').slice(0,40));
      return `<tr>
        <td class="mute mono">${esc(x.time)}</td>
        <td class="mono">${esc(x.ip)}</td>
        <td>${esc(x.status)}</td>
        <td class="mono" title="${esc(x.path)}">${esc(path)}</td>
        <td>${esc(hb(x.bytes))}</td>
        <td>${esc(hr(x.rate))}</td>
        <td>${ua}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="7" class="mute">Waiting for log lines…</td></tr>';
  }catch(e){
    $('clk').textContent = 'error';
    $('clk').className = 'err';
  }
}
tick();
setInterval(tick, 1000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "FlappyCdnDash/1.0"

    def log_message(self, fmt, *args):
        return

    def _peer(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _deny(self):
        body = b"Forbidden: dashboard is LAN-only\n"
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not client_allowed(self._peer()):
            self._deny()
            return
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._ok(PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/live":
            data = json.dumps(snapshot(), separators=(",", ":")).encode("utf-8")
            self._ok(data, "application/json; charset=utf-8")
            return
        if path == "/health":
            self._ok(b"ok\n", "text/plain; charset=utf-8")
            return
        self.send_error(404)


def main():
    threading.Thread(target=log_tailer, name="log-tail", daemon=True).start()
    threading.Thread(target=speed_tracker, name="ss-poll", daemon=True).start()
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(
        f"cdn-dashboard on http://{LISTEN_HOST}:{LISTEN_PORT}/  log={ACCESS_LOG}",
        flush=True,
    )
    httpd.serve_forever()


if __name__ == "__main__":
    main()
