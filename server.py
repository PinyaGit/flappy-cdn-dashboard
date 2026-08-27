#!/usr/bin/env python3
"""Flappy CDN live dashboard — LAN only. No third-party deps."""
from __future__ import annotations

import gzip
import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from glob import glob
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN_HOST = os.environ.get("CDN_DASH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CDN_DASH_PORT", "8090"))
ACCESS_LOG = os.environ.get(
    "CDN_ACCESS_LOG", "/var/log/nginx/cdn.flappy.su.access.log"
)
NGINX_PORT = os.environ.get("CDN_NGINX_PORT", "8080")
WWW_ROOT = os.environ.get("CDN_WWW_ROOT", "/var/www/cdn.flappy.su")
STATE_PATH = os.environ.get(
    "CDN_STATE_PATH", "/var/lib/cdn-dashboard/lifetime.json"
)
LAUNCHER_PUBLIC_URL = os.environ.get(
    "CDN_LAUNCHER_URL", "https://cdn.flappy.su/launcher/Flappy-Launcher.zip"
)
ALLOW_PREFIXES = tuple(
    p.strip()
    for p in os.environ.get(
        "CDN_DASH_ALLOW", "192.168.,10.,127.0.0.1,::1"
    ).split(",")
    if p.strip()
)
RECENT_MAX = 200
POLL_SS_SEC = 1.0
SAVE_EVERY_SEC = 20.0

# Combined + optional trailing request_time (after UA); extra xff=… is ignored
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?P<proto> [^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\d+|-) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
    r'(?: (?P<rt>[\d.]+))?'
)

PROJECTS = ("redovah", "flappy", "launcher", "other")

lock = threading.Lock()
state = {
    "started": time.time(),
    "active": [],
    "recent": deque(maxlen=RECENT_MAX),
    "log_offset": 0,
    "log_ino": None,
    "totals": {"bytes": 0, "reqs": 0},
    "lifetime": {p: {"bytes": 0, "reqs": 0} for p in PROJECTS},
    "seen_files": {},  # path -> {ino, size}
    "by_ip_bytes_1m": {},
    "events_1m": deque(),
    "versions": {},
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


def classify_path(path: str) -> str:
    """Map request URI to a traffic bucket."""
    p = (path or "").split("?", 1)[0].replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    low = p.lower()
    if low.startswith("/flappy/") or low == "/flappy":
        return "flappy"
    if low.startswith("/launcher/") or low == "/launcher":
        return "launcher"
    if low.startswith("/re-dovah/") or low == "/re-dovah":
        return "redovah"
    if (
        low.startswith("/packages/")
        or low in ("/index.json", "/version.txt", "/favicon.ico")
        or low.startswith("/favicon")
    ):
        return "redovah"
    return "other"


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


def ingest_line(line: str, live: bool = True):
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

    proj = classify_path(d["path"])
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
        "project": proj,
    }
    with lock:
        bucket = state["lifetime"].setdefault(proj, {"bytes": 0, "reqs": 0})
        bucket["bytes"] += nbytes
        bucket["reqs"] += 1
        if live:
            state["totals"]["bytes"] += nbytes
            state["totals"]["reqs"] += 1
            state["recent"].appendleft(rec)
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


def _stat_sig(path: str) -> dict | None:
    try:
        st = os.stat(path)
        return {"ino": st.st_ino, "size": st.st_size, "mtime": int(st.st_mtime)}
    except OSError:
        return None


def _open_log(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def list_log_files() -> list[str]:
    files = []
    if os.path.isfile(ACCESS_LOG):
        files.append(ACCESS_LOG)
    rot1 = ACCESS_LOG + ".1"
    if os.path.isfile(rot1):
        files.append(rot1)
    files.extend(sorted(glob(ACCESS_LOG + ".*.gz")))
    # unique, historical first then current last
    seen = set()
    out = []
    for p in files:
        rp = os.path.realpath(p)
        if rp in seen:
            continue
        seen.add(rp)
        out.append(p)
    out.sort(key=lambda p: (0 if p.endswith(".gz") else 1 if p.endswith(".1") else 2, p))
    return out


def load_persist():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    life = data.get("lifetime") or {}
    with lock:
        for p in PROJECTS:
            b = life.get(p) or {}
            state["lifetime"][p] = {
                "bytes": int(b.get("bytes") or 0),
                "reqs": int(b.get("reqs") or 0),
            }
        state["seen_files"] = data.get("seen_files") or {}


def save_persist():
    try:
        os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
        with lock:
            payload = {
                "saved": time.time(),
                "lifetime": {p: dict(state["lifetime"][p]) for p in PROJECTS},
                "seen_files": dict(state["seen_files"]),
            }
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=0)
        os.replace(tmp, STATE_PATH)
    except OSError:
        pass


def process_log_file(path: str, from_offset: int = 0) -> int:
    """Ingest new bytes of a log file. Returns new offset (file size)."""
    try:
        if path.endswith(".gz"):
            with _open_log(path) as f:
                if from_offset:
                    # gzip: re-process whole file if already done
                    return from_offset
                for line in f:
                    ingest_line(line, live=False)
            sig = _stat_sig(path)
            return sig["size"] if sig else 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(from_offset)
            if from_offset > 0:
                f.readline()
            for line in f:
                ingest_line(line, live=False)
            return f.tell()
    except OSError:
        return from_offset


def catch_up_lifetime():
    """Scan rotated + current logs for bytes not yet in persist."""
    load_persist()
    files = list_log_files()
    for path in files:
        sig = _stat_sig(path)
        if not sig:
            continue
        key = path
        prev = state["seen_files"].get(key) or {}
        same_ino = prev.get("ino") == sig["ino"]
        if path.endswith(".gz") and same_ino and prev.get("size") == sig["size"]:
            continue
        offset = int(prev.get("size") or 0) if same_ino and not path.endswith(".gz") else 0
        if offset > sig["size"]:
            offset = 0
        new_off = process_log_file(path, offset)
        with lock:
            state["seen_files"][key] = {
                "ino": sig["ino"],
                "size": new_off if not path.endswith(".gz") else sig["size"],
                "mtime": sig["mtime"],
            }
        if path == ACCESS_LOG or os.path.realpath(path) == os.path.realpath(ACCESS_LOG):
            with lock:
                state["log_offset"] = new_off
                state["log_ino"] = sig["ino"]
    save_persist()


def seed_recent():
    path = ACCESS_LOG
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - 65536)
            f.seek(start)
            if start:
                f.readline()
            lines = f.readlines()
    except OSError:
        return
    # replay into recent only (lifetime already counted)
    tmp = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = LOG_RE.match(line)
        if not m:
            continue
        d = m.groupdict()
        try:
            nbytes = int(d["bytes"]) if d["bytes"] != "-" else 0
        except ValueError:
            nbytes = 0
        tmp.append(
            {
                "ts": time.time(),
                "time": d["time"],
                "ip": d["ip"],
                "method": d["method"],
                "path": d["path"],
                "status": int(d["status"]),
                "bytes": nbytes,
                "ua": d["ua"],
                "project": classify_path(d["path"]),
            }
        )
    with lock:
        state["recent"].clear()
        for rec in reversed(tmp[-RECENT_MAX:]):
            state["recent"].appendleft(rec)


def log_tailer():
    catch_up_lifetime()
    seed_recent()
    last_save = time.time()
    while True:
        try:
            sig = _stat_sig(ACCESS_LOG)
            with open(ACCESS_LOG, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                end = f.tell()
                off = state["log_offset"]
                ino = state.get("log_ino")
                if sig and ino is not None and sig["ino"] != ino:
                    off = 0
                    with lock:
                        state["log_ino"] = sig["ino"]
                if end < off:
                    off = 0
                f.seek(off)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    ingest_line(line, live=True)
                with lock:
                    state["log_offset"] = f.tell()
                    if sig:
                        state["seen_files"][ACCESS_LOG] = {
                            "ino": sig["ino"],
                            "size": f.tell(),
                            "mtime": sig["mtime"],
                        }
        except FileNotFoundError:
            pass
        prune_1m()
        now = time.time()
        if now - last_save >= SAVE_EVERY_SEC:
            save_persist()
            last_save = now
            refresh_versions()
        time.sleep(0.5)


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            t = f.read().strip()
            return t.splitlines()[0].strip() if t else None
    except OSError:
        return None


def refresh_versions():
    launcher = _read_json(os.path.join(WWW_ROOT, "launcher", "version.json")) or {}
    zip_path = os.path.join(WWW_ROOT, "launcher", "Flappy-Launcher.zip")
    zip_size = None
    try:
        zip_size = os.path.getsize(zip_path)
    except OSError:
        zip_size = launcher.get("size")

    rd = _read_json(os.path.join(WWW_ROOT, "index.json")) or {}
    rd_ver = rd.get("version") or _read_text(os.path.join(WWW_ROOT, "version.txt"))

    fl = _read_json(os.path.join(WWW_ROOT, "flappy", "index.json"))
    fl_txt = _read_text(os.path.join(WWW_ROOT, "flappy", "version.txt"))
    if fl:
        fl_ver = fl.get("version")
        fl_status = "published"
        fl_units = fl.get("unitCount")
        fl_created = fl.get("created")
    elif fl_txt:
        fl_ver = fl_txt
        fl_status = "published"
        fl_units = None
        fl_created = None
    else:
        fl_ver = None
        fl_status = "not on CDN yet"
        fl_units = None
        fl_created = None

    versions = {
        "launcher": {
            "version": launcher.get("version"),
            "file": "Flappy-Launcher.zip",
            "size": zip_size,
            "notes": launcher.get("notes") or "",
            "url": LAUNCHER_PUBLIC_URL,
        },
        "redovah": {
            "version": rd_ver,
            "created": rd.get("created"),
            "units": rd.get("unitCount"),
            "status": "published" if rd_ver else "unknown",
        },
        "flappy": {
            "version": fl_ver,
            "created": fl_created,
            "units": fl_units,
            "status": fl_status,
        },
    }
    with lock:
        state["versions"] = versions


def snapshot() -> dict:
    prune_1m()
    with lock:
        active = list(state["active"])
        recent = list(state["recent"])[:80]
        totals = dict(state["totals"])
        by_ip = dict(state["by_ip_bytes_1m"])
        ev = list(state["events_1m"])
        life = {p: dict(state["lifetime"][p]) for p in PROJECTS}
        versions = dict(state["versions"])
    games_b = life["redovah"]["bytes"] + life["flappy"]["bytes"]
    games_r = life["redovah"]["reqs"] + life["flappy"]["reqs"]
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
        "lifetime": {
            "redovah": life["redovah"],
            "flappy": life["flappy"],
            "launcher": life["launcher"],
            "other": life["other"],
            "games": {"bytes": games_b, "reqs": games_r},
        },
        "versions": versions,
        "launcher_download": "/dl/launcher",
        "launcher_public_url": LAUNCHER_PUBLIC_URL,
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
    --gold:#d6ba6e; --gold2:#ece6d2;
  }
  * { box-sizing: border-box; }
  body {
    margin:0; font:14px/1.45 system-ui,Segoe UI,sans-serif;
    background:var(--bg); color:var(--text);
  }
  header {
    padding:14px 18px; border-bottom:1px solid var(--border);
    display:flex; flex-wrap:wrap; gap:12px; align-items:center;
    justify-content:space-between;
  }
  h1 { font-size:16px; margin:0; font-weight:650; letter-spacing:.02em; }
  .mute { color:var(--mute); }
  .ok { color:var(--ok); }
  .err { color:#ff6b6b; }
  .gold { color:var(--gold); }
  .btn {
    display:inline-block; background:var(--gold); color:#1a1410;
    font-weight:700; padding:8px 14px; border-radius:8px;
    text-decoration:none; font-size:13px; border:0; cursor:pointer;
  }
  .btn:hover { filter:brightness(1.08); }
  .grid {
    display:grid; gap:12px; padding:14px;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  }
  .card {
    background:var(--panel); border:1px solid var(--border);
    border-radius:10px; padding:12px 14px;
  }
  .card .v { font-size:22px; font-weight:650; margin-top:4px; }
  .card .s { font-size:12px; color:var(--mute); margin-top:4px; }
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
  .pill.gold { background:#3a3220; color:var(--gold); }
  .vergrid { display:grid; gap:10px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
</style>
</head>
<body>
<header>
  <div>
    <h1>Flappy CDN · live</h1>
    <div class="mute">nginx :<span id="nport">—</span> · LAN-only · refresh 1s</div>
  </div>
  <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
    <a class="btn" id="dl" href="/dl/launcher">Download launcher</a>
    <div class="mute">uptime <span id="up">—</span> · <span id="clk" class="ok">…</span></div>
  </div>
</header>
<div class="grid">
  <div class="card"><div class="l">Active streams</div><div class="v" id="ac">—</div></div>
  <div class="card"><div class="l">Active clients</div><div class="v" id="ai">—</div></div>
  <div class="card"><div class="l">Throughput (1 min)</div><div class="v" id="r1">—</div></div>
  <div class="card"><div class="l">Volume (1 min)</div><div class="v" id="b1">—</div></div>
  <div class="card"><div class="l">Completed (session)</div><div class="v" id="tr">—</div></div>
</div>
<div class="grid">
  <div class="card">
    <div class="l">Flappy Re-Dovah · all time</div>
    <div class="v gold" id="rdB">—</div>
    <div class="s" id="rdR">—</div>
  </div>
  <div class="card">
    <div class="l">Flappy 4.0.0 · all time</div>
    <div class="v gold" id="flB">—</div>
    <div class="s" id="flR">—</div>
  </div>
  <div class="card">
    <div class="l">Both games · all time</div>
    <div class="v gold" id="gB">—</div>
    <div class="s" id="gR">—</div>
  </div>
  <div class="card">
    <div class="l">Launcher zip · all time</div>
    <div class="v" id="lnB">—</div>
    <div class="s" id="lnR">—</div>
  </div>
</div>
<div class="grid" style="padding-top:0">
  <div class="card" style="grid-column:1/-1">
    <div class="l" style="margin-bottom:10px">Current versions on CDN</div>
    <div class="vergrid">
      <div>
        <div class="mute">Launcher</div>
        <div class="v" id="vLn">—</div>
        <div class="s" id="vLnS">—</div>
      </div>
      <div>
        <div class="mute">Flappy Re-Dovah</div>
        <div class="v" id="vRd">—</div>
        <div class="s" id="vRdS">—</div>
      </div>
      <div>
        <div class="mute">Flappy 4.0.0</div>
        <div class="v" id="vFl">—</div>
        <div class="s" id="vFlS">—</div>
      </div>
    </div>
  </div>
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
function reqs(n){ return (n||0).toLocaleString()+' req'; }
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

    const L = d.lifetime||{};
    const rd = L.redovah||{};
    const fl = L.flappy||{};
    const gm = L.games||{};
    const ln = L.launcher||{};
    $('rdB').textContent = hb(rd.bytes);
    $('rdR').textContent = reqs(rd.reqs);
    $('flB').textContent = hb(fl.bytes);
    $('flR').textContent = (fl.bytes||fl.reqs) ? reqs(fl.reqs) : 'not on CDN yet';
    $('gB').textContent = hb(gm.bytes);
    $('gR').textContent = reqs(gm.reqs);
    $('lnB').textContent = hb(ln.bytes);
    $('lnR').textContent = reqs(ln.reqs);

    const V = d.versions||{};
    const vLn = V.launcher||{};
    const vRd = V.redovah||{};
    const vFl = V.flappy||{};
    $('vLn').textContent = vLn.version || '—';
    $('vLnS').textContent = vLn.size ? (vLn.file||'zip')+' · '+hb(vLn.size) : (vLn.notes||'');
    $('vRd').textContent = vRd.version || '—';
    $('vRdS').textContent = vRd.units ? vRd.units+' packages'+(vRd.created?' · '+vRd.created:'') : (vRd.status||'');
    $('vFl').textContent = vFl.version || '—';
    $('vFlS').textContent = vFl.status==='published'
      ? ((vFl.units? vFl.units+' packages':'published')+(vFl.created?' · '+vFl.created:''))
      : (vFl.status||'not on CDN yet');
    if(d.launcher_download) $('dl').href = d.launcher_download;

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
      const tag = x.project==='flappy' ? ' <span class="pill gold">flappy</span>'
                : x.project==='redovah' ? ' <span class="pill">re-dovah</span>'
                : x.project==='launcher' ? ' <span class="pill gold">exe</span>' : '';
      return `<tr>
        <td class="mute mono">${esc(x.time)}</td>
        <td class="mono">${esc(x.ip)}</td>
        <td>${esc(x.status)}</td>
        <td class="mono" title="${esc(x.path)}">${esc(path)}${tag}</td>
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
    server_version = "FlappyCdnDash/1.1"

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

    def _send_launcher_zip(self):
        path = os.path.join(WWW_ROOT, "launcher", "Flappy-Launcher.zip")
        if not os.path.isfile(path):
            self.send_error(404, "launcher zip not on this host")
            return
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header(
            "Content-Disposition", 'attachment; filename="Flappy-Launcher.zip"'
        )
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 256)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def do_HEAD(self):
        if not client_allowed(self._peer()):
            self._deny()
            return
        path = urlparse(self.path).path
        if path == "/dl/launcher":
            zpath = os.path.join(WWW_ROOT, "launcher", "Flappy-Launcher.zip")
            if not os.path.isfile(zpath):
                self.send_error(404, "launcher zip not on this host")
                return
            size = os.path.getsize(zpath)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header(
                "Content-Disposition", 'attachment; filename="Flappy-Launcher.zip"'
            )
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if path in ("/", "/index.html", "/api/live", "/health"):
            self.send_response(200)
            self.end_headers()
            return
        self.send_error(404)

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
        if path == "/dl/launcher":
            self._send_launcher_zip()
            return
        if path == "/health":
            self._ok(b"ok\n", "text/plain; charset=utf-8")
            return
        self.send_error(404)


def main():
    os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
    refresh_versions()
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
