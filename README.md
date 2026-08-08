# Flappy CDN live dashboard

Lightweight **LAN-only** dashboard for watching launcher package downloads against a static **nginx CDN** (the host that serves `index.json` + `packages/*.7z`).

Shows:

- **Live TCP streams** (who is connected to the CDN port right now, approximate speed)
- **Completed requests** from the nginx access log (file, size, status, speed if `$request_time` is logged)
- **Per-IP volume** over the last 60 seconds

No Node, no Docker required on the CDN box. Pure **Python 3 stdlib** + `ss` (iproute2) + **systemd**.

Built for the [Flappy Launcher](https://github.com/PinyaGit/flappy-launcher) CDN layout, but works with any nginx static file host.

## Architecture

```
Players  →  NPM / reverse proxy (TLS)  →  CDN nginx :8080
                                           │
                                           ├─ access.log  ──►  dashboard (tail)
                                           └─ TCP :8080   ──►  dashboard (ss)
                                                      │
                                                      ▼
                                            UI http://CDN:8090/  (LAN only)
```

If TLS terminates on **Nginx Proxy Manager**, every client may appear as the proxy IP unless you:

1. Send `X-Forwarded-For` / `X-Real-IP` from NPM  
2. Enable `real_ip` on the CDN nginx (`install.sh --with-nginx --proxy-ip …`)

## Quick install (on the CDN container)

```bash
# clone or copy this repo onto the CDN host, then:
sudo ./install.sh \
  --with-nginx \
  --proxy-ip 192.168.1.226 \
  --access-log /var/log/nginx/cdn.flappy.su.access.log \
  --nginx-port 8080 \
  --port 8090
```

Open from your LAN PC:

```text
http://192.168.1.112:8090/
```

(Use your CDN host IP.)

### One-liner from GitHub (after you push)

```bash
git clone https://github.com/PinyaGit/flappy-cdn-dashboard.git
cd flappy-cdn-dashboard
sudo ./install.sh --with-nginx --proxy-ip 192.168.1.226
```

## Options

| Flag | Meaning |
|------|---------|
| `--access-log PATH` | nginx access log to tail |
| `--nginx-port N` | CDN listen port (live `ss` filter) |
| `--port N` | dashboard UI port (default `8090`) |
| `--allow PREFIXES` | who may open UI (default `192.168.,10.,127.0.0.1,::1`) |
| `--proxy-ip IP` | NPM/proxy for `set_real_ip_from` |
| `--with-nginx` | inject `log_format cdn_timed`, wire `access_log … cdn_timed`, optional real_ip |
| `--uninstall` | remove unit + `/opt/cdn-dashboard` |

Config after install: `/etc/default/cdn-dashboard`  
Binary/script: `/opt/cdn-dashboard/server.py`  
Unit: `cdn-dashboard.service`

```bash
systemctl status cdn-dashboard
journalctl -u cdn-dashboard -f
curl -s http://127.0.0.1:8090/api/live
```

## NPM tips (large .7z)

On the Proxy Host for `cdn.flappy.su`:

- **Disable Response Buffering** → ON  
- **Disable Request Buffering** → ON  
- Custom config: long `proxy_read_timeout` / `proxy_send_timeout`, pass `X-Forwarded-For`

## Security

- Dashboard returns **403** to clients outside `CDN_DASH_ALLOW` prefixes (LAN by default).
- Does **not** need to be on the public internet.
- Runs as **root** so it can read `/var/log/nginx/*` and run `ss` (typical on a dedicated CDN LXC).

## Uninstall

```bash
sudo ./install.sh --uninstall
```

## License

MIT — see [LICENSE](LICENSE).
