"""
INCC — Imperial Network Command Centre
Public-facing content site + live intrusion-notification console.

Beyond serving the dashboard pages, this app runs its own honeypot: any request
that looks like a vulnerability scan or SQL-injection probe is silently logged
with the source IP and a best-effort geolocation, then served a stock 404. The
Announcements page renders these captures as live "ALERT LEVEL RED" notifications
and also merges the security feed from the Imperial Terminal (ts26) when
configured, so one console shows intrusions across both surfaces.
"""

import os
import re
import json
import time
import threading
import urllib.request
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, abort

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENT_LOG = os.path.join(BASE_DIR, 'incc_events.jsonl')

# Pull the Imperial Terminal's honeypot feed into this console. Defaults to the
# deployed terminal at ts26.onrender.com; override with SECURITY_FEED_URL to point
# elsewhere (e.g. http://127.0.0.1:10001/api/security/events for local dev), or set
# it empty to disable upstream merging.
UPSTREAM_FEED_URL   = os.environ.get('SECURITY_FEED_URL', 'https://ts26.onrender.com/api/security/events')
UPSTREAM_FEED_TOKEN = os.environ.get('SECURITY_FEED_TOKEN', 'incc-sigma-feed-2026')

_LOG_LOCK = threading.Lock()

# Short-lived cache for the upstream feed so rapid client polling (~5s) neither
# hammers the remote terminal nor blocks on its latency.
_UPSTREAM_CACHE = {'at': 0.0, 'data': []}
_UPSTREAM_TTL = 8.0          # seconds
_UPSTREAM_LOCK = threading.Lock()


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK / SCANNER DETECTION
# ──────────────────────────────────────────────────────────────────────────────

_SQLI_PATTERNS = [
    r"'\s*or\s*'?\d+'?\s*=\s*'?\d+", r'\bunion\b\s+(all\s+)?\bselect\b',
    r'--\s', r'/\*.*?\*/', r';\s*(drop|delete|update|insert|alter|truncate)\b',
    r'\bxp_cmdshell\b', r'\binformation_schema\b', r'\bsleep\s*\(', r'\bbenchmark\s*\(',
    r'\bor\b\s+\d+\s*=\s*\d+', r"admin'\s*--",
]
# Paths favoured by automated vulnerability scanners — pure bait.
_SCANNER_PATHS = [
    r'\.env', r'\.git', r'\.aws', r'\.ssh', r'wp-login', r'wp-admin', r'xmlrpc',
    r'phpmyadmin', r'/administrator', r'/admin', r'/config', r'/shell', r'/\.well-known/(?!acme)',
    r'/vendor/', r'/actuator', r'/console', r'/solr', r'/boaform', r'/cgi-bin', r'/backup',
    r'/id_rsa', r'/credentials', r'/owa/', r'/manager/html', r'\.php$', r'\.asp[x]?$',
]
_XSS_PATTERNS = [r'<script', r'javascript:', r'onerror\s*=', r'onload\s*=']

_SIG_RE = re.compile(
    '|'.join(f'(?:{p})' for p in (_SQLI_PATTERNS + _SCANNER_PATHS + _XSS_PATTERNS)),
    re.IGNORECASE | re.DOTALL,
)


def _classify(path_and_query: str):
    """Return a threat category if the target smells hostile, else None."""
    if re.search('|'.join(_SQLI_PATTERNS), path_and_query, re.IGNORECASE | re.DOTALL):
        return 'SQLI_PROBE'
    if re.search('|'.join(_XSS_PATTERNS), path_and_query, re.IGNORECASE):
        return 'XSS_PROBE'
    if re.search('|'.join(_SCANNER_PATHS), path_and_query, re.IGNORECASE):
        return 'SCANNER'
    return None


# ──────────────────────────────────────────────────────────────────────────────
# GEOLOCATION (best-effort, never blocks the request)
# ──────────────────────────────────────────────────────────────────────────────

_GEO_CACHE = {}
_GEO_LOCK = threading.Lock()


def _is_private_ip(ip: str) -> bool:
    return (
        ip in ('127.0.0.1', '::1', '0.0.0.0', 'localhost')
        or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('169.254.')
        or any(ip.startswith(f'172.{n}.') for n in range(16, 32))
        or ip.startswith('fc') or ip.startswith('fd')
    )


def _lookup_geo(ip: str) -> str:
    if _is_private_ip(ip):
        return 'LOCAL NETWORK'
    with _GEO_LOCK:
        if ip in _GEO_CACHE:
            return _GEO_CACHE[ip]
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city'
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        loc = (', '.join(p for p in (data.get('city'), data.get('regionName'),
                                     data.get('country')) if p)
               if data.get('status') == 'success' else 'UNKNOWN') or 'UNKNOWN'
    except Exception:
        loc = 'UNKNOWN'
    with _GEO_LOCK:
        _GEO_CACHE[ip] = loc
    return loc


# ──────────────────────────────────────────────────────────────────────────────
# EVENT PERSISTENCE (append-only JSON lines)
# ──────────────────────────────────────────────────────────────────────────────

def _client_ip() -> str:
    # Trust X-Forwarded-For only if explicitly deployed behind a proxy.
    if os.environ.get('TRUSTED_PROXY') == '1':
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def _append_event(event: dict):
    with _LOG_LOCK:
        with open(EVENT_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + '\n')


def _record_capture(category: str):
    ip = _client_ip()
    full_target = request.full_path.rstrip('?') if request.query_string else request.path
    event = {
        'time':       datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'ip':         ip,
        'category':   category,
        'path':       request.path[:255],
        'target':     full_target[:255],
        'method':     request.method,
        'user_agent': (request.headers.get('User-Agent', '') or '')[:400],
        'location':   'LOCAL NETWORK' if _is_private_ip(ip) else 'PENDING',
        'source':     'INCC',
    }
    _append_event(event)

    if not _is_private_ip(ip):
        def _backfill():
            loc = _lookup_geo(ip)
            # Rewrite the location in place by rebuilding the file (small volumes).
            try:
                with _LOG_LOCK:
                    if not os.path.exists(EVENT_LOG):
                        return
                    lines = open(EVENT_LOG, encoding='utf-8').read().splitlines()
                    out = []
                    for ln in lines:
                        try:
                            e = json.loads(ln)
                        except Exception:
                            out.append(ln); continue
                        if (e.get('ip') == ip and e.get('location') == 'PENDING'
                                and e.get('time') == event['time']):
                            e['location'] = loc
                        out.append(json.dumps(e))
                    with open(EVENT_LOG, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(out) + '\n')
            except Exception:
                pass
        threading.Thread(target=_backfill, daemon=True).start()


def _read_local_events(limit: int = 40):
    if not os.path.exists(EVENT_LOG):
        return []
    with _LOG_LOCK:
        lines = open(EVENT_LOG, encoding='utf-8').read().splitlines()
    events = []
    for ln in reversed(lines):          # newest first
        try:
            events.append(json.loads(ln))
        except Exception:
            continue
        if len(events) >= limit:
            break
    return events


def _fetch_upstream(limit: int = 25):
    if not UPSTREAM_FEED_URL:
        return []
    # Serve from cache if fresh — keeps the alerts endpoint snappy and polite.
    now = time.monotonic()
    with _UPSTREAM_LOCK:
        if now - _UPSTREAM_CACHE['at'] < _UPSTREAM_TTL:
            return _UPSTREAM_CACHE['data']
    try:
        sep = '&' if '?' in UPSTREAM_FEED_URL else '?'
        url = f'{UPSTREAM_FEED_URL}{sep}key={UPSTREAM_FEED_TOKEN}&limit={limit}'
        req = urllib.request.Request(url, headers={'User-Agent': 'INCC-Console/1.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        out = []
        for e in data.get('events', []):
            out.append({
                'time':       e.get('time'),
                'ip':         e.get('ip'),
                'category':   e.get('category'),
                'path':       e.get('path'),
                'target':     e.get('path'),
                'method':     e.get('method'),
                'user_agent': e.get('user_agent'),
                'location':   e.get('location'),
                'source':     'TERMINAL',
            })
    except Exception:
        out = _UPSTREAM_CACHE['data']   # keep last-known-good on transient failure
    with _UPSTREAM_LOCK:
        _UPSTREAM_CACHE['at'] = now
        _UPSTREAM_CACHE['data'] = out
    return out


# ──────────────────────────────────────────────────────────────────────────────
# HONEYPOT — inspect every request before routing
# ──────────────────────────────────────────────────────────────────────────────

@app.before_request
def _honeypot_gate():
    # Ignore our own static assets and the alerts API itself.
    if request.path.startswith('/static/') or request.path.startswith('/incc/api'):
        return None
    target = request.full_path if request.query_string else request.path
    category = _classify(target)
    if category:
        _record_capture(category)
        abort(404)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# PAGE ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/announcements")
def announcements():
    return render_template("announcements.html")


@app.route("/supplies")
def supplies():
    return render_template("supplies.html")


@app.route("/sanitisation")
def sanitisation():
    return render_template("sanitisation.html")


@app.route("/vader")
def vader():
    return app.send_static_file("vr/index.html")


@app.route("/fight")
def fight():
    return app.send_static_file("vr/index.html")


@app.route("/travel")
def travel():
    return app.send_static_file("vr/galaxy.html")


# ──────────────────────────────────────────────────────────────────────────────
# NOTIFICATIONS FEED
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/incc/api/alerts")
def alerts():
    limit = min(request.args.get('limit', 30, type=int) or 30, 100)
    merged = _read_local_events(limit) + _fetch_upstream(limit)
    # newest first, de-dupe on (ip, target, time)
    seen, deduped = set(), []
    for e in sorted(merged, key=lambda x: x.get('time') or '', reverse=True):
        key = (e.get('ip'), e.get('target'), e.get('time'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    stats = {
        'total':      len(deduped),
        'unique_ips': len({e.get('ip') for e in deduped}),
        'sqli':       sum(1 for e in deduped if 'SQLI' in (e.get('category') or '')),
    }
    return jsonify({'stats': stats, 'alerts': deduped[:limit]})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)
