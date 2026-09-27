#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BURP-LIKE WEB v2.1 — JATHNIEL EDITION
Proxy d'interception HTTP/HTTPS avec interface web moderne.

Fix v2.1 : event loop asyncio correct pour mitmproxy 10+
"""

import os
import sys
import json
import time
import asyncio
import base64
import html as html_lib
import re
import sqlite3
import threading
import hashlib
import urllib.parse
import subprocess
import signal
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, Response, send_from_directory, abort
)

try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    MITM_OK = True
except ImportError:
    MITM_OK = False
    print("[!] mitmproxy non installé : pip install mitmproxy")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[!] requests non installé : pip install requests")


# ==================== CONFIG ====================

APP_DIR = Path(__file__).parent
DB_PATH = Path.home() / '.burp_like_web' / 'history.db'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

PROXY_PORT = 8080
WEB_PORT = 5000


# ==================== DÉCODAGE ====================

class Decoder:
    """Décode automatiquement les valeurs (URL, Base64, HTML, Hex, JSON, JWT)."""

    @staticmethod
    def decode_value(value):
        result = {'original': value, 'decoded': value, 'variants': []}
        if not value or not isinstance(value, str):
            return result

        try:
            url_decoded = urllib.parse.unquote(value)
            if url_decoded != value:
                result['variants'].append({'type': 'url', 'value': url_decoded})
                result['decoded'] = url_decoded
        except Exception:
            pass

        try:
            if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) % 4 == 0 and len(value) > 4:
                b64 = base64.b64decode(value).decode('utf-8', errors='ignore')
                if b64.isprintable():
                    result['variants'].append({'type': 'base64', 'value': b64})
        except Exception:
            pass

        try:
            html_dec = html_lib.unescape(value)
            if html_dec != value:
                result['variants'].append({'type': 'html', 'value': html_dec})
        except Exception:
            pass

        try:
            if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0 and len(value) >= 4:
                hex_dec = bytes.fromhex(value).decode('utf-8', errors='ignore')
                if hex_dec.isprintable():
                    result['variants'].append({'type': 'hex', 'value': hex_dec})
        except Exception:
            pass

        try:
            json_data = json.loads(value)
            result['variants'].append({
                'type': 'json',
                'value': json.dumps(json_data, indent=2, ensure_ascii=False)
            })
        except Exception:
            pass

        if value.count('.') == 2:
            try:
                parts = value.split('.')
                pad = lambda s: s + '=' * (-len(s) % 4)
                h = base64.urlsafe_b64decode(pad(parts[0])).decode('utf-8', errors='ignore')
                p = base64.urlsafe_b64decode(pad(parts[1])).decode('utf-8', errors='ignore')
                try:
                    h_pretty = json.dumps(json.loads(h), indent=2)
                    p_pretty = json.dumps(json.loads(p), indent=2)
                except Exception:
                    h_pretty, p_pretty = h, p
                result['variants'].append({
                    'type': 'jwt',
                    'value': f"Header:\n{h_pretty}\n\nPayload:\n{p_pretty}"
                })
            except Exception:
                pass

        return result

    @staticmethod
    def decode_body(body, content_type=''):
        result = {
            'original': body, 'decoded': body, 'params': {},
            'type': 'raw', 'pretty': body,
        }
        if not body:
            return result

        try:
            json_data = json.loads(body)
            result['type'] = 'json'
            result['pretty'] = json.dumps(json_data, indent=2, ensure_ascii=False)
            result['decoded'] = result['pretty']
            if isinstance(json_data, dict):
                for k, v in json_data.items():
                    if isinstance(v, str):
                        result['params'][k] = Decoder.decode_value(v)
            elif isinstance(json_data, list):
                for i, item in enumerate(json_data[:20]):
                    if isinstance(item, str):
                        result['params'][f'[{i}]'] = Decoder.decode_value(item)
            return result
        except Exception:
            pass

        try:
            params = urllib.parse.parse_qs(body, keep_blank_values=True)
            if params:
                result['type'] = 'form'
                lines = []
                for k, vals in params.items():
                    v = vals[0] if vals else ''
                    d = Decoder.decode_value(v)
                    result['params'][k] = d
                    lines.append(f"{k} = {d['decoded']}")
                result['decoded'] = '\n'.join(lines)
                result['pretty'] = result['decoded']
                return result
        except Exception:
            pass

        decoded = Decoder.decode_value(body)
        if decoded['variants']:
            result['decoded'] = decoded['decoded']
            result['pretty'] = decoded['decoded']
            result['variants'] = decoded['variants']

        return result


# ==================== BASE DE DONNÉES ====================

class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self._init_db()
        self._lock = threading.Lock()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT, url TEXT, host TEXT, path TEXT,
            headers TEXT, body TEXT,
            status INTEGER, response_headers TEXT, response_body TEXT,
            timestamp TEXT, modified INTEGER DEFAULT 0,
            response_size INTEGER DEFAULT 0,
            content_type_req TEXT, content_type_resp TEXT,
            decoded_body TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT, type TEXT, url TEXT,
            description TEXT, evidence TEXT, timestamp TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS match_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, target TEXT, pattern TEXT,
            replacement TEXT, enabled INTEGER DEFAULT 1
        )''')
        conn.commit()
        conn.close()

    def insert(self, req):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()
            c.execute('''INSERT INTO requests
                (method, url, host, path, headers, body, status,
                 response_headers, response_body, timestamp, modified,
                 response_size, content_type_req, content_type_resp, decoded_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (req.get('method', ''), req.get('url', ''), req.get('host', ''),
                 req.get('path', ''), json.dumps(req.get('headers', {})),
                 req.get('body', ''), req.get('status', 0),
                 json.dumps(req.get('response_headers', {})),
                 req.get('response_body', ''), datetime.now().isoformat(),
                 1 if req.get('modified') else 0,
                 req.get('response_size', 0),
                 req.get('content_type_req', ''),
                 req.get('content_type_resp', ''),
                 json.dumps(req.get('decoded_body', {}))))
            conn.commit()
            req_id = c.lastrowid
            conn.close()
            return req_id

    def get_by_id(self, req_id):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row = c.fetchone()
        conn.close()
        return row

    def search(self, method='', status='', host='', search=''):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        query = '''SELECT id, method, host, path, status, response_size,
                   timestamp, content_type_resp, modified
                   FROM requests WHERE 1=1'''
        params = []
        if method:
            query += ' AND method = ?'; params.append(method)
        if status:
            query += ' AND status = ?'; params.append(status)
        if host:
            query += ' AND host LIKE ?'; params.append(f'%{host}%')
        if search:
            query += ' AND (url LIKE ? OR body LIKE ? OR response_body LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        query += ' ORDER BY id DESC LIMIT 500'
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows

    def stats(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM requests'); total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM requests WHERE method='GET'"); gets = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM requests WHERE method='POST'"); posts = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings'); findings = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM requests WHERE modified=1'); modified = c.fetchone()[0]
        conn.close()
        return {
            'total': total, 'get': gets, 'post': posts,
            'findings': findings, 'modified': modified
        }

    def insert_finding(self, finding):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()
            c.execute('''INSERT INTO findings
                (severity, type, url, description, evidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (finding.get('severity', 'info'), finding.get('type', ''),
                 finding.get('url', ''), finding.get('description', ''),
                 finding.get('evidence', '')[:500], datetime.now().isoformat()))
            conn.commit()
            conn.close()

    def get_findings(self, limit=200):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''SELECT id, severity, type, url, description, evidence, timestamp
                    FROM findings ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END, id DESC LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def clear(self):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            c = conn.cursor()
            c.execute('DELETE FROM requests')
            c.execute('DELETE FROM findings')
            conn.commit()
            conn.close()

    def export_json(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('SELECT * FROM requests ORDER BY id DESC LIMIT 1000')
        cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, row)) for row in c.fetchall()]
        conn.close()
        return rows


# ==================== SIGNAL BUS ====================

class SignalBus:
    def __init__(self):
        self.pending_requests = []
        self.lock = threading.Lock()
        self.events = {}
        self.modifications = {}
        self.live_captures = []
        self.intercept_enabled = True

    def add_pending(self, req_data, event_key):
        with self.lock:
            self.pending_requests.append({'data': req_data, 'key': event_key})
            event = threading.Event()
            self.events[event_key] = event
        return event

    def get_pending(self):
        with self.lock:
            return list(self.pending_requests)

    def apply_modification(self, event_key, modifications):
        with self.lock:
            self.modifications[event_key] = modifications
            if event_key in self.events:
                self.events[event_key].set()

    def consume_modification(self, event_key):
        with self.lock:
            mods = self.modifications.pop(event_key, {})
            if event_key in self.pending_requests:
                self.pending_requests = [
                    p for p in self.pending_requests if p['key'] != event_key
                ]
            if event_key in self.events:
                del self.events[event_key]
            return mods

    def add_live_capture(self, capture):
        with self.lock:
            self.live_captures.append(capture)
            if len(self.live_captures) > 500:
                self.live_captures = self.live_captures[-500:]

    def get_live_captures(self, limit=50):
        with self.lock:
            return list(self.live_captures[-limit:])


signal_bus = SignalBus()
db = Database()


# ==================== SCANNER PASSIF ====================

class PassiveScanner:
    SQLI_ERRORS = [
        'sql syntax', 'mysql_fetch', 'mysqli_', 'pg_query', 'ora-',
        'sqlite_', 'unclosed quotation', 'microsoft ole db',
        'odbc drivers', 'jdbc', 'postgresql',
    ]

    LFI_PATTERNS = [
        'root:x:0:0:', 'daemon:x:', 'bin:x:', '[boot loader]',
        '[extensions]', 'for 16-bit app support',
    ]

    SSRF_INDICATORS = [
        '169.254.169.254', 'metadata.google', 'localhost:',
        'file://', 'gopher://',
    ]

    SECURITY_HEADERS = {
        'Strict-Transport-Security': ('MEDIUM', 'HSTS manquant'),
        'Content-Security-Policy': ('MEDIUM', 'CSP manquant'),
        'X-Frame-Options': ('LOW', 'Clickjacking possible'),
        'X-Content-Type-Options': ('LOW', 'MIME sniffing possible'),
        'Referrer-Policy': ('LOW', 'Referrer leak possible'),
    }

    def __init__(self, db):
        self.db = db

    def analyze(self, req_data):
        url = req_data.get('url', '')
        req_body = req_data.get('body', '')
        resp_body = req_data.get('response_body', '')
        resp_headers = req_data.get('response_headers', {})

        body_low = resp_body.lower()
        for err in self.SQLI_ERRORS:
            if err.lower() in body_low:
                self._add('HIGH', 'SQL Injection (error-based)', url,
                          f"Erreur SQL visible : {err}", resp_body[:300])
                break

        for key, value in urllib.parse.parse_qs(req_body).items():
            if value and value[0] and len(value[0]) > 3 and value[0] in resp_body:
                if any(x in value[0].lower() for x in ['<script', 'onerror', 'javascript:']):
                    self._add('MEDIUM', 'XSS Reflected', url,
                              f"Payload '{value[0][:50]}' refléché", '')
                    break

        for pat in self.LFI_PATTERNS:
            if pat in resp_body:
                self._add('CRITICAL', 'LFI', url,
                          "Contenu de fichier système détecté", pat)
                break

        for ind in self.SSRF_INDICATORS:
            if ind in resp_body.lower():
                self._add('HIGH', 'SSRF', url, f"Indicateur SSRF : {ind}", '')
                break

        resp_h_lower = {k.lower(): v for k, v in resp_headers.items()}
        for header, (sev, desc) in self.SECURITY_HEADERS.items():
            if header.lower() not in resp_h_lower:
                self._add(sev, 'Missing Security Header', url, desc, '')

        set_cookie = (resp_headers.get('Set-Cookie', '') or
                      resp_headers.get('set-cookie', ''))
        if set_cookie:
            if 'Secure' not in set_cookie and url.startswith('https'):
                self._add('MEDIUM', 'Cookie without Secure', url,
                          'Cookie sans flag Secure', set_cookie[:200])
            if 'HttpOnly' not in set_cookie:
                self._add('LOW', 'Cookie without HttpOnly', url,
                          'Cookie sans flag HttpOnly', set_cookie[:200])

        if 'Index of /' in resp_body:
            self._add('MEDIUM', 'Directory Listing', url, 'Listing activé', '')

        for pat in ['Traceback (most recent call last)', 'at java.lang.',
                    'System.NullReferenceException', 'Warning: ',
                    'Fatal error:']:
            if pat in resp_body:
                self._add('MEDIUM', 'Information Disclosure', url,
                          f"Debug visible : {pat}", '')
                break

    def _add(self, severity, vtype, url, description, evidence):
        self.db.insert_finding({
            'severity': severity, 'type': vtype, 'url': url,
            'description': description, 'evidence': evidence,
        })


scanner = PassiveScanner(db)


# ==================== MITMPROXY ADDON ====================

class InterceptAddon:
    def _in_scope(self, host):
        return True

    def request(self, flow):
        try:
            host = flow.request.host
            if not self._in_scope(host):
                return

            body = flow.request.get_text() if flow.request.content else ''
            content_type = flow.request.headers.get('Content-Type', '')
            decoded_body = Decoder.decode_body(body, content_type)

            req_data = {
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'host': host,
                'path': flow.request.path,
                'headers': dict(flow.request.headers),
                'body': body,
                'content_type_req': content_type,
                'decoded_body': decoded_body,
            }

            flow.metadata['req_data'] = req_data
            flow.metadata['start_time'] = time.time()

            if signal_bus.intercept_enabled:
                event_key = f"{flow.request.pretty_url}_{id(flow)}"
                event = signal_bus.add_pending(req_data, event_key)
                event.wait(timeout=300)
                mods = signal_bus.consume_modification(event_key)

                if mods.get('drop'):
                    flow.response = http.Response.make(
                        503, b"Dropped by Burp-Like Web",
                        {"Content-Type": "text/plain"}
                    )
                    return
                if 'method' in mods:
                    flow.request.method = mods['method']
                if 'url' in mods:
                    parsed = urllib.parse.urlparse(mods['url'])
                    flow.request.scheme = parsed.scheme
                    flow.request.host = parsed.hostname
                    if parsed.port:
                        flow.request.port = parsed.port
                    flow.request.path = parsed.path or '/'
                    if parsed.query:
                        flow.request.path += '?' + parsed.query
                if 'headers' in mods:
                    flow.request.headers.clear()
                    for k, v in mods['headers'].items():
                        flow.request.headers[k] = v
                if 'body' in mods:
                    flow.request.set_text(mods['body'])
        except Exception as e:
            print(f"[ADDON] Erreur request: {e}")

    def response(self, flow):
        try:
            host = flow.request.host
            if not self._in_scope(host):
                return

            req_data = flow.metadata.get('req_data', {})
            start_time = flow.metadata.get('start_time', time.time())

            resp_body = flow.response.get_text() if flow.response.content else ''
            resp_headers = dict(flow.response.headers)
            content_type_resp = flow.response.headers.get('Content-Type', '')

            full_data = {
                **req_data,
                'status': flow.response.status_code,
                'response_headers': resp_headers,
                'response_body': resp_body,
                'response_size': len(resp_body),
                'content_type_resp': content_type_resp,
                'response_time': time.time() - start_time,
            }

            db.insert(full_data)

            try:
                scanner.analyze(full_data)
            except Exception as e:
                print(f"[SCANNER] Erreur: {e}")

            signal_bus.add_live_capture({
                'method': full_data.get('method', ''),
                'url': full_data.get('url', ''),
                'host': host,
                'status': full_data['status'],
                'size': full_data['response_size'],
                'time': round(full_data['response_time'], 3),
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'content_type': content_type_resp.split(';')[0],
            })
        except Exception as e:
            print(f"[ADDON] Erreur response: {e}")


# ==================== PROXY SERVER ====================

class ProxyServer(threading.Thread):
    """Thread qui lance mitmproxy avec son propre event loop asyncio."""

    def __init__(self, port=8080):
        super().__init__(daemon=True)
        self.port = port
        self.master = None
        self.addon = None
        self.loop = None
        self.ready = threading.Event()

    def run(self):
        if not MITM_OK:
            print("[PROXY] mitmproxy non installé")
            return

        # Créer un NOUVEL event loop asyncio pour ce thread
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            self.loop.run_until_complete(self._run_master())
        except Exception as e:
            print(f"[PROXY] Erreur: {e}")
        finally:
            try:
                self.loop.close()
            except Exception:
                pass

    async def _run_master(self):
        """Démarre DumpMaster dans l'event loop du thread."""
        opts = options.Options(
            listen_host='127.0.0.1',
            listen_port=self.port,
        )
        # DumpMaster accepte le loop en paramètre sur mitmproxy 10+
        try:
            self.master = DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False,
                loop=self.loop,
            )
        except TypeError:
            # Fallback si le paramètre loop n'existe pas
            self.master = DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False,
            )

        self.addon = InterceptAddon()
        self.master.addons.add(self.addon)
        print(f"[PROXY] Démarré sur 127.0.0.1:{self.port}")
        self.ready.set()

        await self.master.run()

    def shutdown(self):
        if self.master:
            try:
                self.master.shutdown()
            except Exception:
                pass


# ==================== FLASK APP ====================

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['JSON_SORT_KEYS'] = False


def content_kind(content_type, body):
    ct = (content_type or '').lower()
    if 'json' in ct:
        return 'json'
    if 'html' in ct:
        return 'html'
    if 'xml' in ct:
        return 'xml'
    if 'javascript' in ct:
        return 'js'
    if 'css' in ct:
        return 'css'
    if body.strip().startswith(('{', '[')):
        return 'json'
    if body.strip().startswith('<'):
        return 'xml'
    return 'text'


@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/intercept')
def intercept_page():
    return render_template('intercept.html')


@app.route('/history')
def history_page():
    return render_template('history.html')


@app.route('/intruder')
def intruder_page():
    return render_template('intruder.html')


@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')


@app.route('/repeater')
def repeater_page():
    return render_template('repeater.html')


@app.route('/decoder')
def decoder_page():
    return render_template('decoder.html')


@app.route('/api/stats')
def api_stats():
    stats = db.stats()
    stats['intercept_enabled'] = signal_bus.intercept_enabled
    stats['pending'] = len(signal_bus.get_pending())
    return jsonify(stats)


@app.route('/api/live')
def api_live():
    captures = signal_bus.get_live_captures(50)
    return jsonify(captures)


@app.route('/api/requests')
def api_requests():
    method = request.args.get('method', '')
    status = request.args.get('status', '')
    host = request.args.get('host', '')
    search = request.args.get('search', '')
    rows = db.search(method, status, host, search)
    return jsonify([
        {
            'id': r[0], 'method': r[1], 'host': r[2], 'path': r[3],
            'status': r[4], 'size': r[5], 'timestamp': r[6],
            'content_type': r[7], 'modified': r[8] == 1,
        } for r in rows
    ])


@app.route('/api/request/<int:req_id>')
def api_request_detail(req_id):
    row = db.get_by_id(req_id)
    if not row:
        return jsonify({'error': 'not found'}), 404

    try:
        headers = json.loads(row[5] or '{}')
    except Exception:
        headers = {}
    try:
        resp_headers = json.loads(row[8] or '{}')
    except Exception:
        resp_headers = {}
    try:
        decoded_body = json.loads(row[14] or '{}')
    except Exception:
        decoded_body = Decoder.decode_body(row[6] or '')

    resp_body = row[9] or ''
    decoded_resp = Decoder.decode_body(resp_body, row[13] or '')

    return jsonify({
        'id': row[0],
        'method': row[1],
        'url': row[2],
        'host': row[3],
        'path': row[4],
        'headers': headers,
        'body': row[6],
        'body_decoded': decoded_body,
        'body_kind': content_kind(row[12] or '', row[6] or ''),
        'status': row[7],
        'response_headers': resp_headers,
        'response_body': resp_body,
        'response_decoded': decoded_resp,
        'response_kind': content_kind(row[13] or '', resp_body),
        'timestamp': row[10],
        'modified': row[11] == 1,
        'response_size': row[12] or len(resp_body),
    })


@app.route('/api/pending')
def api_pending():
    pending = signal_bus.get_pending()
    result = []
    for p in pending:
        data = p['data']
        result.append({
            'key': p['key'],
            'method': data.get('method', ''),
            'url': data.get('url', ''),
            'host': data.get('host', ''),
            'path': data.get('path', ''),
            'headers': data.get('headers', {}),
            'body': data.get('body', ''),
            'body_decoded': data.get('decoded_body', {}),
            'content_type': data.get('content_type_req', ''),
        })
    return jsonify(result)


@app.route('/api/intercept/toggle', methods=['POST'])
def api_toggle_intercept():
    signal_bus.intercept_enabled = not signal_bus.intercept_enabled
    return jsonify({'enabled': signal_bus.intercept_enabled})


@app.route('/api/forward', methods=['POST'])
def api_forward():
    data = request.get_json() or {}
    key = data.get('key')
    if not key:
        return jsonify({'error': 'no key'}), 400
    signal_bus.apply_modification(key, {})
    return jsonify({'ok': True})


@app.route('/api/drop', methods=['POST'])
def api_drop():
    data = request.get_json() or {}
    key = data.get('key')
    if not key:
        return jsonify({'error': 'no key'}), 400
    signal_bus.apply_modification(key, {'drop': True})
    return jsonify({'ok': True})


@app.route('/api/modify', methods=['POST'])
def api_modify():
    data = request.get_json() or {}
    key = data.get('key')
    modifications = data.get('modifications', {})
    if not key:
        return jsonify({'error': 'no key'}), 400
    signal_bus.apply_modification(key, modifications)
    return jsonify({'ok': True})


@app.route('/api/clear', methods=['POST'])
def api_clear():
    db.clear()
    return jsonify({'ok': True})


@app.route('/api/findings')
def api_findings():
    rows = db.get_findings()
    return jsonify([
        {
            'id': r[0], 'severity': r[1], 'type': r[2],
            'url': r[3], 'description': r[4],
            'evidence': r[5], 'timestamp': r[6],
        } for r in rows
    ])


@app.route('/api/decode', methods=['POST'])
def api_decode():
    data = request.get_json() or {}
    text = data.get('text', '')
    action = data.get('action', 'auto')

    try:
        if action == 'url_encode':
            result = urllib.parse.quote(text)
        elif action == 'url_decode':
            result = urllib.parse.unquote(text)
        elif action == 'b64_encode':
            result = base64.b64encode(text.encode()).decode()
        elif action == 'b64_decode':
            result = base64.b64decode(text.encode()).decode()
        elif action == 'hex_encode':
            result = text.encode().hex()
        elif action == 'hex_decode':
            result = bytes.fromhex(text).decode()
        elif action == 'html_encode':
            result = html_lib.escape(text)
        elif action == 'html_decode':
            result = html_lib.unescape(text)
        elif action == 'jwt_decode':
            parts = text.split('.')
            if len(parts) == 3:
                pad = lambda s: s + '=' * (-len(s) % 4)
                h = base64.urlsafe_b64decode(pad(parts[0])).decode('utf-8', errors='ignore')
                p = base64.urlsafe_b64decode(pad(parts[1])).decode('utf-8', errors='ignore')
                try:
                    h = json.dumps(json.loads(h), indent=2)
                    p = json.dumps(json.loads(p), indent=2)
                except Exception:
                    pass
                result = f"Header:\n{h}\n\nPayload:\n{p}"
            else:
                result = "JWT invalide (3 parties attendues)"
        elif action == 'md5':
            result = hashlib.md5(text.encode()).hexdigest()
        elif action == 'sha1':
            result = hashlib.sha1(text.encode()).hexdigest()
        elif action == 'sha256':
            result = hashlib.sha256(text.encode()).hexdigest()
        elif action == 'auto':
            decoded = Decoder.decode_value(text)
            result = decoded['decoded']
        else:
            result = "Action inconnue"

        return jsonify({'result': result, 'error': None})
    except Exception as e:
        return jsonify({'result': None, 'error': str(e)})


@app.route('/api/repeater/send', methods=['POST'])
def api_repeater_send():
    data = request.get_json() or {}
    method = data.get('method', 'GET')
    url = data.get('url', '')
    headers = data.get('headers', {})
    body = data.get('body', '')

    if not url or not REQUESTS_OK:
        return jsonify({'error': 'URL manquante ou requests non installé'}), 400

    try:
        url = url.strip().replace('\n', '').replace('\r', '')

        r = requests.request(
            method, url,
            headers=headers,
            data=body.encode() if body else None,
            timeout=30, verify=False, allow_redirects=False,
        )

        decoded = Decoder.decode_body(r.text, r.headers.get('Content-Type', ''))

        response_data = {
            'status': r.status_code,
            'headers': dict(r.headers),
            'body': r.text,
            'body_decoded': decoded,
            'body_kind': content_kind(r.headers.get('Content-Type', ''), r.text),
            'size': len(r.content),
            'time': r.elapsed.total_seconds(),
        }

        db.insert({
            'method': method, 'url': url,
            'host': urllib.parse.urlparse(url).netloc,
            'path': urllib.parse.urlparse(url).path,
            'headers': headers, 'body': body,
            'status': r.status_code,
            'response_headers': dict(r.headers),
            'response_body': r.text,
            'response_size': len(r.content),
            'content_type_req': headers.get('Content-Type', ''),
            'content_type_resp': r.headers.get('Content-Type', ''),
            'decoded_body': Decoder.decode_body(body, headers.get('Content-Type', '')),
        })

        return jsonify(response_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/json')
def api_export_json():
    data = db.export_json()
    return Response(
        json.dumps(data, indent=2, default=str),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename=burp_like_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
    )


@app.route('/api/export/html')
def api_export_html():
    requests_data = db.export_json()
    findings = db.get_findings()

    sev_colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8844',
                  'MEDIUM': '#ffcc44', 'LOW': '#8888ff'}

    html_content = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Burp-Like Report</title>
<style>
body {{ font-family: 'Consolas', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
h1, h2 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 8px; border-bottom: 1px solid #30363d; text-align: left; font-size: 13px; }}
th {{ background: #161b22; color: #7ee787; }}
.badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 11px; }}
pre {{ background: #0d1117; padding: 10px; border-radius: 4px; color: #7ee787; overflow-x: auto; }}
</style></head><body>
<h1>🔷 Burp-Like Web — Rapport</h1>
<p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total requêtes: {len(requests_data)} — Findings: {len(findings)}</p>
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Sévérité</th><th>Type</th><th>URL</th><th>Description</th></tr>"""

    for f in findings:
        sev = f[1]; color = sev_colors.get(sev, '#888')
        html_content += f'<tr><td><span class="badge" style="background:{color}">{sev}</span></td>'
        html_content += f'<td>{f[2]}</td><td>{f[3][:100]}</td><td>{f[4]}</td></tr>'

    html_content += '</table><h2>Historique</h2>'
    html_content += '<table><tr><th>ID</th><th>Method</th><th>URL</th><th>Status</th></tr>'
    for r in requests_data[:500]:
        html_content += f'<tr><td>{r.get("id")}</td><td>{r.get("method")}</td><td>{r.get("url", "")[:120]}</td><td>{r.get("status")}</td></tr>'
    html_content += '</table></body></html>'

    return Response(
        html_content,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment;filename=burp_like_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'}
    )


# ==================== INTRUDER ====================

intruder_state = {
    'running': False,
    'progress': {'current': 0, 'total': 0},
    'results': [],
    'lock': threading.Lock(),
    'stop_flag': False,
}


def run_intruder(config):
    url = config['url']
    method = config['method']
    headers = config['headers']
    body = config['body']
    payloads = config['payloads']
    attack_type = config['attack_type']
    threads = config.get('threads', 5)
    positions = url.count('§') + body.count('§')

    if attack_type == 'sniper':
        combos = []
        for pos in range(positions):
            for p in payloads:
                combo = [''] * positions
                combo[pos] = p
                combos.append(combo)
    elif attack_type == 'battering_ram':
        combos = [[p] * positions for p in payloads]
    elif attack_type == 'pitchfork':
        combos = [list(c) for c in zip(*payloads)] if all(isinstance(p, list) for p in payloads) else [[p] for p in payloads]
    elif attack_type == 'cluster_bomb':
        import itertools
        if all(isinstance(p, list) for p in payloads):
            combos = [list(c) for c in itertools.product(*payloads)]
        else:
            combos = [list(c) for c in itertools.product(payloads, repeat=positions)]
    else:
        combos = []

    with intruder_state['lock']:
        intruder_state['progress'] = {'current': 0, 'total': len(combos)}
        intruder_state['results'] = []
        intruder_state['running'] = True
        intruder_state['stop_flag'] = False

    session = requests.Session()
    session.mount('https://', HTTPAdapter(max_retries=Retry(total=2)))

    def send_one(idx, combo):
        if intruder_state['stop_flag']:
            return None
        try:
            final_url = url
            final_body = body
            final_headers = dict(headers)
            for pos_idx, payload in enumerate(combo):
                placeholder = f'§{pos_idx}§'
                final_url = final_url.replace(placeholder, payload)
                final_body = final_body.replace(placeholder, payload)
                for k, v in final_headers.items():
                    final_headers[k] = v.replace(placeholder, payload)

            start = time.time()
            r = session.request(
                method, final_url, headers=final_headers,
                data=final_body.encode() if final_body else None,
                timeout=15, allow_redirects=False, verify=False,
            )
            elapsed = time.time() - start

            return {
                'idx': idx, 'payloads': combo,
                'status': r.status_code, 'size': len(r.content),
                'time': round(elapsed, 3),
                'body': r.text[:300],
                'headers': dict(r.headers),
            }
        except Exception as e:
            return {'idx': idx, 'payloads': combo, 'error': str(e),
                    'status': 0, 'size': 0, 'time': 0, 'body': ''}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(send_one, i, c): i for i, c in enumerate(combos)}
        for i, fut in enumerate(as_completed(futures)):
            if intruder_state['stop_flag']:
                break
            result = fut.result()
            if result:
                with intruder_state['lock']:
                    intruder_state['results'].append(result)
                    intruder_state['progress']['current'] = i + 1

    with intruder_state['lock']:
        intruder_state['running'] = False


@app.route('/api/intruder/start', methods=['POST'])
def api_intruder_start():
    if intruder_state['running']:
        return jsonify({'error': 'Intruder déjà en cours'}), 400
    config = request.get_json() or {}
    threading.Thread(target=run_intruder, args=(config,), daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/intruder/stop', methods=['POST'])
def api_intruder_stop():
    intruder_state['stop_flag'] = True
    return jsonify({'ok': True})


@app.route('/api/intruder/status')
def api_intruder_status():
    with intruder_state['lock']:
        return jsonify({
            'running': intruder_state['running'],
            'progress': intruder_state['progress'],
            'results': intruder_state['results'][-100:],
        })


# ==================== MAIN ====================

def run_web():
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔷 BURP-LIKE WEB v2.1 — JATHNIEL EDITION                   ║
║                                                              ║
║   Interface web :  http://127.0.0.1:{WEB_PORT}                     ║
║   Proxy MITM    :  http://127.0.0.1:{PROXY_PORT}                     ║
║                                                              ║
║   Ouvre ton navigateur sur http://127.0.0.1:{WEB_PORT}             ║
║   Configure le proxy sur 127.0.0.1:{PROXY_PORT}                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    app.run(
        host='0.0.0.0', port=WEB_PORT,
        debug=False, use_reloader=False,
        threaded=True,
    )


def main():
    # Lancer le proxy dans un thread dédié (avec son propre event loop)
    proxy = ProxyServer(port=PROXY_PORT)
    proxy.start()

    # Attendre que le proxy soit prêt (max 5s)
    proxy.ready.wait(timeout=5)

    try:
        run_web()
    except KeyboardInterrupt:
        print("\n[!] Arrêt...")
        proxy.shutdown()


if __name__ == '__main__':
    main()