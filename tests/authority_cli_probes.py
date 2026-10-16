#!/usr/bin/env python3
"""Synthetic loopback-only independent CLI authority regression (2026-10-15)."""
import http.server
import json
import pathlib
import subprocess
import sys
import tempfile
import threading

if len(sys.argv) != 2:
    raise SystemExit('usage: authority_cli_probes.py /path/to/compiled-binary')
BINARY = str(pathlib.Path(sys.argv[1]).resolve())

class Handler(http.server.BaseHTTPRequestHandler):
    count = 0
    def do_GET(self):
        Handler.count += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'unchanged')
    def log_message(self, *args): pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
checks = 0
try:
    with tempfile.TemporaryDirectory() as folder:
        directory = pathlib.Path(folder)
        input_path = directory / 'input.json'
        words = directory / 'candidates.txt'
        words.write_text('feature\n', encoding='utf-8')
        for name, target in [
            ('bracketed DNS', 'http://[example.test]/?feature=1'),
            ('bracketed IPv4', 'http://[127.0.0.1]/?feature=1'),
            ('unsupported IPvFuture', 'http://[v1.fe80]/?feature=1'),
        ]:
            input_path.write_text(json.dumps({'requests': [{'method': 'GET', 'url': target}]}), encoding='utf-8')
            proc = subprocess.run([BINARY, 'inventory', '--input', str(input_path)], capture_output=True, text=True, timeout=5)
            if proc.returncode != 3 or proc.stdout or target in proc.stderr:
                raise AssertionError((name, proc.returncode, proc.stdout[:100], proc.stderr[:100]))
            checks += 1
            print('PASS inventory rejects', name)
        for name, target in [
            ('bracketed IPv4', f'http://[127.0.0.1]:{server.server_port}/'),
            ('bracketed alternate IPv4', f'http://[127.0.2.3]:{server.server_port}/'),
        ]:
            before = Handler.count
            proc = subprocess.run([BINARY, 'probe', '--target', target, '--candidates', str(words), '--authorize', '--timeout', '500ms'], capture_output=True, text=True, timeout=5)
            if proc.returncode != 3 or proc.stdout or Handler.count != before:
                raise AssertionError((name, proc.returncode, Handler.count-before, proc.stdout[:100]))
            checks += 1
            print('PASS probe refuses before network', name)
        for url in ['https://example.test/?a=1', 'http://[::1]/?ipv6=1', 'http://127.0.0.1/?b=1']:
            input_path.write_text(json.dumps({'requests': [{'method': 'GET', 'url': url}]}), encoding='utf-8')
            proc = subprocess.run([BINARY, 'inventory', '--input', str(input_path)], capture_output=True, text=True, timeout=5)
            if proc.returncode or json.loads(proc.stdout)['mode'] != 'inventory':
                raise AssertionError(('positive inventory', url, proc.returncode, proc.stderr[:100]))
            checks += 1
            print('PASS inventory permits', url)
        before = Handler.count
        proc = subprocess.run([BINARY, 'probe', '--target', f'http://127.0.0.1:{server.server_port}/', '--candidates', str(words), '--authorize', '--timeout', '500ms'], capture_output=True, text=True, timeout=5)
        if proc.returncode or json.loads(proc.stdout)['mode'] != 'probe' or Handler.count <= before:
            raise AssertionError(('positive probe', proc.returncode, Handler.count-before))
        checks += 1
        print('PASS ordinary owned local probe')
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
print('PASS_ALL', checks)
