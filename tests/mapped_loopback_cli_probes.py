#!/usr/bin/env python3
"""Owned local HTTP lab: fail closed on IPv4-mapped IPv6 policy aliases."""
import http.server, json, pathlib, subprocess, tempfile, threading, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else None
if BIN is None:
    raise SystemExit('usage: mapped_loopback_cli_probes.py /path/to/binary')
class Handler(http.server.BaseHTTPRequestHandler):
    seen = 0
    def do_GET(self):
        Handler.seen+=1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'constant')
    def log_message(self, *_): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
checks=0
try:
    with tempfile.TemporaryDirectory() as td:
        words=pathlib.Path(td)/'words.txt'
        words.write_text('alpha\n',encoding='utf-8')
        for name,target,expected in [
            ('IPv4 allowed',f'http://127.0.0.1:{server.server_port}/',0),
            ('mapped IPv6 dotted forbidden',f'http://[::ffff:127.0.0.1]:{server.server_port}/',3),
            ('mapped IPv6 hex forbidden',f'http://[::ffff:7f00:1]:{server.server_port}/',3),
        ]:
            before=Handler.seen
            completed=subprocess.run([str(BIN),'probe','--target',target,'--candidates',str(words),'--authorize','--timeout','500ms'], capture_output=True, text=True, timeout=5)
            correct=(completed.returncode==expected)
            no_network=expected==0 or Handler.seen==before
            stdout_contract=(expected!=0 and completed.stdout=='') or (expected==0 and json.loads(completed.stdout)['mode']=='probe')
            if not (correct and no_network and stdout_contract):
                print('FAIL',name,{'rc':completed.returncode,'expected':expected,'new_requests':Handler.seen-before,'stdout':completed.stdout[:100],'stderr':completed.stderr[:100]})
                sys.exit(1)
            checks+=1
            print('PASS',name,'rc=',completed.returncode,'new_requests=',Handler.seen-before)
finally:
    server.shutdown();server.server_close();t.join(timeout=2)
print('PASS_ALL',checks)
