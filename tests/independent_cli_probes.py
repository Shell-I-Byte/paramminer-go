#!/usr/bin/env python3
"""No external network. Independent CLI probes against a synthetic loopback server."""
import hashlib, http.server, json, os, pathlib, socket, subprocess, sys, tempfile, threading, time, urllib.parse
ROOT=pathlib.Path(__file__).resolve().parents[1]
checks=0

def check(name, actual):
    global checks
    assert actual, f"FAIL {name}"
    checks+=1
    print(f"PASS {checks:02d} {name}")

class Server(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    seen=[]
    def do_GET(self):
        parts=urllib.parse.urlsplit(self.path)
        self.seen.append((self.path, self.headers.get('Cookie','')))
        if parts.path=='/redirect':
            self.send_response(302);self.send_header('Location','https://example.invalid/NEVER-FOLLOW');self.end_headers();return
        if parts.path=='/unstable':
            self.send_response(200);self.end_headers();self.wfile.write(str(len(self.seen)).encode());return
        if parts.path=='/large':
            self.send_response(200);self.end_headers();self.wfile.write(b'x'*(1024*1024+2));return
        if parts.path=='/slow':time.sleep(.15)
        vals=urllib.parse.parse_qs(parts.query)
        msg=b'probe-changed' if 'feature' in vals else b'baseline'
        self.send_response(200);self.send_header('Set-Cookie','secrets=do-not-leak');self.end_headers()
        try:self.wfile.write(msg)
        except (BrokenPipeError, ConnectionResetError):pass
    def log_message(self, *args):pass

with tempfile.TemporaryDirectory(prefix='paramminer-independent-') as tmp:
    tmp=pathlib.Path(tmp)
    binary=tmp/'paramminer-go'
    env=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off')
    p=subprocess.run(['go','build','-trimpath','-o',str(binary),'./cmd/paramminer-go'],cwd=ROOT,env=env,capture_output=True,text=True)
    check('compile Linux CLI',p.returncode==0)
    def run(*args):
        return subprocess.run([str(binary),*args],capture_output=True,text=True,timeout=9,env=env)
    example=ROOT/'examples/requests.json'
    p=run('inventory','--input',str(example))
    check('valid inventory exit 0',p.returncode==0)
    obj=json.loads(p.stdout)
    check('output contract',obj['schema']=='paramminer.result/v1' and obj['mode']=='inventory')
    check('observed status',all(x['status']=='observed' for x in obj['findings']))
    check('observed sorted keys',[x['name'] for x in obj['findings']]==['lang','page'])
    check('count per distinct record',obj['findings'][0]['count']==2)
    check('source sha256',obj['input_sha256']==hashlib.sha256(example.read_bytes()).hexdigest())
    check('no URL leak','example.invalid' not in p.stdout)
    check('no URL path leak','catalog' not in p.stdout)
    check('deterministic output',run('inventory','--input',str(example)).stdout==p.stdout)
    check('stderr clean on success',p.stderr=='')
    check('no args exit 2',run().returncode==2)
    check('unknown command exit 2',run('unknown').returncode==2)
    check('unknown flag exit 2',run('inventory','--invalid').returncode==2)
    check('unknown positional exit 2',run('inventory','--input',str(example),'extra').returncode==2)
    check('missing file exit 3',run('inventory','--input',str(tmp/'absent')).returncode==3)
    for command in ('inventory','probe'):
        for opt in ('-h','-help','--help'):
            h=run(command,opt)
            check(f'{command} {opt} help exit 0',h.returncode==0 and h.stderr=='' and f'usage: paramminer-go {command}' in h.stdout)
    if os.name=='posix' and hasattr(os,'mkfifo'):
        fifo=tmp/'blocked.fifo';os.mkfifo(fifo)
        linked=tmp/'fifo-link';linked.symlink_to(fifo)
        good=tmp/'good.json';good.write_text('{"requests":[]}')
        goodlink=tmp/'good-link';goodlink.symlink_to(good)
        for name,path in [('FIFO',fifo),('symlink FIFO',linked),('directory',tmp)]:
            for mode,flag in [('inventory','--input'),('probe','--candidates')]:
                args=('inventory','--input',str(path)) if mode=='inventory' else ('probe','--target','http://127.0.0.1:1/','--candidates',str(path),'--authorize')
                q=run(*args)
                check(f'{mode} reject {name} without hanging',q.returncode==3 and q.stdout=='')
        check('regular symlink valid',run('inventory','--input',str(goodlink)).returncode==0)
    malicious='--bad\nFORGED-AUDIT-PASS'
    p=run('inventory',malicious)
    check('flag injection exits 2',p.returncode==2)
    check('malicious flag not echoed','FORGED-AUDIT-PASS' not in p.stdout+p.stderr)
    inputs={
        'duplicate root':'{"requests":[],"requests":[]}',
        'duplicate nested':'{"requests":[{"method":"GET","method":"POST","url":"http://127.0.0.1/"}]}',
        'trailing document':'{"requests":[]} true',
        'unknown field':'{"requests":[],"cookie":"SECRET"}',
        'unsupported method':'{"requests":[{"method":"CONNECT","url":"http://127.0.0.1/"}]}',
        'malformed query':'{"requests":[{"method":"GET","url":"http://127.0.0.1/?a=%XX"}]}',
        'credential URL':'{"requests":[{"method":"GET","url":"http://u:password@127.0.0.1/?a=1"}]}',
        'relative URL':'{"requests":[{"method":"GET","url":"/foo?a=1"}]}',
        'invalid param':'{"requests":[{"method":"GET","url":"http://127.0.0.1/?a%0Ab=c"}]}',
        'invalid JSON':'{"requests":[',
        'casefold root alias':'{"Requests":[{"method":"GET","url":"https://example.invalid/?wrong=1"}]}',
        'casefold nested alias':'{"requests":[{"Method":"GET","URL":"https://example.invalid/?wrong=1"}]}',
        'casefold root conflict':'{"requests":[],"Requests":[{"method":"GET","url":"https://example.invalid/?wrong=1"}]}',
        'casefold url conflict':'{"requests":[{"method":"GET","url":"https://example.invalid/?one=1","URL":"https://example.invalid/?two=1"}]}',
        'missing requests':'{}',
        'null requests':'{"requests":null}',
        'null root':'null',
    }
    for label,s in inputs.items():
        f=tmp/(label.replace(' ','_')+'.json');f.write_text(s)
        p=run('inventory','--input',str(f))
        check('reject '+label,p.returncode==3 and p.stdout=='')
    invalid_utf8=tmp/'invalid_utf8.json';invalid_utf8.write_bytes(b'{"requests":[{"method":"GET","url":"http://127.0.0.1/?a='+bytes([255])+b'"}]}')
    check('reject invalid UTF-8',run('inventory','--input',str(invalid_utf8)).returncode==3)
    huge=tmp/'huge.json';huge.write_bytes(b'x'*(8*1024*1024+1))
    check('reject >8MiB input',run('inventory','--input',str(huge)).returncode==3)
    for pair_count, expected_rc in ((10000, 0), (10001, 3), (50000, 3)):
        path = tmp / f'query_{pair_count}.json'
        query = '&'.join(['a=1'] * pair_count)
        path.write_text(json.dumps({'requests':[{'method':'GET','url':'https://example.invalid/?'+query}]},separators=(',',':')))
        p = run('inventory', '--input', str(path))
        check(f'query-field boundary {pair_count}', p.returncode == expected_rc and (p.stdout == '' if expected_rc else json.loads(p.stdout)['findings'][0]['count']==1))
    handler=Server
    srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),handler)
    bg=threading.Thread(target=srv.serve_forever,daemon=True);bg.start()
    try:
        base=f'http://127.0.0.1:{srv.server_address[1]}'
        words=tmp/'words';words.write_text('feature\nrandom\n')
        p=run('probe','--target',base+'/safe','--candidates',str(words),'--authorize')
        check('successful local probe',p.returncode==0)
        result=json.loads(p.stdout)
        check('probe contract',result['schema']=='paramminer.result/v1' and result['mode']=='probe')
        check('one inferred parameter',[x['name'] for x in result['findings']]==['feature'])
        check('inferred not confirmed',result['findings'][0]['status']=='inferred')
        check('no target or cookie in output','127.0.0.1' not in p.stdout and 'do-not-leak' not in p.stdout)
        check('no cookies sent',all(not c for _,c in handler.seen))
        check('probe deterministic',run('probe','--target',base+'/safe','--candidates',str(words),'--authorize').stdout==p.stdout)
        check('authorization mandatory',run('probe','--target',base,'--candidates',str(words)).returncode==3)
        check('remote targets rejected',run('probe','--target','http://8.8.8.8/','--candidates',str(words),'--authorize').returncode==3)
        check('DNS names refused',run('probe','--target','http://localhost:1/','--candidates',str(words),'--authorize').returncode==3)
        check('https refused',run('probe','--target',base.replace('http','https'),'--candidates',str(words),'--authorize').returncode==3)
        check('userinfo refused',run('probe','--target',base.replace('http://','http://user:secret@'),'--candidates',str(words),'--authorize').returncode==3)
        check('supplied query refused',run('probe','--target',base+'/?token=topsecret','--candidates',str(words),'--authorize').returncode==3)
        check('fragment refused',run('probe','--target',base+'/#frag','--candidates',str(words),'--authorize').returncode==3)
        p=run('probe','--target',base+'/redirect','--candidates',str(words),'--authorize')
        check('redirect response no follow',p.returncode==0 and json.loads(p.stdout)['findings']==[])
        check('unstable baseline rejects',run('probe','--target',base+'/unstable','--candidates',str(words),'--authorize').returncode==3)
        check('oversized body rejects',run('probe','--target',base+'/large','--candidates',str(words),'--authorize').returncode==3)
        check('timeout rejects',run('probe','--target',base+'/slow','--candidates',str(words),'--authorize','--timeout','1ms').returncode==3)
        check('zero timeout rejects',run('probe','--target',base,'--candidates',str(words),'--authorize','--timeout','0s').returncode==3)
        check('timeout >10s rejects',run('probe','--target',base,'--candidates',str(words),'--authorize','--timeout','11s').returncode==3)
        for val in ('1ns', '500us', '999999ns', '0s', '-1ms', '10s1ns'):
            before=len(handler.seen)
            rejected=run('probe','--target',base,'--candidates',str(words),'--authorize','--timeout',val)
            check(f'fail closed timeout {val}',rejected.returncode==3 and rejected.stdout=='' and 'timeout must be within 1ms to 10s' in rejected.stderr and len(handler.seen)==before)
        check('valid 10s boundary succeeds',run('probe','--target',base+'/safe','--candidates',str(words),'--authorize','--timeout','10s').returncode==0)
        min_bound=run('probe','--target',base+'/slow','--candidates',str(words),'--authorize','--timeout','1ms')
        check('valid 1ms boundary not rejected during validation','timeout must be within' not in min_bound.stderr)

        for text,label in [('something=bad','non-identifier'),('x\n'*66,'duplicates not hidden since unique check'),('💥','unicode')]:
            f=tmp/('candidate_'+label);f.write_text(text)
            rc=run('probe','--target',base,'--candidates',str(f),'--authorize').returncode
            if label=='duplicates not hidden since unique check':check('repeated candidate deduped',rc==0)
            else:check('reject '+label,rc==3)
        oversized=tmp/'many_names';oversized.write_text(''.join('p%d\n'%i for i in range(65)))
        check('too many unique candidates rejected',run('probe','--target',base,'--candidates',str(oversized),'--authorize').returncode==3)
        check('does not emit private input',not any('password' in x for x in [p.stdout,p.stderr]))
    finally:
        srv.shutdown();srv.server_close();bg.join(timeout=2)
print('FINAL RESULT: CLI_PROBES_PASSED=',checks)
