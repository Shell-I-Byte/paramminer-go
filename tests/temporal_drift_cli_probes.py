#!/usr/bin/env python3
"""Local-only falsification tests for time-dependent HTTP response drift.

Without a stable unmodified post-probe control, a deployment that occurs just
between initial baseline and candidate requests becomes false inferred evidence.
No non-loopback network requests are made by this test.
"""
import argparse
import http.server
import json
import os
import pathlib
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.count += 1
        if self.server.scenario == "drift":
            body = b"before" if self.server.count <= 2 else b"after"
        elif self.server.scenario == "burst":
            body = b"transient" if self.server.count in (3, 4) else b"baseline"
        elif self.server.scenario == "positive":
            body = b"changed" if "candidate=" in self.path else b"baseline"
        else:
            body = b"baseline"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def assert_scenario(binary, scenario, expected_rc, expected_hits, expected_findings, words):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.scenario = scenario
    server.count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cmd = [str(binary), "probe", "--target", f"http://127.0.0.1:{server.server_port}/", "--candidates", str(words), "--authorize", "--timeout", "3s"]
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
        assert completed.returncode == expected_rc, (scenario, "exit", completed.returncode, completed.stdout, completed.stderr)
        assert server.count == expected_hits, (scenario, "request-count", server.count, expected_hits)
        if expected_rc:
            assert completed.stdout == "", (scenario, "error-return-data", completed.stdout)
            assert ("unstable baseline" in completed.stderr if scenario == "drift" else "unstable candidate response" in completed.stderr), (scenario, "unexpected-error", completed.stderr)
        else:
            report = json.loads(completed.stdout)
            assert report["schema"] == "paramminer.result/v1"
            assert [x["name"] for x in report["findings"]] == expected_findings
            assert all(x["status"] == "inferred" for x in report["findings"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    print(f"PASS {scenario}: rc={expected_rc} requests={expected_hits} expected_findings={expected_findings}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        words = tmp / "words.txt"
        words.write_text("candidate\n", encoding="ascii")
        binary = args.binary if args.binary is not None else tmp / ("paramminer-go.exe" if os.name == "nt" else "paramminer-go")
        if args.binary is None:
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/paramminer-go"], cwd=ROOT, check=True, timeout=90)
        assert_scenario(binary, "drift", 3, 5, [], words)
        assert_scenario(binary, "burst", 3, 6, [], words)
        assert_scenario(binary, "positive", 0, 7, ["candidate"], words)
        assert_scenario(binary, "negative", 0, 4, [], words)
    print("CLI_TEMPORAL_PROBES_PASS 4/4")

if __name__ == "__main__":
    main()
