#!/usr/bin/env python3
"""Self-contained RC8 result schema and CLI contract checks (no external network)."""
import json
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class SchemaContractTests(unittest.TestCase):
    def test_result_version_matches_schema(self):
        schema = json.loads((ROOT / "schema/result.schema.json").read_text())
        self.assertEqual(schema["properties"]["version"]["const"], "v0.1.0-rc11")
        self.assertEqual(schema["properties"]["schema"]["const"], "paramminer.result/v1")

    def test_cli_output_contract(self):
        process = subprocess.run(["go", "run", "./cmd/paramminer-go", "inventory", "--input", "examples/requests.json"], cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        schema = json.loads((ROOT / "schema/result.schema.json").read_text())
        self.assertEqual(result["schema"],schema["properties"]["schema"]["const"])
        self.assertEqual(result["version"],schema["properties"]["version"]["const"])
        self.assertEqual(result["mode"],"inventory")
        self.assertEqual(process.stderr,"")

if __name__ == '__main__':
    unittest.main()
