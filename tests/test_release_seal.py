"""Fail-closed release verifier checks with optimization enabled as well."""
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY = ROOT / 'scripts' / 'release_seal.py'


class ReleaseVerificationTests(unittest.TestCase):
    def check_verify(self, archive, optimized, success):
        cmd = [sys.executable]
        if optimized:
            cmd.append('-O')
        cmd.extend([str(VERIFY), '--verify', str(archive)])
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=20)
        if success:
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('VERIFY PASS', proc.stdout)
        else:
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertNotIn('VERIFY PASS', proc.stdout)

    def test_optimized_python_cannot_bypass_tampering(self):
        with tempfile.TemporaryDirectory() as t:
            valid = pathlib.Path(t) / 'valid.zip'
            subprocess.run([sys.executable, str(VERIFY), str(valid)], check=True,
                           capture_output=True, text=True, cwd=ROOT, timeout=30)
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    self.check_verify(valid, optimized, success=True)
            tampered = pathlib.Path(t) / 'tampered.zip'
            with zipfile.ZipFile(valid) as src, zipfile.ZipFile(tampered, 'w') as dest:
                for entry in src.infolist():
                    data = src.read(entry.filename)
                    if entry.filename.endswith('/internal/miner/miner.go'):
                        data += b'\n// deliberate audit tampering\n'
                    dest.writestr(entry, data)
            for optimized in (False, True):
                with self.subTest(tampered=True, optimized=optimized):
                    self.check_verify(tampered, optimized, success=False)

    def test_sealed_zip_preserves_and_validates_executable_modes(self):
        with tempfile.TemporaryDirectory() as t:
            valid = pathlib.Path(t) / 'valid.zip'
            subprocess.run([sys.executable, str(VERIFY), str(valid)], check=True,
                           capture_output=True, text=True, cwd=ROOT, timeout=30)
            with zipfile.ZipFile(valid) as src:
                for name in ('scripts/release_seal.py', 'tests/independent_cli_probes.py'):
                    matches=[info for info in src.infolist() if info.filename.endswith('/'+name)]
                    self.assertEqual(len(matches),1)
                    self.assertEqual(matches[0].external_attr >> 16, 0o100755)
            tampered = pathlib.Path(t) / 'mode-tampered.zip'
            with zipfile.ZipFile(valid) as src, zipfile.ZipFile(tampered,'w') as dest:
                for entry in src.infolist():
                    if entry.filename.endswith('/scripts/release_seal.py'):
                        entry.external_attr=(0o100644 << 16)
                    dest.writestr(entry,src.read(entry.filename))
            for optimized in (False,True):
                self.check_verify(tampered, optimized, success=False)

    def test_optimized_python_rejects_unlisted_archive_file(self):
        with tempfile.TemporaryDirectory() as t:
            valid = pathlib.Path(t) / 'valid.zip'
            subprocess.run([sys.executable, str(VERIFY), str(valid)], check=True,
                           capture_output=True, text=True, cwd=ROOT, timeout=30)
            extra = pathlib.Path(t) / 'extra.zip'
            with zipfile.ZipFile(valid) as src, zipfile.ZipFile(extra, 'w') as dest:
                for entry in src.infolist():
                    dest.writestr(entry, src.read(entry.filename))
                dest.writestr('ParamMiner-Go_v0.1.0-rc11_Run202/UNLISTED.txt', b'no')
            self.check_verify(extra, optimized=True, success=False)


if __name__ == '__main__':
    unittest.main()
