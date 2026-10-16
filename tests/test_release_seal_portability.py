"""Portable release ZIP falsification: archive paths are untrusted metadata."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts'/'release_seal.py'
PREFIX='ParamMiner-Go_v0.1.0-rc11_Run202/'

class ReleaseArchivePathTests(unittest.TestCase):
    def make_variant(self, valid, output, added):
        with zipfile.ZipFile(valid) as source:
            manifest=json.loads(source.read(PREFIX+'SOURCE_MANIFEST_SHA256.json'))
            manifest['files'].update({name:hashlib.sha256(body).hexdigest() for name,body in added.items()})
            with zipfile.ZipFile(output,'w') as dest:
                for entry in source.infolist():
                    data=source.read(entry.filename)
                    if entry.filename==PREFIX+'SOURCE_MANIFEST_SHA256.json':
                        data=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
                    dest.writestr(entry,data)
                for name, body in added.items():
                    entry=zipfile.ZipInfo(PREFIX+name,date_time=(2026,10,14,0,0,0))
                    entry.create_system=3;entry.external_attr=(0o100644 << 16)
                    dest.writestr(entry,body)

    def test_rejects_portability_collisions(self):
        with tempfile.TemporaryDirectory() as t:
            valid=pathlib.Path(t)/'valid.zip'
            subprocess.run([sys.executable,str(SCRIPT),str(valid)],check=True,capture_output=True,text=True)
            cases={
                'backslash_parent_traversal':{'docs\\..\\..\\outside.txt':b'A'},
                'casefold_colliding_file':{'readme.md':b'B'},
                'unicode_normalized_collision':{'docs/caf\u00e9.txt':b'C','docs/cafe\u0301.txt':b'D'},
                'double_slash_alias':{'docs//LIMITATIONS.md':b'E'},
                'parent_file_clashes_with_directory':{'docs':b'F'},
                'windows_reserved_device_name':{'docs/CON.txt':b'G'},
                'windows_alternate_data_stream':{'docs/odd:stream.txt':b'H'},
            }
            for name,extra in cases.items():
                archive=pathlib.Path(t)/f'{name}.zip'
                self.make_variant(valid,archive,extra)
                for optimized in (False,True):
                    with self.subTest(case=name,optimized=optimized):
                        command=[sys.executable]+(['-O'] if optimized else [])+[str(SCRIPT),'--verify',str(archive)]
                        p=subprocess.run(command,capture_output=True,text=True,timeout=20)
                        self.assertNotEqual(p.returncode,0,f'unsafe archive accepted: {name}, python -O={optimized}\n{p.stdout}')

if __name__=='__main__':unittest.main()
