#!/usr/bin/env python3
"""Deterministically seal this standalone source tree; validate ZIP and manifest.

Usage: python3 scripts/release_seal.py OUT.zip
       python3 scripts/release_seal.py --verify OUT.zip
Does not run untrusted source code. Does not include VCS metadata or binaries.
"""
import hashlib, json, pathlib, sys, zipfile, unicodedata
ROOT=pathlib.Path(__file__).resolve().parents[1]
PREFIX='ParamMiner-Go_v0.1.0-rc11_Run202/'
MANIFEST='SOURCE_MANIFEST_SHA256.json'
# Explicit source-controlled executable metadata survives ZIP extraction on
# machines that do not restore Unix modes, and is checked on verification.
EXECUTABLES=('scripts/release_seal.py','tests/independent_cli_probes.py')
IGNORE={'__pycache__','.git','.pytest_cache'}

def eligible(path):
    rel=path.relative_to(ROOT)
    return path.is_file() and not path.is_symlink() and not any(x in IGNORE for x in rel.parts) and rel.name!=MANIFEST and not rel.name.endswith(('.pyc','.exe','.test','.out'))

def listed():
    return {p.relative_to(ROOT).as_posix():p for p in sorted(ROOT.rglob('*')) if eligible(p)}

def sha(data):return hashlib.sha256(data).hexdigest()

def manifest_obj():
    files={name:sha(p.read_bytes()) for name,p in listed().items()}
    return {'algorithm':'SHA-256','schema':'paramminer.source-manifest/v1','files':files,'executable':list(EXECUTABLES)}

def prepare():
    m=manifest_obj()
    (ROOT/MANIFEST).write_text(json.dumps(m,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return m

def seal(destination):
    prepare()
    sources=listed();sources[MANIFEST]=ROOT/MANIFEST
    with zipfile.ZipFile(destination,'w') as z:
        for name,p in sorted(sources.items()):
            entry=zipfile.ZipInfo(PREFIX+name,date_time=(2026,10,14,0,0,0))
            entry.create_system=3
            entry.external_attr=((0o100755 if name in EXECUTABLES else 0o100644)<<16)
            entry.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(entry,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    verify(destination)
    print('SEALED',destination,'FILES',len(sources),'SHA256',sha(pathlib.Path(destination).read_bytes()))

# Reject archive path ambiguity on Windows and Unicode-normalizing filesystems.
# This is an additional structural gate, not publisher authentication.
WINDOWS_DEVICES = {'con', 'prn', 'aux', 'nul'} | {
    f'{prefix}{digit}' for prefix in ('com', 'lpt') for digit in '123456789\u00b9\u00b2\u00b3'
}

def validate_portable_paths(names):
    canonical_files = {}
    for full in names:
        if not full.startswith(PREFIX):
            raise ValueError('archive entry outside source prefix')
        rel = full[len(PREFIX):]
        if not rel or rel.startswith('/') or '\\' in rel or '\x00' in rel:
            raise ValueError('unsafe archive path')
        parts = rel.split('/')
        if any(not part or part in ('.', '..') or part.endswith((' ', '.')) or ':' in part or
               any(ord(ch) < 32 or ord(ch) == 127 for ch in part) for part in parts):
            raise ValueError('nonportable archive path')
        for part in parts:
            normalized = unicodedata.normalize('NFC', part).casefold()
            if normalized.split('.', 1)[0] in WINDOWS_DEVICES:
                raise ValueError('reserved Windows device name')
        canonical = '/'.join(unicodedata.normalize('NFC',part).casefold() for part in parts)
        if canonical in canonical_files:
            raise ValueError('casefold/Unicode archive path collision')
        canonical_files[canonical] = full
    # A file cannot itself also denote an ancestor of another file.
    for canonical in canonical_files:
        parts = canonical.split('/')
        for depth in range(1,len(parts)):
            if '/'.join(parts[:depth]) in canonical_files:
                raise ValueError('file/directory archive path collision')

def verify(location):
    with zipfile.ZipFile(location) as z:
        names=z.namelist()
        # Explicit exceptions are essential: `python -O` removes all `assert`
        # statements, and must never convert an invalid seal into PASS.
        if len(names)!=len(set(names)):
            raise ValueError('duplicate ZIP entries')
        validate_portable_paths(names)
        if not all(x.startswith(PREFIX) and '..' not in pathlib.PurePosixPath(x).parts and not x.endswith('/') for x in names):
            raise ValueError('unsafe archive paths')
        m=json.loads(z.read(PREFIX+MANIFEST))
        fs=m['files']
        if (m.get('executable')!=list(EXECUTABLES) or
                not set(EXECUTABLES).issubset(fs)):
            raise ValueError('invalid executable file metadata')
        if set(names)!={PREFIX+n for n in fs}|{PREFIX+MANIFEST}:
            raise ValueError('manifest coverage mismatch')
        for info in z.infolist():
            relative=info.filename[len(PREFIX):]
            expected_mode=0o100755 if relative in EXECUTABLES else 0o100644
            if (info.external_attr>>16)!=expected_mode:
                raise ValueError('ZIP executable mode differs from manifest policy')
        for n,expected in fs.items():
            if sha(z.read(PREFIX+n))!=expected:
                raise ValueError('content digest mismatch')
        if m['schema']!='paramminer.source-manifest/v1':
            raise ValueError('incorrect manifest schema')
        print('VERIFY PASS',len(fs),'manifest file hashes, ZIP paths and exact coverage')

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--verify':verify(sys.argv[2])
    elif len(sys.argv)==2:seal(sys.argv[1])
    else:raise SystemExit('usage: release_seal.py [--verify] PATH')
