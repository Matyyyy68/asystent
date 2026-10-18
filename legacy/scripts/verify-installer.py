#!/usr/bin/env python3
"""Verify the EXE's architecture, embedded runtime and every payload hash."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('installer',type=Path)
parser.add_argument('--seven-zip',default='7z')
args=parser.parse_args()
exe=args.installer.resolve()
manifest=json.loads((exe.parent/'payload-manifest.json').read_text())
contents=exe.read_bytes()
assert contents[:2]==b'MZ', 'Missing Windows EXE header'
offset=struct.unpack_from('<I',contents,0x3c)[0]
assert contents[offset:offset+4]==b'PE\x00\x00'
assert struct.unpack_from('<H',contents,offset+4)[0]==0x8664, 'Expected Windows x64 installer'
expected=(exe.parent/(exe.name+'.sha256')).read_text().split()[0]
assert hashlib.sha256(contents).hexdigest()==expected, 'Installer checksum mismatch'
with tempfile.TemporaryDirectory(prefix='sentinel-verify-') as directory:
    subprocess.run([args.seven_zip,'x',str(exe),'-o'+directory,'-y','-bso0'],check=True)
    extracted=Path(directory)
    for item in manifest:
        relative=Path(item['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        path=extracted/'app'/relative
        assert path.is_file(), f'Missing file: {relative}'
        assert path.stat().st_size==item['size'], f'Wrong size: {relative}'
        assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256'], f'Hash mismatch: {relative}'
    runtime=json.loads((extracted/'app/Sentinel.Desktop.runtimeconfig.json').read_text())
    assert len(runtime['runtimeOptions'].get('includedFrameworks',[])) >= 2
    # NSIS generates its uninstaller at installation time. 7-Zip's NSIS x64
    # decoder does not reconstruct it; its creation/removal is covered by
    # the real install/reinstall/uninstall lifecycle check under Wine.
    assert list((extracted/'app/Licenses').glob('*')), 'Missing runtime licenses'
print(f'PASS: Windows x64 EXE, checksum, {len(manifest)} payload hashes, bundled runtimes and license files.')
