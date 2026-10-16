#!/usr/bin/env python3
"""Build the tested, self-contained Windows release and an NSIS 3.11+ x64 installer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]

def run(args):
    subprocess.run([str(x) for x in args], cwd=ROOT, check=True)

def nsis_literal(value):
    return str(value).replace('$', '$$').replace('"', '$\\"')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dotnet', default='dotnet')
    parser.add_argument('--makensis', default='makensis')
    args = parser.parse_args()
    run(['python3', ROOT / 'scripts/check-browser-extension.py'])
    version = ET.parse(ROOT / 'eng/ProductVersion.props').findtext('./PropertyGroup/VersionPrefix')
    if not version or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Expected a numeric three-part application version')
    output = ROOT / 'artifacts/installer'
    output.mkdir(parents=True, exist_ok=True)
    exe = output / f'SentinelAI-{version}-win-x64-Setup.exe'
    build = Path(tempfile.mkdtemp(prefix='sentinel-installer-'))
    payload = build / 'payload'
    os.environ.setdefault('DOTNET_CLI_TELEMETRY_OPTOUT', '1')
    os.environ.setdefault('DOTNET_GENERATE_ASPNET_CERTIFICATE', 'false')
    run([args.dotnet, 'restore', 'Sentinel.sln', '--locked-mode', '--disable-parallel', '-m:1', '-nr:false'])
    run([args.dotnet, 'build', 'Sentinel.sln', '-c', 'Release', '--no-restore', '--disable-build-servers', '-m:1', '-nr:false'])
    run([args.dotnet, 'test', 'tests/Sentinel.Tests/Sentinel.Tests.csproj', '-c', 'Release', '--no-build', '--no-restore', '--disable-build-servers', '-m:1', '-nr:false'])
    run([args.dotnet, 'publish', 'src/Sentinel.Desktop/Sentinel.Desktop.csproj', '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=false', '-p:RestoreLockedMode=true', '--disable-build-servers', '-m:1', '-nr:false', '-o', payload])
    browser_host = build / 'browser-host'
    run([args.dotnet, 'publish', 'src/Sentinel.UrlHost/Sentinel.UrlHost.csproj', '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:RestoreLockedMode=true', '--disable-build-servers', '-m:1', '-nr:false', '-o', browser_host])
    shutil.copytree(browser_host, payload / 'BrowserHost')
    shutil.copytree(ROOT / 'browser-extension', payload / 'BrowserExtension')
    for pdb in payload.rglob('*.pdb'):
        pdb.unlink()
    shutil.copy2(ROOT / 'installer/Pomoc.html', payload)
    shutil.copy2(ROOT / 'THIRD_PARTY_NOTICES.md', payload)
    for name in ['Sentinel.Desktop.exe', 'Sentinel.Desktop.dll', 'Sentinel.Core.dll', 'coreclr.dll', 'e_sqlite3.dll',
                 'BrowserHost/Sentinel.UrlHost.exe', 'BrowserExtension/manifest.json', 'BrowserExtension/background.js']:
        if not (payload / name).is_file():
            raise RuntimeError(f'Missing required application file: {name}')
    runtime = json.loads((payload / 'Sentinel.Desktop.runtimeconfig.json').read_text())
    if len(runtime['runtimeOptions'].get('includedFrameworks', [])) < 2:
        raise RuntimeError('Expected self-contained .NET and Windows Desktop runtimes')
    nuget = Path(os.environ.get('NUGET_PACKAGES', str(Path.home() / '.nuget/packages')))
    licenses = payload / 'Licenses'
    licenses.mkdir()
    for framework in runtime['runtimeOptions']['includedFrameworks']:
        package = framework['name'].lower() + '.runtime.win-x64'
        folder = nuget / package / framework['version']
        texts = [p for p in folder.iterdir() if p.is_file() and (p.name.lower().startswith('license') or 'notices' in p.name.lower())]
        if not any(p.name.lower().startswith('license') for p in texts):
            raise RuntimeError(f'Missing runtime license in {folder}')
        for source in texts:
            shutil.copy2(source, licenses / (package + '-' + source.name))
    files = sorted(p for p in payload.rglob('*') if p.is_file())
    manifest = [{'path': p.relative_to(payload).as_posix(), 'size': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
    remove = build / 'remove-files.nsh'
    lines = []
    for p in files:
        relative = nsis_literal(str(p.relative_to(payload)).replace('/', '\\'))
        lines.append(f'Delete "$INSTDIR\\app\\{relative}"')
    for p in sorted((p for p in payload.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        relative = nsis_literal(str(p.relative_to(payload)).replace('/', '\\'))
        lines.append(f'RMDir "$INSTDIR\\app\\{relative}"')
    lines.append('RMDir "$INSTDIR\\app"')
    remove.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    option = '/' if os.name == 'nt' else '-'
    definitions = {'APP_VERSION': version, 'PAYLOAD_DIR': payload, 'REMOVE_MANIFEST': remove, 'OUTPUT_EXE': exe,
                   'ESTIMATED_KB': (sum(p.stat().st_size for p in files) + 1023) // 1024}
    run([args.makensis, option+'WX', option+'V3', *[f'{option}D{k}={v}' for k,v in definitions.items()], ROOT / 'installer/SentinelAI.nsi'])
    (output / 'payload-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    (output / (exe.name+'.sha256')).write_text(f'{digest}  {exe.name}\n', encoding='ascii')
    shutil.copy2(ROOT / 'installer/Pomoc.html', output / 'Pierwsze-kroki.html')
    shutil.rmtree(build)
    print(f'Installer: {exe}\nSHA256: {digest}\nPayload files: {len(files)}')

if __name__ == '__main__':
    main()
