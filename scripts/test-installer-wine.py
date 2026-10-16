import pathlib,json,os,subprocess,hashlib,time,argparse,tempfile,xml.etree.ElementTree as ET
parser=argparse.ArgumentParser(description='Test install/reinstall/uninstall in an already prepared, disposable Wine prefix.')
parser.add_argument('--environment',type=pathlib.Path,required=True)
parser.add_argument('--installer',type=pathlib.Path,required=True)
parser.add_argument('--mutex-helper',type=pathlib.Path)
args=parser.parse_args()
base=args.environment.resolve().parent
assert base.parent == pathlib.Path(tempfile.gettempdir()).resolve() and base.name.startswith('sentinel-installer-'), 'Use a disposable Sentinel test directory under the temporary directory'
env=os.environ.copy();env.update(json.loads(args.environment.read_text()));wine=env['WINELOADER']
assert pathlib.Path(env['WINEPREFIX']).resolve().parent == base, 'Wine profile must belong to this test directory'
installer=args.installer.resolve()
manifest=json.loads((installer.parent/'payload-manifest.json').read_text())
def run(*args,expected=0):
 r=subprocess.run([wine,*map(str,args)],env=env,capture_output=True,text=True,timeout=55)
 assert r.returncode==expected,(args,r.returncode,r.stdout[-1000:],r.stderr[-1000:])
 return r
run(installer,'/S');print('PASS: silent install',flush=True)
prefix=pathlib.Path(env['WINEPREFIX']);roots=list(prefix.glob('drive_c/users/*/AppData/Local/Programs/Sentinel AI'));assert len(roots)==1;installed=roots[0]
for item in manifest:
 p=installed/'app'/item['path'];assert p.is_file(),p
 assert hashlib.sha256(p.read_bytes()).hexdigest()==item['sha256'],p
assert (installed/'Odinstaluj.exe').is_file()
local=installed.parent.parent;profile=local.parent.parent
assert (profile/'Desktop/Sentinel AI.lnk').is_file()
assert (profile/'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Sentinel AI/Sentinel AI.lnk').is_file()
registry=r'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI'
product_version=ET.parse(pathlib.Path(__file__).resolve().parents[1]/'eng/ProductVersion.props').findtext('./PropertyGroup/VersionPrefix')
r=run('reg','query',registry);assert product_version in r.stdout;assert 'Odinstaluj.exe' in r.stdout
print(f'PASS: {len(manifest)} installed hashes, uninstaller, shortcuts and registration',flush=True)
if args.mutex_helper:
 ready=base/'mutex.ready';release=base/'mutex.release'
 ready.unlink(missing_ok=True);release.unlink(missing_ok=True)
 with open(base/'mutex.log','w') as log:
  helper=subprocess.Popen([wine,str(args.mutex_helper.resolve()),'/S'],env=env,stdout=log,stderr=log)
  try:
   deadline=time.monotonic()+10
   while not ready.exists() and time.monotonic()<deadline: time.sleep(.1)
   assert ready.exists(), 'Mutex helper did not start'
   run(installer,'/S',expected=2)
   run(installed/'Odinstaluj.exe','/S')
   assert (installed/'app/Sentinel.Desktop.exe').is_file()
   assert (installed/'Odinstaluj.exe').is_file()
   assert (profile/'Desktop/Sentinel AI.lnk').is_file()
   assert (profile/'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Sentinel AI/Sentinel AI.lnk').is_file()
   run('reg','query',registry)
   print('PASS: running-application mutex blocks installation and uninstallation',flush=True)
  finally:
   release.write_text('release');helper.wait(timeout=10)
data=local/'SentinelAI/Data';data.mkdir(parents=True,exist_ok=True);(data/'keep.txt').write_text('synthetic user data')
credential=local/'SentinelAI/enterprise-credential.bin';credential.write_bytes(b'synthetic protected credential')
private=installed/'app/my-notes.txt';private.write_text('private non-package file')
run(installer,'/S');assert (data/'keep.txt').read_text()=='synthetic user data';assert private.read_text()=='private non-package file'
print('PASS: reinstall preserves data',flush=True)
run(installed/'Odinstaluj.exe','/S')
deadline=time.monotonic()+25
while (installed/'app/Sentinel.Desktop.exe').exists() and time.monotonic()<deadline: time.sleep(.2)
assert all(not (installed/'app'/item['path']).exists() for item in manifest)
assert (data/'keep.txt').read_text()=='synthetic user data';assert private.read_text()=='private non-package file'
assert not credential.exists()
assert not (profile/'Desktop/Sentinel AI.lnk').exists()
assert not (profile/'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Sentinel AI').exists()
run('reg','query',registry,expected=1)
print('PASS: uninstall removes only packaged files, shortcuts and registry; preserves personal files and history',flush=True)
(base/'lifecycle-passed.txt').write_text('Install, manifest hashes, registry, shortcuts, reinstall, uninstall and data preservation passed under Wine 10.\n')
