const fs = require('node:fs'); const path = require('node:path'); const crypto = require('node:crypto'); const cp = require('node:child_process'); const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const version = fs.readFileSync(path.join(root,'eng/ProductVersion.props'),'utf8').match(/<VersionPrefix>([^<]+)<\/VersionPrefix>/)?.[1];
assert.match(version,/^\d+\.\d+\.\d+$/);
for (const name of ['desktop', 'website']) {
  const directory = path.join(root, name);
  assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8')).version, version, `${name} package version`);
  assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'package-lock.json'), 'utf8')).version, version, `${name} lockfile version`);
}
const appSource = fs.readFileSync(path.join(root, 'desktop/src/main.tsx'), 'utf8');
assert.ok(appSource.includes(`Sentinel AI User · ${version}`), 'visible desktop app version');
const manifest = JSON.parse(fs.readFileSync(path.join(root,'browser-extension/manifest.json'),'utf8'));
assert.equal(manifest.version,version); assert.equal(manifest.manifest_version,3);
assert.equal(manifest.minimum_chrome_version,'102');
assert.deepEqual(new Set(manifest.permissions),new Set(['webNavigation','downloads','tabs','nativeMessaging','storage']));
const digest=crypto.createHash('sha256').update(Buffer.from(manifest.key,'base64')).digest();
const id=[...digest.subarray(0,16)].map(n=>String.fromCharCode(97+(n>>4),97+(n&15))).join('');
assert.ok(fs.readFileSync(path.join(root,'src/Sentinel.UrlHost/NativeHostRegistration.cs'),'utf8').includes(`ExtensionId = "${id}"`));
for(const file of fs.readdirSync(path.join(root,'browser-extension')).filter(f=>f.endsWith('.js'))) cp.execFileSync('node',['--check',path.join(root,'browser-extension',file)]);
for(const dir of ['src/Sentinel.Core','src/Sentinel.Engine','src/Sentinel.UrlHost']) {
  const proj=fs.readdirSync(path.join(root,dir)).find(f=>f.endsWith('.csproj'));
  assert.ok(proj); assert.ok(!fs.readFileSync(path.join(root,dir,proj),'utf8').includes('<Version>'));
}
console.log(`PASS: ${version}, Chromium MV3, permissions, identity ${id}, JavaScript syntax`);
