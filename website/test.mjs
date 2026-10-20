import fs from 'node:fs';
import assert from 'node:assert/strict';
const html = fs.readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const version = JSON.parse(fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;
assert.ok(html.includes(`/releases/download/v${version}/Sentinel.AI.Setup.${version}.exe`), `installer link must match website version ${version}`);
assert.ok(html.includes(`/releases/download/v${version}/Sentinel.AI.Setup.${version}.exe.sha256`), `checksum link must match website version ${version}`);
assert.ok(html.includes(`/releases/tag/v${version}`), `release notes link must match website version ${version}`);
for (const [, anchor] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(html.includes(`id="${anchor}"`), anchor);
for (const [, resource] of html.matchAll(/(?:src|href)="\.\/([^"]+)"/g)) {
  const asset = resource.startsWith('media/') ? `../${resource}` : resource;
  assert.ok(fs.existsSync(new URL(asset, import.meta.url)), resource);
}
for (const [, illustration] of html.matchAll(/src="\.\/media\/([^"]+\.png)"/g))
  assert.ok(fs.existsSync(new URL(`../media/${illustration}`, import.meta.url)), illustration);
assert.ok(html.includes('lang="pl"')); assert.ok(html.includes('alt="'));
console.log(`PASS: release ${version}, local links, anchors, assets, language and screenshot alternative text`);
