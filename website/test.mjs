import fs from 'node:fs';
import assert from 'node:assert/strict';
const html = fs.readFileSync(new URL('./index.html', import.meta.url), 'utf8');
for (const [, anchor] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(html.includes(`id="${anchor}"`), anchor);
for (const [, resource] of html.matchAll(/(?:src|href)="\.\/([^"]+)"/g)) assert.ok(fs.existsSync(new URL(resource, import.meta.url)), resource);
assert.ok(html.includes('lang="pl"')); assert.ok(html.includes('alt="'));
console.log('PASS: local links, anchors, assets, language and screenshot alternative text');
