import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const DATASET = 'phreshphish/phreshphish';
const REVISION = 'eca603e0ecd4f698f8d4d226c088659e72681239';
const outputDirectory = process.argv[2];
if (!outputDirectory) throw new Error('Pass a unique temporary output directory.');

const metadata = await fetch(`https://huggingface.co/api/datasets/${DATASET}`);
if (!metadata.ok || (await metadata.json()).sha !== REVISION) {
  throw new Error('PhreshPhish revision changed; refusing benchmark extraction.');
}
const baseUrl = `https://huggingface.co/datasets/${DATASET}/resolve/${REVISION}/`;
const groups = [
  { name: 'benchmark-005', count: 586 },
  { name: 'benchmark-010', count: 296 },
  { name: 'benchmark-050', count: 59 },
  { name: 'benchmark-100', count: 29 },
  { name: 'benchmark-500', count: 5 },
];
const targets = [
  { name: 'benign.txt', relativePath: 'benchmark/benign.txt' },
  ...groups.flatMap(group => Array.from({ length: group.count }, (_, index) => ({
    name: `${group.name}/${index}.txt`,
    relativePath: `benchmark/${group.name}/${index}.txt`,
  }))),
];
await mkdir(outputDirectory, { recursive: false });
const entries = [];
let next = 0;
async function worker() {
  while (next < targets.length) {
    const target = targets[next++];
    const response = await fetch(baseUrl + target.relativePath);
    if (!response.ok) throw new Error(`Could not fetch pinned benchmark list ${target.name}: HTTP ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > 8 * 1024 * 1024) throw new Error(`Benchmark list unexpectedly large: ${target.name}`);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const ids = text.trim().split(/\s+/);
    if (!text.trim() || ids.some(id => !/^[a-f0-9]{64}$/i.test(id)) || new Set(ids).size !== ids.length) {
      throw new Error(`Malformed or duplicate record ID in ${target.name}`);
    }
    const destination = path.join(outputDirectory, target.name);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, bytes, { flag: 'wx' });
    entries.push({ file: target.name, rows: ids.length, sha256: createHash('sha256').update(bytes).digest('hex').toUpperCase() });
  }
}
await Promise.all(Array.from({ length: 12 }, worker));
entries.sort((a, b) => a.file.localeCompare(b.file));
const benign = entries.find(entry => entry.file === 'benign.txt');
if (benign.rows !== 90_262 || entries.length !== 976) {
  throw new Error('Official PhreshPhish benchmark inventory or shared benign list changed.');
}
const finalMetadata = await fetch(`https://huggingface.co/api/datasets/${DATASET}`);
if (!finalMetadata.ok || (await finalMetadata.json()).sha !== REVISION) {
  throw new Error('Dataset revision changed during benchmark-list extraction.');
}
const manifest = {
  dataset: DATASET,
  revision: REVISION,
  licenseScope: 'anti-phishing research only',
  groups,
  files: entries,
  inventorySha256: createHash('sha256').update(entries.map(entry => `${entry.file}\t${entry.rows}\t${entry.sha256}\n`).join('')).digest('hex').toUpperCase(),
  urlsOpened: 0,
};
await writeFile(path.join(outputDirectory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ revision: REVISION, files: entries.length, benignRows: benign.rows, inventorySha256: manifest.inventorySha256 }));
