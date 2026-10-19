import { cpSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = process.argv[2];
if (!['website', 'desktop'].includes(target)) throw new Error('Usage: node scripts/copy-media.mjs website|desktop');
const source = path.join(repo, 'media');
const destination = path.join(repo, target, 'public', 'media');
rmSync(destination, { recursive: true, force: true });
mkdirSync(path.dirname(destination), { recursive: true });
cpSync(source, destination, { recursive: true });
console.log(`Copied shared media to ${path.relative(repo, destination)}`);
