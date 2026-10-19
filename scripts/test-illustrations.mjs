import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../media/illustrations');
const files = fs.readdirSync(root, { recursive: true })
  .filter(file => typeof file === 'string' && file.endsWith('.png'))
  .map(file => path.join(root, file)).sort();
assert.equal(files.length, 63, `Expected 63 distinct illustration files; found ${files.length}`);
const installerProject = fs.readFileSync(path.resolve(root, '../../installer/Sentinel.Setup/Sentinel.Setup.csproj'), 'utf8');
for (const name of ['welcome', 'prepare', 'configure', 'installing', 'complete', 'error']) {
  assert.ok(installerProject.includes(`LogicalName="installer-${name}.png"`), `Installer is missing embedded ${name} illustration`);
  assert.ok(fs.existsSync(path.join(root, 'installer', `${name}.png`)), `Installer illustration not found: ${name}`);
}

function decodePng(file) {
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a', `${file}: invalid PNG signature`);
  let offset = 8, width, height, bitDepth, colorType;
  const compressed = [];
  while (offset < bytes.length) {
    const length = bytes.readUInt32BE(offset); offset += 4;
    const type = bytes.toString('ascii', offset, offset + 4); offset += 4;
    const data = bytes.subarray(offset, offset + length); offset += length + 4;
    if (type === 'IHDR') {
      width = data.readUInt32BE(0); height = data.readUInt32BE(4);
      bitDepth = data[8]; colorType = data[9];
    } else if (type === 'IDAT') compressed.push(data);
    else if (type === 'IEND') break;
  }
  assert.equal(bitDepth, 8, `${file}: expected 8-bit pixels`);
  assert.equal(colorType, 6, `${file}: expected RGBA color type`);
  assert.ok((width === 512 && (height === 341 || height === 342)), `${file}: unexpected dimensions ${width}x${height}`);

  const encoded = inflateSync(Buffer.concat(compressed));
  const stride = width * 4;
  const pixels = Buffer.alloc(height * stride);
  let src = 0;
  const paeth = (a, b, c) => {
    const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
    return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
  };
  for (let y = 0; y < height; y++) {
    const filter = encoded[src++], row = y * stride, prev = row - stride;
    for (let x = 0; x < stride; x++) {
      const raw = encoded[src++], left = x >= 4 ? pixels[row + x - 4] : 0;
      const up = y ? pixels[prev + x] : 0, upperLeft = y && x >= 4 ? pixels[prev + x - 4] : 0;
      const predictor = filter === 0 ? 0 : filter === 1 ? left : filter === 2 ? up
        : filter === 3 ? Math.floor((left + up) / 2)
          : filter === 4 ? paeth(left, up, upperLeft) : NaN;
      assert.ok(Number.isFinite(predictor), `${file}: unsupported PNG filter ${filter}`);
      pixels[row + x] = (raw + predictor) & 255;
    }
  }
  return { width, height, pixels };
}

const hashes = new Map();
for (const file of files) {
  const { width, height, pixels } = decodePng(file);
  let transparent = false;
  for (let alpha = 3; alpha < pixels.length; alpha += 4) {
    if (pixels[alpha] === 0) { transparent = true; break; }
  }
  assert.ok(transparent, `${file}: alpha channel exists but has no fully transparent pixels`);
  const hash = crypto.createHash('sha256').update(pixels).digest('hex');
  assert.ok(!hashes.has(hash), `${file}: exact duplicate of ${hashes.get(hash)}`);
  hashes.set(hash, file);
}
console.log(`PASS: ${files.length} unique RGBA PNG illustrations; real alpha, expected dimensions, and six installer resources verified.`);
