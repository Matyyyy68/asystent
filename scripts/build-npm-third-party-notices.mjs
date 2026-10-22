import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..');
const desktopRoot = path.join(repositoryRoot, 'desktop');
const lock = JSON.parse(await readFile(path.join(desktopRoot, 'package-lock.json'), 'utf8'));
const runtimePackages = Object.entries(lock.packages)
  .filter(([name, entry]) => name.startsWith('node_modules/') && entry.version && entry.dev !== true)
  .sort(([left], [right]) => left.localeCompare(right));

if (runtimePackages.length === 0) throw new Error('No production npm dependencies were found in desktop/package-lock.json.');

const sections = [
  'Third-party licenses for Sentinel AI desktop runtime npm dependencies',
  'Generated from desktop/package-lock.json and installed package license files.',
  'These notices cover npm production dependencies bundled into the desktop application.',
  '',
];

for (const [lockPath, entry] of runtimePackages) {
  const packageDirectory = path.join(desktopRoot, lockPath);
  const packageMetadata = JSON.parse(await readFile(path.join(packageDirectory, 'package.json'), 'utf8'));
  if (typeof entry.license !== 'string' || !entry.license.trim()) {
    throw new Error(`Lockfile license declaration is missing for ${packageMetadata.name}@${entry.version}.`);
  }
  if (packageMetadata.version !== entry.version) {
    throw new Error(`Installed version mismatch for ${packageMetadata.name}: expected ${entry.version}, found ${packageMetadata.version}.`);
  }
  if (packageMetadata.license !== entry.license) {
    throw new Error(`Installed license metadata mismatch for ${packageMetadata.name}@${entry.version}: lockfile says '${entry.license}', package metadata says '${packageMetadata.license}'.`);
  }

  const files = await readdir(packageDirectory);
  const licenseFiles = files.filter((name) => /^(license|licence|copying)(\.|$)/i.test(name)).sort();
  if (licenseFiles.length !== 1) {
    throw new Error(`Expected exactly one top-level license file for ${packageMetadata.name}@${entry.version}; found ${licenseFiles.length}.`);
  }

  const licenseText = (await readFile(path.join(packageDirectory, licenseFiles[0]), 'utf8')).trim();
  if (!licenseText) throw new Error(`License file is empty for ${packageMetadata.name}@${entry.version}.`);
  sections.push(`${packageMetadata.name}@${entry.version} — ${entry.license}`);
  sections.push(licenseText, '');
}

const outputPath = path.join(repositoryRoot, 'artifacts', 'third-party-notices.txt');
await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${sections.join('\n')}\n`, 'utf8');
console.log(`Generated ${runtimePackages.length} npm runtime notices: ${outputPath}`);
