import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..');
const require = createRequire(path.join(repositoryRoot, 'desktop/package.json'));
const asar = require('@electron/asar');

function normalizeArchivePath(value) {
  return value.replaceAll('\\', '/').replace(/^\/+/, '');
}

function packageRootFromArchivePath(value) {
  const normalized = normalizeArchivePath(value);
  if (!normalized.includes('node_modules/') || !normalized.endsWith('/package.json')) return null;
  return normalized.slice(0, -'/package.json'.length);
}

export async function auditPackagedNpmLicenses(archivePath, noticesPath, lockPath = path.join(repositoryRoot, 'desktop/package-lock.json')) {
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  const expected = new Map(Object.entries(lock.packages ?? {})
    .filter(([packagePath, entry]) => packagePath.startsWith('node_modules/') && entry.version && entry.dev !== true)
    .map(([packagePath, entry]) => [packagePath, entry]));
  const files = asar.listPackage(archivePath);
  const packageJsonPaths = files.filter((value) => packageRootFromArchivePath(value) !== null);
  const actual = new Map();

  for (const packageJsonPath of packageJsonPaths) {
    const packageRoot = packageRootFromArchivePath(packageJsonPath);
    const relativePackagePath = packageRoot;
    if (actual.has(relativePackagePath)) throw new Error(`Duplicate packaged npm manifest: ${relativePackagePath}`);
    const manifestPath = packageJsonPath.replace(/^[/\\]+/, '');
    const manifest = JSON.parse(asar.extractFile(archivePath, manifestPath).toString('utf8'));
    actual.set(relativePackagePath, { manifest, packageRoot, manifestPath });
  }

  const missing = [...expected.keys()].filter((packagePath) => !actual.has(packagePath));
  const unexpected = [...actual.keys()].filter((packagePath) => !expected.has(packagePath));
  if (missing.length || unexpected.length) {
    throw new Error(`Packaged npm modules differ from runtime lockfile; missing: ${missing.join(', ') || 'none'}; unexpected: ${unexpected.join(', ') || 'none'}.`);
  }

  const notices = await readFile(noticesPath, 'utf8');
  for (const [packagePath, locked] of expected) {
    const packaged = actual.get(packagePath).manifest;
    const expectedName = packagePath.slice(packagePath.lastIndexOf('node_modules/') + 'node_modules/'.length);
    if (packaged.name !== expectedName) throw new Error(`Packaged npm name mismatch at ${packagePath}: found ${packaged.name}.`);
    if (packaged.version !== locked.version) throw new Error(`Packaged npm version mismatch for ${packagePath}: expected ${locked.version}, found ${packaged.version}.`);
    if (!locked.license || packaged.license !== locked.license) throw new Error(`Packaged npm license metadata mismatch for ${packagePath}.`);
    const header = `${packaged.name}@${packaged.version} — ${locked.license}`;
    if (!notices.includes(header)) throw new Error(`Runtime license notice is missing package header: ${header}.`);

    const normalizedRoot = normalizeArchivePath(actual.get(packagePath).packageRoot);
    const directLicenseFiles = files.filter((value) => {
      const normalized = normalizeArchivePath(value);
      if (!normalized.startsWith(`${normalizedRoot}/`)) return false;
      const relative = normalized.slice(normalizedRoot.length + 1);
      return !relative.includes('/') && /^(license|licence|copying)(\.|$)/i.test(relative);
    });
    if (directLicenseFiles.length !== 1) throw new Error(`Expected one packaged license file for ${header}; found ${directLicenseFiles.length}.`);
    const licenseText = asar.extractFile(archivePath, directLicenseFiles[0].replace(/^[/\\]+/, '')).toString('utf8').trim();
    if (!licenseText || !notices.includes(licenseText)) throw new Error(`Runtime notices do not contain the packaged license text for ${header}.`);
  }

  return { packageCount: expected.size };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) throw new Error('Usage: node audit-packaged-npm-licenses.mjs <app.asar> <npm-runtime-notices.txt>');
    const result = await auditPackagedNpmLicenses(process.argv[2], process.argv[3]);
    console.log(`PASS: all ${result.packageCount} npm runtime packages in app.asar match lockfile metadata and bundled license notices.`);
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}
