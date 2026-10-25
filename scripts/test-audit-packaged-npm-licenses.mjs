import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { auditPackagedNpmLicenses } from './audit-packaged-npm-licenses.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const require = createRequire(path.join(repositoryRoot, 'desktop/package.json'));
const asar = require('@electron/asar');

async function fixture({ notice = true, archiveVersion = '1.2.3', extraPackage = false, omitExtraFromLock = false,
  packageName = 'example-package', packagePath = 'node_modules/example-package' } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-packaged-license-'));
  const app = path.join(root, 'app');
  const packageDir = path.join(app, packagePath);
  fs.mkdirSync(packageDir, { recursive: true });
  fs.writeFileSync(path.join(packageDir, 'package.json'), JSON.stringify({
    name: packageName, version: archiveVersion, license: 'MIT',
  }));
  fs.writeFileSync(path.join(packageDir, 'LICENSE'), 'MIT License\nFixture license terms.\n');

  if (extraPackage) {
    const extra = path.join(app, 'node_modules/extra-package');
    fs.mkdirSync(extra, { recursive: true });
    fs.writeFileSync(path.join(extra, 'package.json'), JSON.stringify({
      name: 'extra-package', version: '1.0.0', license: 'ISC',
    }));
    fs.writeFileSync(path.join(extra, 'LICENSE'), 'ISC License\nExtra fixture terms.\n');
  }

  const archivePath = path.join(root, 'app.asar');
  await asar.createPackage(app, archivePath);
  const lockPath = path.join(root, 'package-lock.json');
  const packages = {
    '': { name: 'fixture', version: '1.0.0' },
    [packagePath]: { version: '1.2.3', license: 'MIT', dev: false },
  };
  if (extraPackage && !omitExtraFromLock) packages['node_modules/extra-package'] = { version: '1.0.0', license: 'ISC', dev: false };
  fs.writeFileSync(lockPath, JSON.stringify({ lockfileVersion: 3, packages }));
  const sections = notice
    ? [`${packageName}@1.2.3 — MIT`, 'MIT License\nFixture license terms.']
    : [`${packageName}@1.2.3 — MIT`, 'MIT License\nDifferent license terms.'];
  if (extraPackage) sections.push('extra-package@1.0.0 — ISC', 'ISC License\nExtra fixture terms.');
  const noticesPath = path.join(root, 'npm-runtime.txt');
  fs.writeFileSync(noticesPath, sections.join('\n\n'));
  return { root, archivePath, noticesPath, lockPath };
}

test('accepts the exact runtime modules, lock metadata, and packaged license text', async () => {
  const item = await fixture();
  try {
    assert.deepEqual(await auditPackagedNpmLicenses(item.archivePath, item.noticesPath, item.lockPath), { packageCount: 1 });
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('matches scoped packages nested in the app archive to their lockfile path', async () => {
  const item = await fixture({ packagePath: 'node_modules/parent/node_modules/@scope/example', packageName: '@scope/example' });
  try {
    assert.deepEqual(await auditPackagedNpmLicenses(item.archivePath, item.noticesPath, item.lockPath), { packageCount: 1 });
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects a package whose shipped license text is missing from notices', async () => {
  const item = await fixture({ notice: false });
  try {
    await assert.rejects(auditPackagedNpmLicenses(item.archivePath, item.noticesPath, item.lockPath), /do not contain the packaged license text/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects an archive that does not match the runtime lockfile set', async () => {
  const item = await fixture({ extraPackage: true, omitExtraFromLock: true });
  try {
    await assert.rejects(auditPackagedNpmLicenses(item.archivePath, item.noticesPath, item.lockPath), /differ from runtime lockfile/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects a shipped runtime package at a version different from the lockfile', async () => {
  const item = await fixture({ archiveVersion: '9.9.9' });
  try {
    await assert.rejects(auditPackagedNpmLicenses(item.archivePath, item.noticesPath, item.lockPath), /version mismatch/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});
