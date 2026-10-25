import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { readNpmLockEntries } from './audit-npm-license-lock.mjs';

function fixture({ lockVersion = '1.2.3', installedVersion = lockVersion, lockLicense = 'MIT', installedLicense = lockLicense, installed = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-license-audit-'));
  const packagePath = 'node_modules/example-package';
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'fixture', version: '1.0.0' },
      [packagePath]: { version: lockVersion, license: lockLicense, dev: true },
    },
  }));
  if (installed) {
    const packageDir = path.join(root, packagePath);
    fs.mkdirSync(packageDir, { recursive: true });
    fs.writeFileSync(path.join(packageDir, 'package.json'), JSON.stringify({
      name: 'example-package', version: installedVersion, license: installedLicense,
    }));
  }
  return { root, lockFile: path.join(root, 'package-lock.json'), packagePath };
}

test('accepts matching installed package version and license', () => {
  const item = fixture();
  try {
    assert.deepEqual(readNpmLockEntries(item.lockFile), [{
      PackagePath: item.packagePath,
      Version: '1.2.3',
      LicenseDeclaration: 'MIT',
      DevelopmentDependency: 'true',
    }]);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects an installed version that differs from the lockfile', () => {
  const item = fixture({ installedVersion: '9.9.9' });
  try {
    assert.throws(() => readNpmLockEntries(item.lockFile), /metadata differs from lockfile/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects an installed license that differs from the lockfile', () => {
  const item = fixture({ installedLicense: 'ISC' });
  try {
    assert.throws(() => readNpmLockEntries(item.lockFile), /metadata differs from lockfile/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('keeps lockfile packages that are not installed locally', () => {
  const item = fixture({ installed: false });
  try {
    assert.equal(readNpmLockEntries(item.lockFile).length, 1);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});
