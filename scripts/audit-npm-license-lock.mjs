import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function licenseDeclaration(value) {
  return value && typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
}

export function readNpmLockEntries(lockFile) {
  const lockRoot = path.dirname(lockFile);
  const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  const rows = [];

  for (const [packagePath, metadata] of Object.entries(lock.packages ?? {})) {
    if (!packagePath.startsWith('node_modules/') || !metadata.version) continue;
    const license = licenseDeclaration(metadata.license);
    const localManifestPath = path.join(lockRoot, packagePath, 'package.json');
    if (fs.existsSync(localManifestPath)) {
      const local = JSON.parse(fs.readFileSync(localManifestPath, 'utf8'));
      const localLicense = licenseDeclaration(local.license);
      if (String(local.version) !== String(metadata.version) || localLicense !== license) {
        throw new Error(`Installed package metadata differs from lockfile: ${packagePath}@${metadata.version} (installed ${local.version}, license '${localLicense}', lock '${license}')`);
      }
    }
    rows.push({
      PackagePath: packagePath,
      Version: String(metadata.version),
      LicenseDeclaration: license,
      DevelopmentDependency: String(Boolean(metadata.dev)),
    });
  }

  return rows;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const rows = readNpmLockEntries(process.argv[2]);
    process.stdout.write(rows.map(row => JSON.stringify(row)).join('\n'));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'License lock audit failed'}\n`);
    process.exitCode = 1;
  }
}
