import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));

for (const script of ['extract-train-columns.mjs', 'extract-test-columns.mjs', 'extract-official-benchmarks.mjs']) {
  test(`${script} refuses to start without explicit network authorization`, () => {
    const result = spawnSync(process.execPath, [path.join(directory, script)], { encoding: 'utf8', timeout: 10_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Pass --allow-network/);
    assert.doesNotMatch(result.stderr, /fetch failed|ENOTFOUND|ECONN/);
  });
}
