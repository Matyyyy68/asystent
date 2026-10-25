import test from 'node:test';
import assert from 'node:assert/strict';
import { assertResearchDatasetMetadata } from './dataset-metadata.mjs';

const revision = 'eca603e0ecd4f698f8d4d226c088659e72681239';

test('accepts only the pinned PhreshPhish revision declared CC BY 4.0', () => {
  assert.doesNotThrow(() => assertResearchDatasetMetadata({ sha: revision, cardData: { license: 'cc-by-4.0' } }, revision));
});

test('refuses an unpinned dataset revision', () => {
  assert.throws(
    () => assertResearchDatasetMetadata({ sha: 'changed', cardData: { license: 'cc-by-4.0' } }, revision),
    /Dataset revision changed/
  );
});

test('refuses missing or changed license metadata', () => {
  assert.throws(() => assertResearchDatasetMetadata({ sha: revision }, revision), /license is not declared/);
  assert.throws(
    () => assertResearchDatasetMetadata({ sha: revision, cardData: { license: 'other' } }, revision),
    /license is not declared/
  );
});
