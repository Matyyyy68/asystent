const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('manual-analysis disclosure matches the active detection rule version', () => {
  const enginePath = path.resolve(__dirname, '../../src/Sentinel.Core/Analysis/ThreatAnalysisEngine.cs');
  const uiPath = path.resolve(__dirname, '../src/main.tsx');
  const engine = fs.readFileSync(enginePath, 'utf8');
  const ui = fs.readFileSync(uiPath, 'utf8');
  const ruleVersion = /public const string RulesVersion = "([^"]+)";/.exec(engine)?.[1];

  assert.ok(ruleVersion, 'ThreatAnalysisEngine must declare its active rules version.');
  assert.ok(ui.includes(`Bieżąca wersja \`${ruleVersion}\``),
    `Manual-analysis disclosure must identify active rule version ${ruleVersion}.`);
});
