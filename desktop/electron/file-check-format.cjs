'use strict';

const signatureLabels = new Map([
  ['Valid', 'podpis prawidłowy'],
  ['NotSigned', 'brak podpisu'],
  ['HashMismatch', 'podpis niezgodny z plikiem'],
  ['NotTrusted', 'certyfikat podpisu niezaufany'],
  ['Unavailable', 'podpis niedostępny'],
  ['Unknown', 'stan podpisu nieznany']
]);

function formatFileCheckResult(result) {
  const name = typeof result?.name === 'string'
    ? result.name.replace(/[\r\n\t]/g, ' ').slice(0, 160) || '(bez nazwy)'
    : '(bez nazwy)';
  if (result?.error) return `Nie sprawdzono — ${name}`;
  const reputation = result?.matched ? 'dopasowanie lokalnej listy' : 'brak dopasowania lokalnej listy';
  const signature = signatureLabels.get(result?.signatureStatus) || signatureLabels.get('Unknown');
  return `${reputation}; ${signature} — ${name}`;
}

module.exports = { formatFileCheckResult };
