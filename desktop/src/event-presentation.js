const riskLabels = Object.freeze({
  Information: 'Informacja',
  Low: 'Niskie ryzyko',
  Moderate: 'Podejrzenie',
  High: 'Wysokie ryzyko',
  Critical: 'Poważne zagrożenie'
});

const statusLabels = Object.freeze({
  New: 'Nowe',
  Reviewed: 'Sprawdzone',
  FalsePositive: 'Oznaczone jako fałszywy alarm'
});

export function presentRisk(risk) {
  return riskLabels[risk] || 'Wymaga sprawdzenia';
}

export function presentEventStatus(status) {
  return statusLabels[status] || 'Status nieznany';
}
