export function visibleHistoryEvents(events, includeInformational = false) {
  if (includeInformational) return events;
  return events.filter(event => event.risk !== 'Information');
}
