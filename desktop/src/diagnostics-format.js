export function formatExitCode(value) {
  if (typeof value !== 'string' || !/^-?\d+$/.test(value)) return value ?? 'brak';
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric < -0x80000000 || numeric > 0xffffffff) return value;
  const unsigned = numeric < 0 ? numeric >>> 0 : numeric;
  return `${value} (0x${unsigned.toString(16).toUpperCase().padStart(8, '0')})`;
}
