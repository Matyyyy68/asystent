'use strict';

function requestedFileCheck(args) {
  if (!Array.isArray(args)) return null;
  const index = args.indexOf('--check-file');
  const candidate = index >= 0 ? args[index + 1] : null;
  return typeof candidate === 'string' && candidate.length > 0 && candidate.length <= 32760
    && !candidate.startsWith('--') ? candidate : null;
}

module.exports = { requestedFileCheck };
