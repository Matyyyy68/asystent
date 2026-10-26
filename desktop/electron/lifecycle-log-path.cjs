const path = require('node:path');

function lifecycleLogDirectory({ smokeTest, isolatedDataRoot, localAppData, userDataPath }) {
  if (smokeTest && typeof isolatedDataRoot === 'string' && isolatedDataRoot.trim()) {
    return path.join(isolatedDataRoot, 'logs');
  }
  return path.join(localAppData || userDataPath, 'Sentinel AI', 'Logs');
}

module.exports = { lifecycleLogDirectory };
