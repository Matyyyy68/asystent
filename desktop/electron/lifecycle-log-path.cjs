const path = require('node:path');

function isolatedElectronPaths(dataRoot) {
  const root = path.resolve(dataRoot);
  return {
    userData: path.join(root, 'electron-user-data'),
    sessionData: path.join(root, 'electron-session-data')
  };
}

function lifecycleLogDirectory({ smokeTest, isolatedDataRoot, localAppData, userDataPath }) {
  if (smokeTest && typeof isolatedDataRoot === 'string' && isolatedDataRoot.trim()) {
    return path.join(isolatedDataRoot, 'logs');
  }
  return path.join(localAppData || userDataPath, 'Sentinel AI', 'Logs');
}

module.exports = { isolatedElectronPaths, lifecycleLogDirectory };
