'use strict';

async function requestEnterpriseContextConsent(getEnterpriseStatus, showConsentDialog) {
  const status = await getEnterpriseStatus();
  if (!status?.paired || !status.sharingMetadata || typeof status.server !== 'string' || !status.server)
    return false;
  return (await showConsentDialog(status.server)) === true;
}

module.exports = { requestEnterpriseContextConsent };
