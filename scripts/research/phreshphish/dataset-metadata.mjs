export function assertResearchDatasetMetadata(metadata, expectedRevision) {
  if (!metadata || typeof metadata !== 'object' || metadata.sha !== expectedRevision) {
    throw new Error(`Dataset revision changed: expected ${expectedRevision}, got ${metadata?.sha ?? 'missing'}`);
  }
  if (metadata.cardData?.license !== 'cc-by-4.0') {
    throw new Error('PhreshPhish license is not declared as CC BY 4.0; refusing anti-phishing research extraction.');
  }
}
