export function buildIncidentAnalysisContext(group: {
  kind?: string;
  events?: ReadonlyArray<{
    id?: string | number;
    eventId?: string;
    risk?: string;
    riskScore?: number | null;
    evidenceCodes?: ReadonlyArray<string>;
  }>;
}): string;
