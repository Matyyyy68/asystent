export interface HistoryEvent {
  id: number;
  timestamp: string;
  risk: string;
  category: string;
  application: string;
  explanation: string;
  recommendation: string;
  status: string;
  source?: string | null;
  correlationId?: string | null;
  confidence?: number | null;
  ruleVersion?: string | null;
  schemaVersion?: number;
  evidenceCodes?: string[];
}

export interface HistoryGroup {
  key: string;
  kind: 'domain' | 'process' | 'single';
  events: HistoryEvent[];
}

export function groupHistoryEvents(events: readonly HistoryEvent[], query?: string): HistoryGroup[];
