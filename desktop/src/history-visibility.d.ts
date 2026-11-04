export interface VisibleHistoryEvent {
  risk?: string;
  [key: string]: unknown;
}

export function visibleHistoryEvents<T extends VisibleHistoryEvent>(events: T[], includeInformational?: boolean): T[];

