export interface ProtectionStatusView {
  title: string;
  description: string;
}

export function getProtectionStatus(
  status: any,
  firstRun: boolean,
  firstAssessment: 'waiting' | 'running' | 'complete' | 'failed'
): ProtectionStatusView;
