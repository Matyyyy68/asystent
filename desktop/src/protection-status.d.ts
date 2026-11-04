export interface ProtectionStatusView {
  title: string;
  description: string;
}

export interface MachineServiceStatus {
  available: boolean;
  reason?: string;
  state?: string;
  lastCollectionAtUtc?: string;
}

export function getProtectionStatus(
  status: any,
  firstRun: boolean,
  firstAssessment: 'waiting' | 'running' | 'complete' | 'failed',
  machineService?: MachineServiceStatus | null
): ProtectionStatusView;

