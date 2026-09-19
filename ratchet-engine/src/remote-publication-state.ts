const DEVICE_ID_PATTERN = /^device1:[a-z2-7]{52}$/;
const MAX_REMOTE_DEVICES = 100_000;
const MAX_PUBLICATION_SEQUENCE = Number.MAX_SAFE_INTEGER;

export type RemotePublicationSequenceState =
  readonly (readonly [string, number])[];

function validateDeviceId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !DEVICE_ID_PATTERN.test(value)) {
    throw new Error(`${field} must be a canonical GhostLink DeviceID`);
  }
  return value;
}

function validateSequence(value: unknown, field: string): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) <= 0 ||
    (value as number) > MAX_PUBLICATION_SEQUENCE
  ) {
    throw new Error(`${field} is outside the supported range`);
  }
  return value as number;
}

export function parseRemotePublicationSequences(
  value: unknown
): RemotePublicationSequenceState {
  if (!Array.isArray(value) || value.length > MAX_REMOTE_DEVICES) {
    throw new Error('remote publication sequences must be a bounded array');
  }

  const seen = new Set<string>();
  const entries = value.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(
        `remote publication sequences[${index}] must contain two values`
      );
    }

    const deviceId = validateDeviceId(
      entry[0],
      `remote publication sequences[${index}][0]`
    );
    if (seen.has(deviceId)) {
      throw new Error('remote publication sequences contain a duplicate DeviceID');
    }
    seen.add(deviceId);

    return [
      deviceId,
      validateSequence(
        entry[1],
        `remote publication sequences[${index}][1]`
      ),
    ] as const;
  });

  return entries;
}

export class MemoryRemotePublicationSequenceStore {
  private readonly sequences = new Map<string, number>();

  constructor(state: RemotePublicationSequenceState = []) {
    for (const [deviceId, sequence] of parseRemotePublicationSequences(state)) {
      this.sequences.set(deviceId, sequence);
    }
  }

  observe(deviceId: string, sequence: number): number {
    validateDeviceId(deviceId, 'remote DeviceID');
    validateSequence(sequence, 'remote publication sequence');

    const current = this.sequences.get(deviceId);
    if (current !== undefined && sequence < current) {
      throw new Error('remote publication sequence regressed');
    }
    if (current === undefined || sequence > current) {
      this.sequences.set(deviceId, sequence);
    }
    return this.sequences.get(deviceId)!;
  }

  highest(deviceId: string): number | null {
    validateDeviceId(deviceId, 'remote DeviceID');
    return this.sequences.get(deviceId) ?? null;
  }

  remove(deviceId: string): boolean {
    validateDeviceId(deviceId, 'remote DeviceID');
    return this.sequences.delete(deviceId);
  }

  exportState(): RemotePublicationSequenceState {
    return [...this.sequences.entries()].sort(([left], [right]) =>
      left.localeCompare(right)
    );
  }

  static fromState(
    state: RemotePublicationSequenceState
  ): MemoryRemotePublicationSequenceStore {
    return new MemoryRemotePublicationSequenceStore(state);
  }
}
