const LIFECYCLE_STATE_VERSION = 1;
const MAX_PUBLICATION_SEQUENCE = Number.MAX_SAFE_INTEGER;
const MAX_PREKEY_ID = 0x7fff_ffff;
const MAX_ONE_TIME_BUNDLES = 256;
export const MAX_RETIRED_GENERATIONS = 32;
const MAX_PUBLIC_PAYLOAD_BYTES = 1024 * 1024;

export interface PreKeyGenerationState {
  readonly sequence: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly signedPreKeyId: number;
  readonly lastResortKyberPreKeyId: number;
  readonly oneTimeKeyIds: readonly (readonly [number, number])[];
  readonly publicPayload: string | null;
  readonly publishedAt: number | null;
  readonly retiredAt: number | null;
}

export interface PreKeyLifecycleState {
  readonly version: 1;
  readonly publicationSequence: number;
  readonly pending: PreKeyGenerationState | null;
  readonly active: PreKeyGenerationState | null;
  readonly retired: readonly PreKeyGenerationState[];
}

function requireObject(
  value: unknown,
  context: string
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactFields(
  document: Record<string, unknown>,
  fields: readonly string[],
  context: string
): void {
  const actual = Object.keys(document).sort().join(',');
  const expected = [...fields].sort().join(',');
  if (actual !== expected) {
    throw new Error(`${context} fields do not match version 1`);
  }
}

function requireInteger(
  value: unknown,
  field: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    throw new Error(`${field} is outside the supported range`);
  }
  return value as number;
}

function requireNullableTimestamp(value: unknown, field: string): number | null {
  if (value === null) {
    return null;
  }
  return requireInteger(value, field, 0);
}

function requirePublicPayload(value: unknown, field: string): string | null {
  if (value === null) {
    return null;
  }
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_PUBLIC_PAYLOAD_BYTES
  ) {
    throw new Error(`${field} must be bounded non-empty UTF-8 text or null`);
  }
  return value;
}

function parseOneTimeKeyIds(
  value: unknown,
  field: string
): Array<readonly [number, number]> {
  if (!Array.isArray(value) || value.length > MAX_ONE_TIME_BUNDLES) {
    throw new Error(`${field} must be a bounded array`);
  }

  const preKeyIds = new Set<number>();
  const kyberIds = new Set<number>();

  return value.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(`${field}[${index}] must contain two identifiers`);
    }

    const preKeyId = requireInteger(
      entry[0],
      `${field}[${index}][0]`,
      1,
      MAX_PREKEY_ID
    );
    const kyberPreKeyId = requireInteger(
      entry[1],
      `${field}[${index}][1]`,
      1,
      MAX_PREKEY_ID
    );

    if (preKeyIds.has(preKeyId)) {
      throw new Error(`${field} contains a duplicate EC pre-key identifier`);
    }
    if (kyberIds.has(kyberPreKeyId)) {
      throw new Error(`${field} contains a duplicate Kyber identifier`);
    }

    preKeyIds.add(preKeyId);
    kyberIds.add(kyberPreKeyId);
    return [preKeyId, kyberPreKeyId] as const;
  });
}

function parseGeneration(
  value: unknown,
  field: string
): PreKeyGenerationState {
  const document = requireObject(value, field);
  requireExactFields(
    document,
    [
      'sequence',
      'createdAt',
      'expiresAt',
      'signedPreKeyId',
      'lastResortKyberPreKeyId',
      'oneTimeKeyIds',
      'publicPayload',
      'publishedAt',
      'retiredAt',
    ],
    field
  );

  const sequence = requireInteger(
    document.sequence,
    `${field}.sequence`,
    1,
    MAX_PUBLICATION_SEQUENCE
  );
  const createdAt = requireInteger(
    document.createdAt,
    `${field}.createdAt`,
    0
  );
  const expiresAt = requireInteger(
    document.expiresAt,
    `${field}.expiresAt`,
    0
  );
  if (expiresAt <= createdAt) {
    throw new Error(`${field}.expiresAt must be later than createdAt`);
  }

  const publishedAt = requireNullableTimestamp(
    document.publishedAt,
    `${field}.publishedAt`
  );
  const retiredAt = requireNullableTimestamp(
    document.retiredAt,
    `${field}.retiredAt`
  );
  if (retiredAt !== null && publishedAt === null) {
    throw new Error(`${field} cannot retire before publication`);
  }
  if (
    retiredAt !== null &&
    publishedAt !== null &&
    retiredAt < publishedAt
  ) {
    throw new Error(`${field}.retiredAt precedes publishedAt`);
  }

  const oneTimeKeyIds = parseOneTimeKeyIds(
    document.oneTimeKeyIds,
    `${field}.oneTimeKeyIds`
  );
  const lastResortKyberPreKeyId = requireInteger(
    document.lastResortKyberPreKeyId,
    `${field}.lastResortKyberPreKeyId`,
    1,
    MAX_PREKEY_ID
  );
  if (
    oneTimeKeyIds.some(
      ([, kyberPreKeyId]) => kyberPreKeyId === lastResortKyberPreKeyId
    )
  ) {
    throw new Error(
      `${field} last-resort Kyber ID must not be a one-time Kyber ID`
    );
  }

  return {
    sequence,
    createdAt,
    expiresAt,
    signedPreKeyId: requireInteger(
      document.signedPreKeyId,
      `${field}.signedPreKeyId`,
      1,
      MAX_PREKEY_ID
    ),
    lastResortKyberPreKeyId,
    oneTimeKeyIds,
    publicPayload: requirePublicPayload(
      document.publicPayload,
      `${field}.publicPayload`
    ),
    publishedAt,
    retiredAt,
  };
}

function ensureGenerationRole(
  generation: PreKeyGenerationState,
  role: 'pending' | 'active' | 'retired'
): void {
  if (role === 'pending') {
    if (generation.publishedAt !== null || generation.retiredAt !== null) {
      throw new Error('pending generation must not be published or retired');
    }
    return;
  }

  if (generation.publishedAt === null) {
    throw new Error(`${role} generation must have publishedAt`);
  }

  if (role === 'active' && generation.retiredAt !== null) {
    throw new Error('active generation must not be retired');
  }
  if (role === 'retired' && generation.retiredAt === null) {
    throw new Error('retired generation must have retiredAt');
  }
}

export function emptyPreKeyLifecycleState(): PreKeyLifecycleState {
  return {
    version: 1,
    publicationSequence: 0,
    pending: null,
    active: null,
    retired: [],
  };
}

export function parsePreKeyLifecycleState(
  value: unknown
): PreKeyLifecycleState {
  const document = requireObject(value, 'pre-key lifecycle');
  requireExactFields(
    document,
    ['version', 'publicationSequence', 'pending', 'active', 'retired'],
    'pre-key lifecycle'
  );

  if (document.version !== LIFECYCLE_STATE_VERSION) {
    throw new Error('unsupported pre-key lifecycle version');
  }

  const publicationSequence = requireInteger(
    document.publicationSequence,
    'pre-key lifecycle publicationSequence',
    0,
    MAX_PUBLICATION_SEQUENCE
  );

  const pending =
    document.pending === null
      ? null
      : parseGeneration(document.pending, 'pre-key lifecycle pending');
  const active =
    document.active === null
      ? null
      : parseGeneration(document.active, 'pre-key lifecycle active');

  if (
    !Array.isArray(document.retired) ||
    document.retired.length > MAX_RETIRED_GENERATIONS
  ) {
    throw new Error('pre-key lifecycle retired must be a bounded array');
  }
  const retired = document.retired.map((item, index) =>
    parseGeneration(item, `pre-key lifecycle retired[${index}]`)
  );

  if (pending !== null) {
    ensureGenerationRole(pending, 'pending');
    if (pending.sequence !== publicationSequence) {
      throw new Error('pending sequence must equal publicationSequence');
    }
  }
  if (active !== null) {
    ensureGenerationRole(active, 'active');
  }
  for (const generation of retired) {
    ensureGenerationRole(generation, 'retired');
  }

  const generations = [
    ...(pending === null ? [] : [pending]),
    ...(active === null ? [] : [active]),
    ...retired,
  ];
  const sequences = new Set<number>();
  for (const generation of generations) {
    if (generation.sequence > publicationSequence) {
      throw new Error('generation sequence exceeds publicationSequence');
    }
    if (sequences.has(generation.sequence)) {
      throw new Error('pre-key lifecycle contains duplicate generation sequence');
    }
    sequences.add(generation.sequence);
  }

  if (
    pending !== null &&
    active !== null &&
    pending.sequence <= active.sequence
  ) {
    throw new Error('pending sequence must be newer than active sequence');
  }

  return {
    version: 1,
    publicationSequence,
    pending,
    active,
    retired,
  };
}

export function clonePreKeyLifecycleState(
  state: PreKeyLifecycleState
): PreKeyLifecycleState {
  return parsePreKeyLifecycleState({
    version: state.version,
    publicationSequence: state.publicationSequence,
    pending:
      state.pending === null
        ? null
        : {
            ...state.pending,
            oneTimeKeyIds: state.pending.oneTimeKeyIds.map(
              ([preKeyId, kyberPreKeyId]) => [preKeyId, kyberPreKeyId]
            ),
          },
    active:
      state.active === null
        ? null
        : {
            ...state.active,
            oneTimeKeyIds: state.active.oneTimeKeyIds.map(
              ([preKeyId, kyberPreKeyId]) => [preKeyId, kyberPreKeyId]
            ),
          },
    retired: state.retired.map((generation) => ({
      ...generation,
      oneTimeKeyIds: generation.oneTimeKeyIds.map(
        ([preKeyId, kyberPreKeyId]) => [preKeyId, kyberPreKeyId]
      ),
    })),
  });
}

export class MemoryPreKeyLifecycleStore {
  private state: PreKeyLifecycleState;

  constructor(state: PreKeyLifecycleState = emptyPreKeyLifecycleState()) {
    this.state = clonePreKeyLifecycleState(state);
  }

  snapshot(): PreKeyLifecycleState {
    return clonePreKeyLifecycleState(this.state);
  }

  replace(state: PreKeyLifecycleState): void {
    this.state = clonePreKeyLifecycleState(state);
  }

  exportState(): PreKeyLifecycleState {
    return this.snapshot();
  }

  static fromState(state: PreKeyLifecycleState): MemoryPreKeyLifecycleStore {
    return new MemoryPreKeyLifecycleStore(state);
  }
}
