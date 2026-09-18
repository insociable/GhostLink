import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
} from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

import {
  parsePartyStoresState,
  type PartyStoresState,
} from './stores.js';

const VAULT_ENVELOPE_VERSION = 1;
const LEGACY_VAULT_PAYLOAD_VERSION = 1;
const VAULT_PAYLOAD_VERSION = 2;
const VAULT_CIPHER = 'aes-256-gcm';
const MASTER_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAX_VAULT_BYTES = 16 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = 12 * 1024 * 1024;
const MAX_REVISION = Number.MAX_SAFE_INTEGER;
const AAD = Buffer.from('ghostlink-ratchet-state-v1', 'utf8');
const STATE_ID_PATTERN = /^[0-9a-f]{32}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

interface VaultOwner {
  readonly name: string;
  readonly deviceId: number;
}

interface VaultStateMetadata {
  readonly stateId: string;
  readonly revision: number;
  readonly previousDigest: string | null;
}

interface LegacyVaultPayload {
  readonly version: 1;
  readonly owner: VaultOwner;
  readonly stores: PartyStoresState;
}

interface RollbackAwareVaultPayload {
  readonly version: 2;
  readonly owner: VaultOwner;
  readonly state: VaultStateMetadata;
  readonly stores: PartyStoresState;
}

type VaultPayload = LegacyVaultPayload | RollbackAwareVaultPayload;

interface VaultEnvelope {
  readonly version: 1;
  readonly cipher: 'aes-256-gcm';
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export type VaultStateOrigin = 'created' | 'migrated' | 'existing';

export interface VaultCheckpointMetadata {
  readonly stateId: string;
  readonly revision: number;
  readonly previousDigest: string | null;
}

export class RatchetVaultError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RatchetVaultError';
  }
}

export class RatchetVaultUnlockError extends RatchetVaultError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RatchetVaultUnlockError';
  }
}

function assertExactFields(
  document: Record<string, unknown>,
  expected: readonly string[],
  context: string
): void {
  const actual = Object.keys(document).sort();
  const wanted = [...expected].sort();
  if (actual.join(',') !== wanted.join(',')) {
    throw new RatchetVaultError(
      `${context} fields do not match the expected format`
    );
  }
}

function requireObject(
  value: unknown,
  context: string
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RatchetVaultError(`${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireText(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RatchetVaultError(`${field} must be non-empty text`);
  }
  return value;
}

function requireDeviceId(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new RatchetVaultError('owner.deviceId must be a positive safe integer');
  }
  return value as number;
}

function requireStateId(value: unknown): string {
  if (typeof value !== 'string' || !STATE_ID_PATTERN.test(value)) {
    throw new RatchetVaultError(
      'vault stateId must be 128-bit lowercase hexadecimal'
    );
  }
  return value;
}

function requireRevision(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > MAX_REVISION
  ) {
    throw new RatchetVaultError(
      'vault revision must be a positive safe integer'
    );
  }
  return value as number;
}

function requirePreviousDigest(
  value: unknown,
  revision: number
): string | null {
  if (revision === 1) {
    if (value !== null) {
      throw new RatchetVaultError(
        'initial rollback-aware vault must not have a previous digest'
      );
    }
    return null;
  }
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new RatchetVaultError(
      'vault previousDigest must be 32-byte lowercase hexadecimal'
    );
  }
  return value;
}

function requireCheckpointDigest(value: string): string {
  if (!DIGEST_PATTERN.test(value)) {
    throw new RatchetVaultError(
      'checkpoint digest must be 32-byte lowercase hexadecimal'
    );
  }
  return value;
}

function decodeCanonicalBase64(
  value: unknown,
  field: string,
  expectedBytes?: number
): Buffer {
  const text = requireText(value, field);
  const decoded = Buffer.from(text, 'base64');

  if (decoded.toString('base64') !== text) {
    throw new RatchetVaultError(`${field} must be canonical Base64`);
  }
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) {
    throw new RatchetVaultError(
      `${field} must decode to exactly ${expectedBytes} bytes`
    );
  }
  return decoded;
}

function parseEnvelope(value: unknown): VaultEnvelope {
  const document = requireObject(value, 'vault');
  assertExactFields(
    document,
    ['version', 'cipher', 'nonce', 'ciphertext', 'tag'],
    'vault'
  );

  if (document.version !== VAULT_ENVELOPE_VERSION) {
    throw new RatchetVaultError('unsupported vault envelope version');
  }
  if (document.cipher !== VAULT_CIPHER) {
    throw new RatchetVaultError('unsupported vault cipher');
  }

  const nonce = decodeCanonicalBase64(document.nonce, 'vault nonce', NONCE_BYTES);
  const ciphertext = decodeCanonicalBase64(
    document.ciphertext,
    'vault ciphertext'
  );
  const tag = decodeCanonicalBase64(document.tag, 'vault tag', TAG_BYTES);

  if (ciphertext.length === 0) {
    throw new RatchetVaultError('vault ciphertext must not be empty');
  }

  return {
    version: 1,
    cipher: VAULT_CIPHER,
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function parseOwner(value: unknown): VaultOwner {
  const document = requireObject(value, 'vault owner');
  assertExactFields(document, ['name', 'deviceId'], 'vault owner');
  return {
    name: requireText(document.name, 'owner.name'),
    deviceId: requireDeviceId(document.deviceId),
  };
}

function parseState(value: unknown): VaultStateMetadata {
  const document = requireObject(value, 'vault state');
  assertExactFields(
    document,
    ['stateId', 'revision', 'previousDigest'],
    'vault state'
  );
  const revision = requireRevision(document.revision);
  return {
    stateId: requireStateId(document.stateId),
    revision,
    previousDigest: requirePreviousDigest(
      document.previousDigest,
      revision
    ),
  };
}

function parsePayload(value: unknown): VaultPayload {
  const document = requireObject(value, 'decrypted vault');

  if (document.version === LEGACY_VAULT_PAYLOAD_VERSION) {
    assertExactFields(
      document,
      ['version', 'owner', 'stores'],
      'decrypted vault'
    );
    return {
      version: 1,
      owner: parseOwner(document.owner),
      stores: parsePartyStoresState(document.stores),
    };
  }

  if (document.version === VAULT_PAYLOAD_VERSION) {
    assertExactFields(
      document,
      ['version', 'owner', 'state', 'stores'],
      'decrypted vault'
    );
    return {
      version: 2,
      owner: parseOwner(document.owner),
      state: parseState(document.state),
      stores: parsePartyStoresState(document.stores),
    };
  }

  throw new RatchetVaultError('unsupported decrypted vault version');
}

function parseJson(raw: Buffer, context: string): unknown {
  try {
    return JSON.parse(raw.toString('utf8')) as unknown;
  } catch (error) {
    throw new RatchetVaultError(`${context} must contain valid UTF-8 JSON`, {
      cause: error,
    });
  }
}

function validateMasterKey(masterKey: Uint8Array): Buffer {
  if (masterKey.byteLength !== MASTER_KEY_BYTES) {
    throw new RatchetVaultError(
      `vault master key must be exactly ${MASTER_KEY_BYTES} bytes`
    );
  }
  return Buffer.from(masterKey);
}

async function fsyncDirectory(path: string): Promise<void> {
  if (process.platform === 'win32') {
    return;
  }

  const handle = await open(path, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export class RatchetStateVault {
  private readonly masterKey: Buffer;
  private readonly stateId: string | null;
  private readonly allowLegacyMigration: boolean;
  private checkpoint: VaultCheckpointMetadata | null = null;
  private acknowledgedDigest: string | null = null;
  private stateOrigin: VaultStateOrigin | null = null;

  constructor(
    readonly path: string,
    masterKey: Uint8Array,
    stateId?: string,
    allowLegacyMigration = false
  ) {
    if (!path) {
      throw new RatchetVaultError('vault path must not be empty');
    }
    this.masterKey = validateMasterKey(masterKey);
    this.stateId = stateId === undefined ? null : requireStateId(stateId);
    this.allowLegacyMigration = allowLegacyMigration;
  }

  async exists(): Promise<boolean> {
    try {
      const info = await stat(this.path);
      return info.isFile();
    } catch (error) {
      if (
        error instanceof Error &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        return false;
      }
      throw error;
    }
  }

  needsStateInitialization(): boolean {
    return this.stateId !== null && this.checkpoint === null;
  }

  getStateOrigin(): VaultStateOrigin | null {
    return this.stateOrigin;
  }

  getCheckpointMetadata(): VaultCheckpointMetadata {
    if (this.stateId === null || this.checkpoint === null) {
      throw new RatchetVaultError('ratchet vault is not rollback-aware');
    }
    return { ...this.checkpoint };
  }

  acknowledgeCheckpoint(digest: string): void {
    if (this.stateId === null || this.checkpoint === null) {
      throw new RatchetVaultError('ratchet vault is not rollback-aware');
    }
    this.acknowledgedDigest = requireCheckpointDigest(digest);
  }

  async load(expectedOwner: VaultOwner): Promise<PartyStoresState | null> {
    if (!(await this.exists())) {
      if (this.stateId !== null) {
        this.stateOrigin = 'created';
      }
      return null;
    }

    const info = await stat(this.path);
    if (info.size > MAX_VAULT_BYTES) {
      throw new RatchetVaultError('vault file exceeds the size limit');
    }

    const raw = await readFile(this.path);
    const envelope = parseEnvelope(parseJson(raw, 'vault'));

    const nonce = Buffer.from(envelope.nonce, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');

    let plaintext: Buffer;
    try {
      const decipher = createDecipheriv(
        VAULT_CIPHER,
        this.masterKey,
        nonce,
        { authTagLength: TAG_BYTES }
      );
      decipher.setAAD(AAD);
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
    } catch (error) {
      throw new RatchetVaultUnlockError(
        'vault key is incorrect or vault data was modified',
        { cause: error }
      );
    }

    if (plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw new RatchetVaultError('decrypted vault exceeds the size limit');
    }

    const payload = parsePayload(parseJson(plaintext, 'decrypted vault'));
    if (
      payload.owner.name !== expectedOwner.name ||
      payload.owner.deviceId !== expectedOwner.deviceId
    ) {
      throw new RatchetVaultError('vault owner does not match requested device');
    }

    if (payload.version === 1) {
      if (this.stateId !== null) {
        if (!this.allowLegacyMigration) {
          throw new RatchetVaultError(
            'legacy ratchet vault requires explicit rollback-state migration'
          );
        }
        this.stateOrigin = 'migrated';
        this.checkpoint = null;
        this.acknowledgedDigest = null;
      }
      return payload.stores;
    }

    if (this.stateId === null) {
      throw new RatchetVaultError(
        'rollback-aware ratchet vault requires state coordination'
      );
    }
    if (payload.state.stateId !== this.stateId) {
      throw new RatchetVaultError(
        'ratchet vault belongs to a different client state'
      );
    }

    this.checkpoint = {
      stateId: payload.state.stateId,
      revision: payload.state.revision,
      previousDigest: payload.state.previousDigest,
    };
    this.acknowledgedDigest = null;
    this.stateOrigin = 'existing';
    return payload.stores;
  }

  async save(owner: VaultOwner, stores: PartyStoresState): Promise<void> {
    let payload: VaultPayload;

    if (this.stateId === null) {
      payload = {
        version: 1,
        owner: {
          name: requireText(owner.name, 'owner.name'),
          deviceId: requireDeviceId(owner.deviceId),
        },
        stores,
      };
    } else {
      let revision: number;
      let previousDigest: string | null;

      if (this.checkpoint === null) {
        revision = 1;
        previousDigest = null;
      } else {
        if (this.acknowledgedDigest === null) {
          throw new RatchetVaultError(
            'ratchet vault checkpoint must be acknowledged before mutation'
          );
        }
        if (this.checkpoint.revision >= MAX_REVISION) {
          throw new RatchetVaultError('ratchet vault revision is exhausted');
        }
        revision = this.checkpoint.revision + 1;
        previousDigest = this.acknowledgedDigest;
      }

      payload = {
        version: 2,
        owner: {
          name: requireText(owner.name, 'owner.name'),
          deviceId: requireDeviceId(owner.deviceId),
        },
        state: {
          stateId: this.stateId,
          revision,
          previousDigest,
        },
        stores,
      };
    }

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    if (plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw new RatchetVaultError('vault plaintext exceeds the size limit');
    }

    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv(
      VAULT_CIPHER,
      this.masterKey,
      nonce,
      { authTagLength: TAG_BYTES }
    );
    cipher.setAAD(AAD);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const envelope: VaultEnvelope = {
      version: 1,
      cipher: VAULT_CIPHER,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    };
    const serialized = Buffer.from(JSON.stringify(envelope), 'utf8');

    if (serialized.length > MAX_VAULT_BYTES) {
      throw new RatchetVaultError('serialized vault exceeds the size limit');
    }

    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true, mode: 0o700 });

    const temporary = join(
      directory,
      '.' +
        basename(this.path) +
        '.tmp-' +
        process.pid +
        '-' +
        randomBytes(8).toString('hex')
    );

    let handle;
    try {
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(serialized);
      await handle.sync();
      await handle.close();
      handle = undefined;

      await rename(temporary, this.path);
      if (process.platform !== 'win32') {
        await chmod(this.path, 0o600);
      }
      await fsyncDirectory(directory);
    } catch (error) {
      if (handle !== undefined) {
        await handle.close().catch(() => undefined);
      }
      await rm(temporary, { force: true }).catch(() => undefined);
      throw new RatchetVaultError('unable to persist ratchet vault atomically', {
        cause: error,
      });
    }

    if (payload.version === 2) {
      this.checkpoint = {
        stateId: payload.state.stateId,
        revision: payload.state.revision,
        previousDigest: payload.state.previousDigest,
      };
      this.acknowledgedDigest = null;
    }
  }

  destroyKey(): void {
    this.masterKey.fill(0);
  }
}
