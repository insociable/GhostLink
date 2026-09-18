import * as SignalClient from '@signalapp/libsignal-client';

import {
  emptyPreKeyLifecycleState,
  MemoryPreKeyLifecycleStore,
  parsePreKeyLifecycleState,
  type PreKeyLifecycleState,
} from './prekey-lifecycle-state.js';
import {
  MemoryRemotePublicationSequenceStore,
  parseRemotePublicationSequences,
  type RemotePublicationSequenceState,
} from './remote-publication-state.js';
import { validateRegistrationId } from './protocol-profile.js';

const MAX_STORE_ENTRIES = 100_000;

function addressKey(address: SignalClient.ProtocolAddress): string {
  return `${address.name()}::${address.deviceId()}`;
}

function encodeBytes(value: Uint8Array): string {
  return Buffer.from(value).toString('base64');
}

function decodeBytes(
  value: string,
  field: string
): Uint8Array<ArrayBuffer> {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== value) {
    throw new Error(`${field} must be canonical non-empty Base64`);
  }
  return Uint8Array.from(decoded);
}

function assertArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`);
  }
  if (value.length > MAX_STORE_ENTRIES) {
    throw new Error(`${field} contains too many entries`);
  }
  return value;
}

function assertInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
  return value as number;
}

function assertString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${field} must be non-empty text`);
  }
  return value;
}

export interface PartyStoresState {
  readonly version: 3;
  readonly session: readonly (readonly [string, string])[];
  readonly identity: {
    readonly registrationId: number;
    readonly privateKey: string;
    readonly trusted: readonly (readonly [string, string])[];
  };
  readonly preKey: readonly (readonly [number, string])[];
  readonly signedPreKey: readonly (readonly [number, string])[];
  readonly kyberPreKey: {
    readonly records: readonly (readonly [number, string])[];
    readonly used: readonly number[];
    readonly baseKeysSeen: readonly (readonly [string, readonly string[]])[];
  };
  readonly lifecycle: PreKeyLifecycleState;
  readonly remotePublicationSequences: RemotePublicationSequenceState;
}

function parseStringEntries(
  value: unknown,
  field: string
): Array<[string, string]> {
  return assertArray(value, field).map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(`${field}[${index}] must contain two values`);
    }
    return [
      assertString(entry[0], `${field}[${index}][0]`),
      assertString(entry[1], `${field}[${index}][1]`),
    ];
  });
}

function parseNumberEntries(
  value: unknown,
  field: string
): Array<[number, string]> {
  return assertArray(value, field).map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(`${field}[${index}] must contain two values`);
    }
    return [
      assertInteger(entry[0], `${field}[${index}][0]`),
      assertString(entry[1], `${field}[${index}][1]`),
    ];
  });
}

export function parsePartyStoresState(value: unknown): PartyStoresState {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('stores state must be an object');
  }

  const document = value as Record<string, unknown>;
  const version = assertInteger(document.version, 'version');
  if (version !== 1 && version !== 2 && version !== 3) {
    throw new Error('unsupported stores state version');
  }

  const expected =
    version === 1
      ? ['version', 'session', 'identity', 'preKey', 'signedPreKey', 'kyberPreKey']
      : version === 2
        ? [
            'version',
            'session',
            'identity',
            'preKey',
            'signedPreKey',
            'kyberPreKey',
            'lifecycle',
          ]
        : [
            'version',
            'session',
            'identity',
            'preKey',
            'signedPreKey',
            'kyberPreKey',
            'lifecycle',
            'remotePublicationSequences',
          ];
  if (
    Object.keys(document).sort().join(',') !== expected.slice().sort().join(',')
  ) {
    throw new Error(`stores state fields do not match version ${version}`);
  }

  if (
    typeof document.identity !== 'object' ||
    document.identity === null ||
    Array.isArray(document.identity)
  ) {
    throw new Error('identity state must be an object');
  }
  const identity = document.identity as Record<string, unknown>;
  if (
    Object.keys(identity).sort().join(',') !==
    ['registrationId', 'privateKey', 'trusted'].sort().join(',')
  ) {
    throw new Error('identity state fields do not match version 1');
  }

  if (
    typeof document.kyberPreKey !== 'object' ||
    document.kyberPreKey === null ||
    Array.isArray(document.kyberPreKey)
  ) {
    throw new Error('Kyber state must be an object');
  }
  const kyber = document.kyberPreKey as Record<string, unknown>;
  if (
    Object.keys(kyber).sort().join(',') !==
    ['records', 'used', 'baseKeysSeen'].sort().join(',')
  ) {
    throw new Error('Kyber state fields do not match version 1');
  }

  const baseKeysSeen = assertArray(
    kyber.baseKeysSeen,
    'kyberPreKey.baseKeysSeen'
  ).map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(
        `kyberPreKey.baseKeysSeen[${index}] must contain two values`
      );
    }
    const key = assertString(
      entry[0],
      `kyberPreKey.baseKeysSeen[${index}][0]`
    );
    const keys = assertArray(
      entry[1],
      `kyberPreKey.baseKeysSeen[${index}][1]`
    ).map((item, keyIndex) =>
      assertString(
        item,
        `kyberPreKey.baseKeysSeen[${index}][1][${keyIndex}]`
      )
    );
    return [key, keys] as const;
  });

  return {
    version: 3,
    session: parseStringEntries(document.session, 'session'),
    identity: {
      registrationId: validateRegistrationId(
        assertInteger(
          identity.registrationId,
          'identity.registrationId'
        )
      ),
      privateKey: assertString(identity.privateKey, 'identity.privateKey'),
      trusted: parseStringEntries(identity.trusted, 'identity.trusted'),
    },
    preKey: parseNumberEntries(document.preKey, 'preKey'),
    signedPreKey: parseNumberEntries(document.signedPreKey, 'signedPreKey'),
    kyberPreKey: {
      records: parseNumberEntries(kyber.records, 'kyberPreKey.records'),
      used: assertArray(kyber.used, 'kyberPreKey.used').map((item, index) =>
        assertInteger(item, `kyberPreKey.used[${index}]`)
      ),
      baseKeysSeen,
    },
    lifecycle:
      version === 1
        ? emptyPreKeyLifecycleState()
        : parsePreKeyLifecycleState(document.lifecycle),
    remotePublicationSequences:
      version === 3
        ? parseRemotePublicationSequences(document.remotePublicationSequences)
        : [],
  };
}

export class MemorySessionStore extends SignalClient.SessionStore {
  private readonly records = new Map<string, Uint8Array>();

  async saveSession(
    address: SignalClient.ProtocolAddress,
    record: SignalClient.SessionRecord
  ): Promise<void> {
    this.records.set(addressKey(address), Uint8Array.from(record.serialize()));
  }

  async getSession(
    address: SignalClient.ProtocolAddress
  ): Promise<SignalClient.SessionRecord | null> {
    const serialized = this.records.get(addressKey(address));
    return serialized
      ? SignalClient.SessionRecord.deserialize(Buffer.from(serialized))
      : null;
  }

  async getExistingSessions(
    addresses: SignalClient.ProtocolAddress[]
  ): Promise<SignalClient.SessionRecord[]> {
    return Promise.all(
      addresses.map(async (address) => {
        const record = await this.getSession(address);
        if (record === null) {
          throw new Error(`session not found for ${addressKey(address)}`);
        }
        return record;
      })
    );
  }

  exportState(): Array<[string, string]> {
    return [...this.records].map(([key, value]) => [key, encodeBytes(value)]);
  }

  static fromState(entries: readonly (readonly [string, string])[]): MemorySessionStore {
    const store = new MemorySessionStore();
    for (const [key, value] of entries) {
      const decoded = decodeBytes(value, `session[${key}]`);
      SignalClient.SessionRecord.deserialize(decoded);
      store.records.set(key, Uint8Array.from(decoded));
    }
    return store;
  }

  clone(): MemorySessionStore {
    return MemorySessionStore.fromState(this.exportState());
  }
}

export class MemoryIdentityKeyStore extends SignalClient.IdentityKeyStore {
  private readonly trusted = new Map<string, Uint8Array>();

  constructor(
    private readonly registrationId: number,
    private readonly identityKey: SignalClient.PrivateKey =
      SignalClient.PrivateKey.generate()
  ) {
    super();
  }

  async getIdentityKey(): Promise<SignalClient.PrivateKey> {
    return this.identityKey;
  }

  async getLocalRegistrationId(): Promise<number> {
    return this.registrationId;
  }

  async isTrustedIdentity(
    address: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey,
    _direction: SignalClient.Direction
  ): Promise<boolean> {
    const current = this.trusted.get(addressKey(address));
    return current === undefined
      ? true
      : SignalClient.PublicKey.deserialize(Buffer.from(current)).equals(key);
  }

  async saveIdentity(
    address: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey
  ): Promise<SignalClient.IdentityChange> {
    const idx = addressKey(address);
    const current = this.trusted.get(idx);
    const changed =
      current !== undefined &&
      !SignalClient.PublicKey.deserialize(Buffer.from(current)).equals(key);

    this.trusted.set(idx, Uint8Array.from(key.serialize()));

    return changed
      ? SignalClient.IdentityChange.ReplacedExisting
      : SignalClient.IdentityChange.NewOrUnchanged;
  }

  async getIdentity(
    address: SignalClient.ProtocolAddress
  ): Promise<SignalClient.PublicKey | null> {
    const current = this.trusted.get(addressKey(address));
    return current === undefined
      ? null
      : SignalClient.PublicKey.deserialize(Buffer.from(current));
  }

  exportState(): PartyStoresState['identity'] {
    return {
      registrationId: this.registrationId,
      privateKey: encodeBytes(this.identityKey.serialize()),
      trusted: [...this.trusted].map(([key, value]) => [
        key,
        encodeBytes(value),
      ]),
    };
  }

  static fromState(state: PartyStoresState['identity']): MemoryIdentityKeyStore {
    const privateKey = SignalClient.PrivateKey.deserialize(
      decodeBytes(state.privateKey, 'identity.privateKey')
    );
    const store = new MemoryIdentityKeyStore(state.registrationId, privateKey);

    for (const [key, value] of state.trusted) {
      const decoded = decodeBytes(value, `identity.trusted[${key}]`);
      SignalClient.PublicKey.deserialize(decoded);
      store.trusted.set(key, Uint8Array.from(decoded));
    }
    return store;
  }

  clone(): MemoryIdentityKeyStore {
    return MemoryIdentityKeyStore.fromState(this.exportState());
  }
}

export class MemoryPreKeyStore extends SignalClient.PreKeyStore {
  private readonly records = new Map<number, Uint8Array>();

  async savePreKey(
    id: number,
    record: SignalClient.PreKeyRecord
  ): Promise<void> {
    this.records.set(id, Uint8Array.from(record.serialize()));
  }

  async getPreKey(id: number): Promise<SignalClient.PreKeyRecord> {
    const serialized = this.records.get(id);
    if (serialized === undefined) {
      throw new Error(`pre-key ${id} not found`);
    }
    return SignalClient.PreKeyRecord.deserialize(Buffer.from(serialized));
  }

  async removePreKey(id: number): Promise<void> {
    const serialized = this.records.get(id);
    if (serialized !== undefined) {
      serialized.fill(0);
      this.records.delete(id);
    }
  }

  hasPreKey(id: number): boolean {
    return this.records.has(id);
  }

  exportState(): Array<[number, string]> {
    return [...this.records].map(([id, value]) => [id, encodeBytes(value)]);
  }

  static fromState(entries: readonly (readonly [number, string])[]): MemoryPreKeyStore {
    const store = new MemoryPreKeyStore();
    for (const [id, value] of entries) {
      const decoded = decodeBytes(value, `preKey[${id}]`);
      SignalClient.PreKeyRecord.deserialize(decoded);
      store.records.set(id, Uint8Array.from(decoded));
    }
    return store;
  }
}

export class MemorySignedPreKeyStore extends SignalClient.SignedPreKeyStore {
  private readonly records = new Map<number, Uint8Array>();

  async saveSignedPreKey(
    id: number,
    record: SignalClient.SignedPreKeyRecord
  ): Promise<void> {
    this.records.set(id, Uint8Array.from(record.serialize()));
  }

  async getSignedPreKey(id: number): Promise<SignalClient.SignedPreKeyRecord> {
    const serialized = this.records.get(id);
    if (serialized === undefined) {
      throw new Error(`signed pre-key ${id} not found`);
    }
    return SignalClient.SignedPreKeyRecord.deserialize(Buffer.from(serialized));
  }

  hasSignedPreKey(id: number): boolean {
    return this.records.has(id);
  }

  removeSignedPreKey(id: number): boolean {
    const serialized = this.records.get(id);
    if (serialized === undefined) {
      return false;
    }
    serialized.fill(0);
    return this.records.delete(id);
  }

  exportState(): Array<[number, string]> {
    return [...this.records].map(([id, value]) => [id, encodeBytes(value)]);
  }

  static fromState(
    entries: readonly (readonly [number, string])[]
  ): MemorySignedPreKeyStore {
    const store = new MemorySignedPreKeyStore();
    for (const [id, value] of entries) {
      const decoded = decodeBytes(value, `signedPreKey[${id}]`);
      SignalClient.SignedPreKeyRecord.deserialize(decoded);
      store.records.set(id, Uint8Array.from(decoded));
    }
    return store;
  }
}

export class MemoryKyberPreKeyStore extends SignalClient.KyberPreKeyStore {
  private readonly records = new Map<number, Uint8Array>();
  private readonly used = new Set<number>();
  private readonly baseKeysSeen = new Map<bigint, SignalClient.PublicKey[]>();

  async saveKyberPreKey(
    id: number,
    record: SignalClient.KyberPreKeyRecord
  ): Promise<void> {
    this.records.set(id, Uint8Array.from(record.serialize()));
  }

  async getKyberPreKey(id: number): Promise<SignalClient.KyberPreKeyRecord> {
    const serialized = this.records.get(id);
    if (serialized === undefined) {
      throw new Error(`Kyber pre-key ${id} not found`);
    }
    return SignalClient.KyberPreKeyRecord.deserialize(Buffer.from(serialized));
  }

  async markKyberPreKeyUsed(
    id: number,
    signedPreKeyId: number,
    baseKey: SignalClient.PublicKey
  ): Promise<void> {
    this.used.add(id);
    const compound = (BigInt(id) << 32n) | BigInt(signedPreKeyId);
    const seen = this.baseKeysSeen.get(compound);

    if (seen === undefined) {
      this.baseKeysSeen.set(compound, [baseKey]);
      return;
    }

    if (seen.some((candidate) => candidate.equals(baseKey))) {
      throw new Error('reused base key');
    }

    seen.push(baseKey);
  }

  async hasKyberPreKeyBeenUsed(id: number): Promise<boolean> {
    return this.used.has(id);
  }

  hasKyberPreKey(id: number): boolean {
    return this.records.has(id);
  }

  removeKyberPreKey(id: number): boolean {
    const serialized = this.records.get(id);
    const removed =
      serialized === undefined
        ? false
        : (serialized.fill(0), this.records.delete(id));
    this.used.delete(id);

    const keyId = BigInt(id);
    for (const compound of [...this.baseKeysSeen.keys()]) {
      if ((compound >> 32n) === keyId) {
        this.baseKeysSeen.delete(compound);
      }
    }

    return removed;
  }

  exportState(): PartyStoresState['kyberPreKey'] {
    return {
      records: [...this.records].map(([id, value]) => [id, encodeBytes(value)]),
      used: [...this.used],
      baseKeysSeen: [...this.baseKeysSeen].map(([compound, keys]) => [
        compound.toString(10),
        keys.map((key) => encodeBytes(key.serialize())),
      ]),
    };
  }

  static fromState(
    state: PartyStoresState['kyberPreKey']
  ): MemoryKyberPreKeyStore {
    const store = new MemoryKyberPreKeyStore();

    for (const [id, value] of state.records) {
      const decoded = decodeBytes(value, `kyberPreKey.records[${id}]`);
      SignalClient.KyberPreKeyRecord.deserialize(decoded);
      store.records.set(id, Uint8Array.from(decoded));
    }
    for (const id of state.used) {
      store.used.add(id);
    }
    for (const [compoundText, encodedKeys] of state.baseKeysSeen) {
      if (!/^[0-9]+$/.test(compoundText)) {
        throw new Error('Kyber base-key compound ID must be decimal text');
      }
      const compound = BigInt(compoundText);
      store.baseKeysSeen.set(
        compound,
        encodedKeys.map((value, index) =>
          SignalClient.PublicKey.deserialize(
            decodeBytes(
              value,
              `kyberPreKey.baseKeysSeen[${compoundText}][${index}]`
            )
          )
        )
      );
    }
    return store;
  }
}

export interface PartyStores {
  readonly session: MemorySessionStore;
  readonly identity: MemoryIdentityKeyStore;
  readonly preKey: MemoryPreKeyStore;
  readonly signedPreKey: MemorySignedPreKeyStore;
  readonly kyberPreKey: MemoryKyberPreKeyStore;
  readonly lifecycle: MemoryPreKeyLifecycleStore;
  readonly remotePublicationSequences: MemoryRemotePublicationSequenceStore;
}

export function createPartyStores(registrationId: number): PartyStores {
  return {
    session: new MemorySessionStore(),
    identity: new MemoryIdentityKeyStore(registrationId),
    preKey: new MemoryPreKeyStore(),
    signedPreKey: new MemorySignedPreKeyStore(),
    kyberPreKey: new MemoryKyberPreKeyStore(),
    lifecycle: new MemoryPreKeyLifecycleStore(),
    remotePublicationSequences: new MemoryRemotePublicationSequenceStore(),
  };
}

export function exportPartyStores(stores: PartyStores): PartyStoresState {
  return {
    version: 3,
    session: stores.session.exportState(),
    identity: stores.identity.exportState(),
    preKey: stores.preKey.exportState(),
    signedPreKey: stores.signedPreKey.exportState(),
    kyberPreKey: stores.kyberPreKey.exportState(),
    lifecycle: stores.lifecycle.exportState(),
    remotePublicationSequences:
      stores.remotePublicationSequences.exportState(),
  };
}

export function restorePartyStores(state: PartyStoresState): PartyStores {
  return {
    session: MemorySessionStore.fromState(state.session),
    identity: MemoryIdentityKeyStore.fromState(state.identity),
    preKey: MemoryPreKeyStore.fromState(state.preKey),
    signedPreKey: MemorySignedPreKeyStore.fromState(state.signedPreKey),
    kyberPreKey: MemoryKyberPreKeyStore.fromState(state.kyberPreKey),
    lifecycle: MemoryPreKeyLifecycleStore.fromState(state.lifecycle),
    remotePublicationSequences:
      MemoryRemotePublicationSequenceStore.fromState(
        state.remotePublicationSequences
      ),
  };
}