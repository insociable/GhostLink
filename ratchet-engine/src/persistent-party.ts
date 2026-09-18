import { randomInt } from 'node:crypto';

import * as SignalClient from '@signalapp/libsignal-client';

import {
  RatchetParty,
  type PreKeyGenerationMaterial,
  type WireMessage,
} from './party.js';
import {
  MAX_REGISTRATION_ID,
  MIN_REGISTRATION_ID,
  SIGNAL_DEVICE_ID,
} from './protocol-profile.js';
import { MAX_RETIRED_GENERATIONS } from './prekey-lifecycle-state.js';
import {
  createPartyStores,
  exportPartyStores,
  restorePartyStores,
  type PartyStoresState,
} from './stores.js';
import { RatchetStateVault } from './vault.js';

interface Owner {
  readonly name: string;
  readonly deviceId: number;
}

export interface PreparedPreKeyGeneration extends PreKeyGenerationMaterial {
  readonly sequence: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface PreKeyGenerationStatus {
  readonly sequence: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly publishedAt: number | null;
  readonly staged: boolean;
}

export interface PreKeyLifecycleStatus {
  readonly publicationSequence: number;
  readonly pending: PreKeyGenerationStatus | null;
  readonly active: PreKeyGenerationStatus | null;
  readonly retiredCount: number;
}

export interface PreKeyGarbageCollectionResult {
  readonly retiredGenerationsRemoved: number;
  readonly preKeysRemoved: number;
  readonly signedPreKeysRemoved: number;
  readonly kyberPreKeysRemoved: number;
}

const DEFAULT_ONE_TIME_POOL_TARGET = 100;
const MAX_ONE_TIME_POOL_SIZE = 256;
const MAX_BINDING_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
export const RETIRED_PREKEY_RETENTION_SECONDS = 15 * 24 * 60 * 60;
const MAX_PUBLICATION_SEQUENCE = Number.MAX_SAFE_INTEGER;
const MAX_SECONDS_SAFE_FOR_MILLISECONDS = Math.floor(
  Number.MAX_SAFE_INTEGER / 1000
);

export class PersistentRatchetParty {
  private inner: RatchetParty;
  private operationTail: Promise<void> = Promise.resolve();

  private constructor(
    private readonly owner: Owner,
    private readonly vault: RatchetStateVault,
    inner: RatchetParty
  ) {
    this.inner = inner;
  }

  static async open(
    name: string,
    deviceId: number,
    vaultPath: string,
    masterKey: Uint8Array
  ): Promise<PersistentRatchetParty> {
    if (!name) {
      throw new Error('ratchet party name must not be empty');
    }
    if (!Number.isSafeInteger(deviceId) || deviceId <= 0) {
      throw new Error('ratchet party deviceId must be a positive safe integer');
    }

    const owner = { name, deviceId };
    const vault = new RatchetStateVault(vaultPath, masterKey);
    const persisted = await vault.load(owner);

    let stores;
    if (persisted === null) {
      stores = createPartyStores(
        randomInt(MIN_REGISTRATION_ID, MAX_REGISTRATION_ID + 1)
      );
      await vault.save(owner, exportPartyStores(stores));
    } else {
      stores = restorePartyStores(persisted);
    }

    const registrationId = await stores.identity.getLocalRegistrationId();
    const party = new RatchetParty(name, deviceId, registrationId, stores);

    return new PersistentRatchetParty(owner, vault, party);
  }

  get address(): SignalClient.ProtocolAddress {
    return this.inner.address;
  }

  private rebuild(state: PartyStoresState): RatchetParty {
    const stores = restorePartyStores(state);
    return new RatchetParty(
      this.owner.name,
      this.owner.deviceId,
      state.identity.registrationId,
      stores
    );
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operationTail;

    let release: () => void = () => undefined;
    this.operationTail = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async transaction<T>(
    operation: (party: RatchetParty) => Promise<T>
  ): Promise<T> {
    return this.exclusive(async () => {
      const before = exportPartyStores(this.inner.stores);

      try {
        const result = await operation(this.inner);
        await this.vault.save(
          this.owner,
          exportPartyStores(this.inner.stores)
        );
        return result;
      } catch (error) {
        this.inner = this.rebuild(before);
        throw error;
      }
    });
  }

  async createPreKeyBundle(): Promise<SignalClient.PreKeyBundle> {
    return this.transaction((party) => party.createPreKeyBundle());
  }


  async preparePreKeyGeneration(
    oneTimeCount = DEFAULT_ONE_TIME_POOL_TARGET,
    nowSeconds = Math.floor(Date.now() / 1000),
    lifetimeSeconds = MAX_BINDING_LIFETIME_SECONDS
  ): Promise<PreparedPreKeyGeneration> {
    if (
      !Number.isSafeInteger(oneTimeCount) ||
      oneTimeCount <= 0 ||
      oneTimeCount > MAX_ONE_TIME_POOL_SIZE
    ) {
      throw new Error(
        `oneTimeCount must be between 1 and ${MAX_ONE_TIME_POOL_SIZE}`
      );
    }
    if (
      !Number.isSafeInteger(nowSeconds) ||
      nowSeconds < 0 ||
      nowSeconds > MAX_SECONDS_SAFE_FOR_MILLISECONDS
    ) {
      throw new Error('nowSeconds is outside the supported range');
    }
    if (
      !Number.isSafeInteger(lifetimeSeconds) ||
      lifetimeSeconds <= 0 ||
      lifetimeSeconds > MAX_BINDING_LIFETIME_SECONDS
    ) {
      throw new Error('lifetimeSeconds must be between 1 and seven days');
    }

    const expiresAt = nowSeconds + lifetimeSeconds;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new Error('pre-key generation expiration exceeds safe integer range');
    }

    return this.transaction(async (party) => {
      const lifecycle = party.stores.lifecycle.snapshot();
      if (lifecycle.pending !== null) {
        throw new Error('a pending pre-key generation already exists');
      }
      if (lifecycle.publicationSequence >= MAX_PUBLICATION_SEQUENCE) {
        throw new Error('pre-key publication sequence is exhausted');
      }

      const sequence = lifecycle.publicationSequence + 1;
      const material = await party.createPreKeyGeneration(
        oneTimeCount,
        nowSeconds * 1000
      );

      party.stores.lifecycle.replace({
        ...lifecycle,
        publicationSequence: sequence,
        pending: {
          sequence,
          createdAt: nowSeconds,
          expiresAt,
          signedPreKeyId: material.signedPreKeyId,
          lastResortKyberPreKeyId: material.lastResortKyberPreKeyId,
          oneTimeKeyIds: material.oneTimeKeyIds,
          publicPayload: null,
          publishedAt: null,
          retiredAt: null,
        },
      });

      return {
        ...material,
        sequence,
        createdAt: nowSeconds,
        expiresAt,
      };
    });
  }

  async getPendingPreKeyGeneration(): Promise<
    (PreparedPreKeyGeneration & { readonly publicPayload: string | null }) | null
  > {
    return this.exclusive(async () => {
      const lifecycle = this.inner.stores.lifecycle.snapshot();
      const pending = lifecycle.pending;
      if (pending === null) {
        return null;
      }

      const material = await this.inner.loadPreKeyGeneration(pending);
      return {
        ...material,
        sequence: pending.sequence,
        createdAt: pending.createdAt,
        expiresAt: pending.expiresAt,
        publicPayload: pending.publicPayload,
      };
    });
  }

  async getPreKeyLifecycleStatus(): Promise<PreKeyLifecycleStatus> {
    return this.exclusive(async () => {
      const lifecycle = this.inner.stores.lifecycle.snapshot();
      const summarize = (
        generation: typeof lifecycle.pending
      ): PreKeyGenerationStatus | null => {
        if (generation === null) {
          return null;
        }
        return {
          sequence: generation.sequence,
          createdAt: generation.createdAt,
          expiresAt: generation.expiresAt,
          publishedAt: generation.publishedAt,
          staged: generation.publicPayload !== null,
        };
      };

      return {
        publicationSequence: lifecycle.publicationSequence,
        pending: summarize(lifecycle.pending),
        active: summarize(lifecycle.active),
        retiredCount: lifecycle.retired.length,
      };
    });
  }

  async stagePreKeyPublication(
    sequence: number,
    publicPayload: string
  ): Promise<void> {
    if (
      !Number.isSafeInteger(sequence) ||
      sequence <= 0 ||
      sequence > MAX_PUBLICATION_SEQUENCE
    ) {
      throw new Error('publication sequence is outside the supported range');
    }
    if (
      publicPayload.length === 0 ||
      Buffer.byteLength(publicPayload, 'utf8') > 1024 * 1024
    ) {
      throw new Error('public payload must be bounded non-empty UTF-8 text');
    }

    await this.transaction(async (party) => {
      const lifecycle = party.stores.lifecycle.snapshot();
      const pending = lifecycle.pending;
      if (pending === null) {
        throw new Error('no pending pre-key generation exists');
      }
      if (pending.sequence !== sequence) {
        throw new Error('pending pre-key generation sequence does not match');
      }
      if (
        pending.publicPayload !== null &&
        pending.publicPayload !== publicPayload
      ) {
        throw new Error(
          'pending pre-key generation already has a different public payload'
        );
      }
      if (pending.publicPayload === publicPayload) {
        return;
      }

      party.stores.lifecycle.replace({
        ...lifecycle,
        pending: {
          ...pending,
          publicPayload,
        },
      });
    });
  }

  async commitPreKeyPublication(
    sequence: number,
    publishedAt = Math.floor(Date.now() / 1000)
  ): Promise<void> {
    if (
      !Number.isSafeInteger(sequence) ||
      sequence <= 0 ||
      sequence > MAX_PUBLICATION_SEQUENCE
    ) {
      throw new Error('publication sequence is outside the supported range');
    }
    if (
      !Number.isSafeInteger(publishedAt) ||
      publishedAt < 0 ||
      publishedAt > Number.MAX_SAFE_INTEGER
    ) {
      throw new Error('publishedAt is outside the supported range');
    }

    await this.transaction(async (party) => {
      const lifecycle = party.stores.lifecycle.snapshot();
      const pending = lifecycle.pending;

      if (pending === null) {
        if (lifecycle.active?.sequence === sequence) {
          return;
        }
        throw new Error('no matching pending pre-key generation exists');
      }
      if (pending.sequence !== sequence) {
        throw new Error('pending pre-key generation sequence does not match');
      }
      if (pending.publicPayload === null) {
        throw new Error('pending pre-key publication has not been staged');
      }
      if (publishedAt < pending.createdAt || publishedAt >= pending.expiresAt) {
        throw new Error(
          'publication acknowledgement timestamp is outside generation lifetime'
        );
      }

      const retired = [...lifecycle.retired];
      if (lifecycle.active !== null) {
        if (
          lifecycle.active.publishedAt !== null &&
          publishedAt < lifecycle.active.publishedAt
        ) {
          throw new Error(
            'publication acknowledgement predates the active generation'
          );
        }
        if (retired.length >= MAX_RETIRED_GENERATIONS) {
          throw new Error(
            'retired generation limit reached before garbage collection'
          );
        }
        retired.push({
          ...lifecycle.active,
          retiredAt: publishedAt,
        });
      }

      party.stores.lifecycle.replace({
        ...lifecycle,
        pending: null,
        active: {
          ...pending,
          publishedAt,
          retiredAt: null,
        },
        retired,
      });
    });
  }

  async garbageCollectPreKeys(
    nowSeconds = Math.floor(Date.now() / 1000)
  ): Promise<PreKeyGarbageCollectionResult> {
    if (
      !Number.isSafeInteger(nowSeconds) ||
      nowSeconds < 0 ||
      nowSeconds > MAX_SECONDS_SAFE_FOR_MILLISECONDS
    ) {
      throw new Error('nowSeconds is outside the supported range');
    }

    return this.exclusive(async () => {
      const lifecycle = this.inner.stores.lifecycle.snapshot();

      if (
        lifecycle.active !== null &&
        lifecycle.active.publicPayload === null
      ) {
        throw new Error('active pre-key generation is missing staged metadata');
      }

      for (const generation of lifecycle.retired) {
        if (
          generation.retiredAt === null ||
          generation.publicPayload === null
        ) {
          throw new Error(
            'retired pre-key generation metadata is incomplete'
          );
        }
        if (nowSeconds < generation.retiredAt) {
          throw new Error(
            'current time predates a retired pre-key generation'
          );
        }
      }

      const expired = lifecycle.retired.filter(
        (generation) =>
          generation.retiredAt !== null &&
          nowSeconds - generation.retiredAt >=
            RETIRED_PREKEY_RETENTION_SECONDS
      );
      if (expired.length === 0) {
        return {
          retiredGenerationsRemoved: 0,
          preKeysRemoved: 0,
          signedPreKeysRemoved: 0,
          kyberPreKeysRemoved: 0,
        };
      }

      const retained = lifecycle.retired.filter(
        (generation) =>
          generation.retiredAt !== null &&
          nowSeconds - generation.retiredAt <
            RETIRED_PREKEY_RETENTION_SECONDS
      );

      const protectedPreKeys = new Set<number>();
      const protectedSignedPreKeys = new Set<number>();
      const protectedKyberPreKeys = new Set<number>();

      const protectGeneration = (
        generation: typeof lifecycle.active
      ): void => {
        if (generation === null) {
          return;
        }
        protectedSignedPreKeys.add(generation.signedPreKeyId);
        protectedKyberPreKeys.add(generation.lastResortKyberPreKeyId);
        for (const [preKeyId, kyberPreKeyId] of generation.oneTimeKeyIds) {
          protectedPreKeys.add(preKeyId);
          protectedKyberPreKeys.add(kyberPreKeyId);
        }
      };

      protectGeneration(lifecycle.pending);
      protectGeneration(lifecycle.active);
      for (const generation of retained) {
        protectGeneration(generation);
      }

      const preKeysToRemove = new Set<number>();
      const signedPreKeysToRemove = new Set<number>();
      const kyberPreKeysToRemove = new Set<number>();

      for (const generation of expired) {
        if (!protectedSignedPreKeys.has(generation.signedPreKeyId)) {
          signedPreKeysToRemove.add(generation.signedPreKeyId);
        }
        if (
          !protectedKyberPreKeys.has(
            generation.lastResortKyberPreKeyId
          )
        ) {
          kyberPreKeysToRemove.add(
            generation.lastResortKyberPreKeyId
          );
        }
        for (const [preKeyId, kyberPreKeyId] of generation.oneTimeKeyIds) {
          if (!protectedPreKeys.has(preKeyId)) {
            preKeysToRemove.add(preKeyId);
          }
          if (!protectedKyberPreKeys.has(kyberPreKeyId)) {
            kyberPreKeysToRemove.add(kyberPreKeyId);
          }
        }
      }

      const before = exportPartyStores(this.inner.stores);
      try {
        let preKeysRemoved = 0;
        for (const id of preKeysToRemove) {
          if (this.inner.stores.preKey.hasPreKey(id)) {
            await this.inner.stores.preKey.removePreKey(id);
            preKeysRemoved += 1;
          }
        }

        let signedPreKeysRemoved = 0;
        for (const id of signedPreKeysToRemove) {
          if (this.inner.stores.signedPreKey.removeSignedPreKey(id)) {
            signedPreKeysRemoved += 1;
          }
        }

        let kyberPreKeysRemoved = 0;
        for (const id of kyberPreKeysToRemove) {
          if (this.inner.stores.kyberPreKey.removeKyberPreKey(id)) {
            kyberPreKeysRemoved += 1;
          }
        }

        this.inner.stores.lifecycle.replace({
          ...lifecycle,
          retired: retained,
        });

        await this.vault.save(
          this.owner,
          exportPartyStores(this.inner.stores)
        );

        return {
          retiredGenerationsRemoved: expired.length,
          preKeysRemoved,
          signedPreKeysRemoved,
          kyberPreKeysRemoved,
        };
      } catch (error) {
        this.inner = this.rebuild(before);
        throw error;
      }
    });
  }

  private remoteAddress(name: string): SignalClient.ProtocolAddress {
    if (!name) {
      throw new Error('remote ratchet address must not be empty');
    }
    return SignalClient.ProtocolAddress.new(name, SIGNAL_DEVICE_ID);
  }

  async hasSessionWithAddress(remoteName: string): Promise<boolean> {
    const remoteAddress = this.remoteAddress(remoteName);
    return this.exclusive(async () =>
      (await this.inner.stores.session.getSession(remoteAddress)) !== null
    );
  }

  async establishSessionWithAddress(
    remoteName: string,
    publicationSequence: number,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    const remoteAddress = this.remoteAddress(remoteName);
    await this.transaction(async (party) => {
      party.stores.remotePublicationSequences.observe(
        remoteName,
        publicationSequence
      );
      await party.establishSessionAt(remoteAddress, bundle);
    });
  }

  async encryptBytesTo(
    remoteName: string,
    plaintext: Uint8Array
  ): Promise<WireMessage> {
    const remoteAddress = this.remoteAddress(remoteName);
    return this.transaction((party) =>
      party.encryptBytes(remoteAddress, plaintext)
    );
  }

  async decryptBytesFrom(
    remoteName: string,
    message: WireMessage
  ): Promise<Uint8Array> {
    const remoteAddress = this.remoteAddress(remoteName);
    return this.transaction((party) =>
      party.decryptBytes(remoteAddress, message)
    );
  }

  async decryptBytesFromWithContext(
    remoteName: string,
    message: WireMessage,
    expectedContext: Uint8Array
  ): Promise<Uint8Array> {
    if (expectedContext.byteLength === 0) {
      throw new Error('expected ratchet context must not be empty');
    }

    const remoteAddress = this.remoteAddress(remoteName);
    return this.transaction(async (party) => {
      const plaintext = await party.decryptBytes(remoteAddress, message);
      if (plaintext.byteLength < expectedContext.byteLength) {
        throw new Error('decrypted ratchet context does not match');
      }

      const actualContext = Buffer.from(
        plaintext.subarray(0, expectedContext.byteLength)
      );
      if (!actualContext.equals(Buffer.from(expectedContext))) {
        throw new Error('decrypted ratchet context does not match');
      }

      return plaintext.subarray(expectedContext.byteLength);
    });
  }

  async establishSession(
    remote: PersistentRatchetParty,
    publicationSequence: number,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    await this.establishSessionWithAddress(
      remote.address.name(),
      publicationSequence,
      bundle
    );
  }

  async encrypt(
    remote: PersistentRatchetParty,
    plaintext: string
  ): Promise<WireMessage> {
    return this.transaction((party) => party.encrypt(remote.inner, plaintext));
  }

  async decrypt(
    remote: PersistentRatchetParty,
    message: WireMessage
  ): Promise<string> {
    return this.transaction((party) => party.decrypt(remote.inner, message));
  }

  async exportStateForTesting(): Promise<PartyStoresState> {
    return this.exclusive(async () => exportPartyStores(this.inner.stores));
  }

  close(): void {
    this.vault.destroyKey();
  }
}