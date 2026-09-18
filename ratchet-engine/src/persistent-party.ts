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

const DEFAULT_ONE_TIME_POOL_TARGET = 100;
const MAX_ONE_TIME_POOL_SIZE = 256;
const MAX_BINDING_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
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

  private remoteAddress(name: string): SignalClient.ProtocolAddress {
    if (!name) {
      throw new Error('remote ratchet address must not be empty');
    }
    return SignalClient.ProtocolAddress.new(name, SIGNAL_DEVICE_ID);
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

  async establishSession(
    remote: PersistentRatchetParty,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    await this.transaction((party) =>
      party.establishSession(remote.inner, bundle)
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