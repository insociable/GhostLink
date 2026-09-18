import { randomInt } from 'node:crypto';

import * as SignalClient from '@signalapp/libsignal-client';

import { RatchetParty, type WireMessage } from './party.js';
import {
  MAX_REGISTRATION_ID,
  MIN_REGISTRATION_ID,
  SIGNAL_DEVICE_ID,
} from './protocol-profile.js';
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

  private remoteAddress(name: string): SignalClient.ProtocolAddress {
    if (!name) {
      throw new Error('remote ratchet address must not be empty');
    }
    return SignalClient.ProtocolAddress.new(name, SIGNAL_DEVICE_ID);
  }

  async establishSessionWithAddress(
    remoteName: string,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    const remoteAddress = this.remoteAddress(remoteName);
    await this.transaction((party) =>
      party.establishSessionAt(remoteAddress, bundle)
    );
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