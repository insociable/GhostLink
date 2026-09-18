import * as SignalClient from '@signalapp/libsignal-client';

function addressKey(address: SignalClient.ProtocolAddress): string {
  return `${address.name()}::${address.deviceId()}`;
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

  clone(): MemorySessionStore {
    const copy = new MemorySessionStore();
    for (const [key, value] of this.records) {
      copy.records.set(key, Uint8Array.from(value));
    }
    return copy;
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

  clone(): MemoryIdentityKeyStore {
    const copy = new MemoryIdentityKeyStore(
      this.registrationId,
      SignalClient.PrivateKey.deserialize(this.identityKey.serialize())
    );
    for (const [key, value] of this.trusted) {
      copy.trusted.set(key, Uint8Array.from(value));
    }
    return copy;
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
    this.records.delete(id);
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
}

export interface PartyStores {
  readonly session: MemorySessionStore;
  readonly identity: MemoryIdentityKeyStore;
  readonly preKey: MemoryPreKeyStore;
  readonly signedPreKey: MemorySignedPreKeyStore;
  readonly kyberPreKey: MemoryKyberPreKeyStore;
}

export function createPartyStores(registrationId: number): PartyStores {
  return {
    session: new MemorySessionStore(),
    identity: new MemoryIdentityKeyStore(registrationId),
    preKey: new MemoryPreKeyStore(),
    signedPreKey: new MemorySignedPreKeyStore(),
    kyberPreKey: new MemoryKyberPreKeyStore(),
  };
}