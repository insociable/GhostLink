import { randomInt } from 'node:crypto';

import * as SignalClient from '@signalapp/libsignal-client';

import {
  MAX_PREKEY_ID,
  validateRegistrationId,
} from './protocol-profile.js';
import {
  MemoryPreKeyLifecycleStore,
  type PreKeyGenerationState,
} from './prekey-lifecycle-state.js';
import {
  createPartyStores,
  MemoryKyberPreKeyStore,
  MemoryPreKeyStore,
  MemorySignedPreKeyStore,
  type PartyStores,
} from './stores.js';

export interface WireMessage {
  readonly type: SignalClient.CiphertextMessageType;
  readonly body: Uint8Array;
}

export interface PreKeyGenerationMaterial {
  readonly oneTimeBundles: readonly SignalClient.PreKeyBundle[];
  readonly fallbackBundle: SignalClient.PreKeyBundle;
  readonly signedPreKeyId: number;
  readonly lastResortKyberPreKeyId: number;
  readonly oneTimeKeyIds: readonly (readonly [number, number])[];
}

const MAX_ONE_TIME_PREKEY_BUNDLES = 256;

function uniqueRandomId(isUsed: (id: number) => boolean): number {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const id = randomInt(1, MAX_PREKEY_ID + 1);
    if (!isUsed(id)) {
      return id;
    }
  }
  throw new Error('unable to allocate a unique pre-key identifier');
}

export class RatchetParty {
  readonly address: SignalClient.ProtocolAddress;
  readonly stores: PartyStores;

  constructor(
    name: string,
    deviceId: number,
    registrationId: number,
    stores: PartyStores = createPartyStores(registrationId)
  ) {
    if (!name) {
      throw new Error('ratchet party name must not be empty');
    }
    if (!Number.isSafeInteger(deviceId) || deviceId <= 0) {
      throw new Error('ratchet party deviceId must be a positive safe integer');
    }
    validateRegistrationId(registrationId);
    this.address = SignalClient.ProtocolAddress.new(name, deviceId);
    this.stores = stores;
  }

  async createPreKeyBundle(): Promise<SignalClient.PreKeyBundle> {
    const identityKey = await this.stores.identity.getIdentityKey();

    const preKeyId = uniqueRandomId((id) =>
      this.stores.preKey.hasPreKey(id)
    );
    const preKey = SignalClient.PrivateKey.generate();
    await this.stores.preKey.savePreKey(
      preKeyId,
      SignalClient.PreKeyRecord.new(
        preKeyId,
        preKey.getPublicKey(),
        preKey
      )
    );

    const signedPreKeyId = uniqueRandomId((id) =>
      this.stores.signedPreKey.hasSignedPreKey(id)
    );
    const signedPreKey = SignalClient.PrivateKey.generate();
    const signedPreKeySignature = identityKey.sign(
      signedPreKey.getPublicKey().serialize()
    );
    await this.stores.signedPreKey.saveSignedPreKey(
      signedPreKeyId,
      SignalClient.SignedPreKeyRecord.new(
        signedPreKeyId,
        Date.now(),
        signedPreKey.getPublicKey(),
        signedPreKey,
        signedPreKeySignature
      )
    );

    const kyberPreKeyId = uniqueRandomId((id) =>
      this.stores.kyberPreKey.hasKyberPreKey(id)
    );
    const kyberKeyPair = SignalClient.KEMKeyPair.generate();
    const kyberSignature = identityKey.sign(
      kyberKeyPair.getPublicKey().serialize()
    );
    await this.stores.kyberPreKey.saveKyberPreKey(
      kyberPreKeyId,
      SignalClient.KyberPreKeyRecord.new(
        kyberPreKeyId,
        Date.now(),
        kyberKeyPair,
        kyberSignature
      )
    );

    return SignalClient.PreKeyBundle.new(
      await this.stores.identity.getLocalRegistrationId(),
      this.address.deviceId(),
      preKeyId,
      preKey.getPublicKey(),
      signedPreKeyId,
      signedPreKey.getPublicKey(),
      signedPreKeySignature,
      identityKey.getPublicKey(),
      kyberPreKeyId,
      kyberKeyPair.getPublicKey(),
      kyberSignature
    );
  }


  async createPreKeyGeneration(
    oneTimeCount: number,
    timestampMs = Date.now()
  ): Promise<PreKeyGenerationMaterial> {
    if (
      !Number.isSafeInteger(oneTimeCount) ||
      oneTimeCount <= 0 ||
      oneTimeCount > MAX_ONE_TIME_PREKEY_BUNDLES
    ) {
      throw new Error(
        `oneTimeCount must be between 1 and ${MAX_ONE_TIME_PREKEY_BUNDLES}`
      );
    }
    if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) {
      throw new Error('timestampMs must be a non-negative safe integer');
    }

    const identityKey = await this.stores.identity.getIdentityKey();
    const registrationId =
      await this.stores.identity.getLocalRegistrationId();

    const signedPreKeyId = uniqueRandomId((id) =>
      this.stores.signedPreKey.hasSignedPreKey(id)
    );
    const signedPreKey = SignalClient.PrivateKey.generate();
    const signedPreKeySignature = identityKey.sign(
      signedPreKey.getPublicKey().serialize()
    );
    await this.stores.signedPreKey.saveSignedPreKey(
      signedPreKeyId,
      SignalClient.SignedPreKeyRecord.new(
        signedPreKeyId,
        timestampMs,
        signedPreKey.getPublicKey(),
        signedPreKey,
        signedPreKeySignature
      )
    );

    const lastResortKyberPreKeyId = uniqueRandomId((id) =>
      this.stores.kyberPreKey.hasKyberPreKey(id)
    );
    const lastResortKyberKeyPair = SignalClient.KEMKeyPair.generate();
    const lastResortKyberSignature = identityKey.sign(
      lastResortKyberKeyPair.getPublicKey().serialize()
    );
    await this.stores.kyberPreKey.saveKyberPreKey(
      lastResortKyberPreKeyId,
      SignalClient.KyberPreKeyRecord.new(
        lastResortKyberPreKeyId,
        timestampMs,
        lastResortKyberKeyPair,
        lastResortKyberSignature
      )
    );

    const oneTimeBundles: SignalClient.PreKeyBundle[] = [];
    const oneTimeKeyIds: Array<readonly [number, number]> = [];

    for (let index = 0; index < oneTimeCount; index += 1) {
      const preKeyId = uniqueRandomId((id) =>
        this.stores.preKey.hasPreKey(id)
      );
      const preKey = SignalClient.PrivateKey.generate();
      await this.stores.preKey.savePreKey(
        preKeyId,
        SignalClient.PreKeyRecord.new(
          preKeyId,
          preKey.getPublicKey(),
          preKey
        )
      );

      const kyberPreKeyId = uniqueRandomId((id) =>
        this.stores.kyberPreKey.hasKyberPreKey(id)
      );
      const kyberKeyPair = SignalClient.KEMKeyPair.generate();
      const kyberSignature = identityKey.sign(
        kyberKeyPair.getPublicKey().serialize()
      );
      await this.stores.kyberPreKey.saveKyberPreKey(
        kyberPreKeyId,
        SignalClient.KyberPreKeyRecord.new(
          kyberPreKeyId,
          timestampMs,
          kyberKeyPair,
          kyberSignature
        )
      );

      oneTimeKeyIds.push([preKeyId, kyberPreKeyId]);
      oneTimeBundles.push(
        SignalClient.PreKeyBundle.new(
          registrationId,
          this.address.deviceId(),
          preKeyId,
          preKey.getPublicKey(),
          signedPreKeyId,
          signedPreKey.getPublicKey(),
          signedPreKeySignature,
          identityKey.getPublicKey(),
          kyberPreKeyId,
          kyberKeyPair.getPublicKey(),
          kyberSignature
        )
      );
    }

    const fallbackBundle = SignalClient.PreKeyBundle.new(
      registrationId,
      this.address.deviceId(),
      null,
      null,
      signedPreKeyId,
      signedPreKey.getPublicKey(),
      signedPreKeySignature,
      identityKey.getPublicKey(),
      lastResortKyberPreKeyId,
      lastResortKyberKeyPair.getPublicKey(),
      lastResortKyberSignature
    );

    return {
      oneTimeBundles,
      fallbackBundle,
      signedPreKeyId,
      lastResortKyberPreKeyId,
      oneTimeKeyIds,
    };
  }

  async loadPreKeyGeneration(
    state: PreKeyGenerationState
  ): Promise<PreKeyGenerationMaterial> {
    const identityKey = await this.stores.identity.getIdentityKey();
    const registrationId =
      await this.stores.identity.getLocalRegistrationId();

    const signedPreKey = await this.stores.signedPreKey.getSignedPreKey(
      state.signedPreKeyId
    );
    if (signedPreKey.id() !== state.signedPreKeyId) {
      throw new Error('signed pre-key record ID does not match lifecycle state');
    }

    const lastResortKyber = await this.stores.kyberPreKey.getKyberPreKey(
      state.lastResortKyberPreKeyId
    );
    if (lastResortKyber.id() !== state.lastResortKyberPreKeyId) {
      throw new Error(
        'last-resort Kyber record ID does not match lifecycle state'
      );
    }

    const oneTimeBundles: SignalClient.PreKeyBundle[] = [];

    for (const [preKeyId, kyberPreKeyId] of state.oneTimeKeyIds) {
      const preKey = await this.stores.preKey.getPreKey(preKeyId);
      if (preKey.id() !== preKeyId) {
        throw new Error('EC pre-key record ID does not match lifecycle state');
      }

      const kyberPreKey = await this.stores.kyberPreKey.getKyberPreKey(
        kyberPreKeyId
      );
      if (kyberPreKey.id() !== kyberPreKeyId) {
        throw new Error(
          'one-time Kyber record ID does not match lifecycle state'
        );
      }

      oneTimeBundles.push(
        SignalClient.PreKeyBundle.new(
          registrationId,
          this.address.deviceId(),
          preKeyId,
          preKey.publicKey(),
          signedPreKey.id(),
          signedPreKey.publicKey(),
          signedPreKey.signature(),
          identityKey.getPublicKey(),
          kyberPreKey.id(),
          kyberPreKey.publicKey(),
          kyberPreKey.signature()
        )
      );
    }

    const fallbackBundle = SignalClient.PreKeyBundle.new(
      registrationId,
      this.address.deviceId(),
      null,
      null,
      signedPreKey.id(),
      signedPreKey.publicKey(),
      signedPreKey.signature(),
      identityKey.getPublicKey(),
      lastResortKyber.id(),
      lastResortKyber.publicKey(),
      lastResortKyber.signature()
    );

    return {
      oneTimeBundles,
      fallbackBundle,
      signedPreKeyId: signedPreKey.id(),
      lastResortKyberPreKeyId: lastResortKyber.id(),
      oneTimeKeyIds: state.oneTimeKeyIds,
    };
  }

  async establishSessionAt(
    remoteAddress: SignalClient.ProtocolAddress,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    await SignalClient.processPreKeyBundle(
      bundle,
      remoteAddress,
      this.address,
      this.stores.session,
      this.stores.identity
    );
  }

  async establishSession(
    remote: RatchetParty,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    await this.establishSessionAt(remote.address, bundle);
  }

  async encryptBytes(
    remoteAddress: SignalClient.ProtocolAddress,
    plaintext: Uint8Array
  ): Promise<WireMessage> {
    const ciphertext = await SignalClient.signalEncrypt(
      Uint8Array.from(plaintext),
      remoteAddress,
      this.address,
      this.stores.session,
      this.stores.identity
    );

    return {
      type: ciphertext.type(),
      body: Uint8Array.from(ciphertext.serialize()),
    };
  }

  async encrypt(remote: RatchetParty, plaintext: string): Promise<WireMessage> {
    return this.encryptBytes(
      remote.address,
      Buffer.from(plaintext, 'utf8')
    );
  }

  async decryptBytes(
    remoteAddress: SignalClient.ProtocolAddress,
    message: WireMessage
  ): Promise<Uint8Array> {
    let plaintext: Uint8Array;

    if (message.type === SignalClient.CiphertextMessageType.PreKey) {
      plaintext = await SignalClient.signalDecryptPreKey(
        SignalClient.PreKeySignalMessage.deserialize(
          Uint8Array.from(message.body)
        ),
        remoteAddress,
        this.address,
        this.stores.session,
        this.stores.identity,
        this.stores.preKey,
        this.stores.signedPreKey,
        this.stores.kyberPreKey
      );
    } else if (message.type === SignalClient.CiphertextMessageType.Whisper) {
      plaintext = await SignalClient.signalDecrypt(
        SignalClient.SignalMessage.deserialize(
          Uint8Array.from(message.body)
        ),
        remoteAddress,
        this.address,
        this.stores.session,
        this.stores.identity
      );
    } else {
      throw new Error(`unsupported libsignal message type: ${message.type}`);
    }

    return Uint8Array.from(plaintext);
  }

  async decrypt(remote: RatchetParty, message: WireMessage): Promise<string> {
    const plaintext = await this.decryptBytes(remote.address, message);
    return Buffer.from(plaintext).toString('utf8');
  }

  compromisedClone(): RatchetParty {
    const stores: PartyStores = {
      session: this.stores.session.clone(),
      identity: this.stores.identity.clone(),
      preKey: new MemoryPreKeyStore(),
      signedPreKey: new MemorySignedPreKeyStore(),
      kyberPreKey: new MemoryKyberPreKeyStore(),
      lifecycle: new MemoryPreKeyLifecycleStore(),
    };

    return new RatchetParty(
      this.address.name(),
      this.address.deviceId(),
      stores.identity.exportState().registrationId,
      stores
    );
  }
}