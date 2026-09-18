import * as SignalClient from '@signalapp/libsignal-client';

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

export class RatchetParty {
  readonly address: SignalClient.ProtocolAddress;
  readonly stores: PartyStores;

  constructor(
    name: string,
    deviceId: number,
    registrationId: number,
    stores: PartyStores = createPartyStores(registrationId)
  ) {
    this.address = SignalClient.ProtocolAddress.new(name, deviceId);
    this.stores = stores;
  }

  async createPreKeyBundle(): Promise<SignalClient.PreKeyBundle> {
    const identityKey = await this.stores.identity.getIdentityKey();

    const preKeyId = 1001;
    const preKey = SignalClient.PrivateKey.generate();
    await this.stores.preKey.savePreKey(
      preKeyId,
      SignalClient.PreKeyRecord.new(
        preKeyId,
        preKey.getPublicKey(),
        preKey
      )
    );

    const signedPreKeyId = 2001;
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

    const kyberPreKeyId = 3001;
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

  async establishSession(
    remote: RatchetParty,
    bundle: SignalClient.PreKeyBundle
  ): Promise<void> {
    await SignalClient.processPreKeyBundle(
      bundle,
      remote.address,
      this.address,
      this.stores.session,
      this.stores.identity
    );
  }

  async encrypt(remote: RatchetParty, plaintext: string): Promise<WireMessage> {
    const ciphertext = await SignalClient.signalEncrypt(
      Buffer.from(plaintext, 'utf8'),
      remote.address,
      this.address,
      this.stores.session,
      this.stores.identity
    );

    return {
      type: ciphertext.type(),
      body: Uint8Array.from(ciphertext.serialize()),
    };
  }

  async decrypt(remote: RatchetParty, message: WireMessage): Promise<string> {
    let plaintext: Uint8Array;

    if (message.type === SignalClient.CiphertextMessageType.PreKey) {
      plaintext = await SignalClient.signalDecryptPreKey(
        SignalClient.PreKeySignalMessage.deserialize(Buffer.from(message.body)),
        remote.address,
        this.address,
        this.stores.session,
        this.stores.identity,
        this.stores.preKey,
        this.stores.signedPreKey,
        this.stores.kyberPreKey
      );
    } else if (message.type === SignalClient.CiphertextMessageType.Whisper) {
      plaintext = await SignalClient.signalDecrypt(
        SignalClient.SignalMessage.deserialize(Buffer.from(message.body)),
        remote.address,
        this.address,
        this.stores.session,
        this.stores.identity
      );
    } else {
      throw new Error(`unsupported libsignal message type: ${message.type}`);
    }

    return Buffer.from(plaintext).toString('utf8');
  }

  compromisedClone(): RatchetParty {
    const stores: PartyStores = {
      session: this.stores.session.clone(),
      identity: this.stores.identity.clone(),
      preKey: new MemoryPreKeyStore(),
      signedPreKey: new MemorySignedPreKeyStore(),
      kyberPreKey: new MemoryKyberPreKeyStore(),
    };

    return new RatchetParty(
      this.address.name(),
      this.address.deviceId(),
      0,
      stores
    );
  }
}