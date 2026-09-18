import assert from 'node:assert/strict';
import test from 'node:test';

import * as SignalClient from '@signalapp/libsignal-client';

import {
  exportPreKeyMaterial,
  importPreKeyMaterial,
  type WirePreKeyMaterial,
} from '../src/prekey-material.js';
import { RatchetParty } from '../src/party.js';

test('official libsignal pre-key bundle round-trips through public wire material', async () => {
  const alice = new RatchetParty('alice-device', 1, 4101);
  const bob = new RatchetParty('bob-device', 1, 4201);

  const original = await bob.createPreKeyBundle();
  const material = exportPreKeyMaterial(original);

  assert.equal(material.version, 1);
  assert.equal(material.signal_device_id, 1);
  assert.equal(Buffer.from(material.identity_key, 'base64').length, 33);
  assert.equal(Buffer.from(material.signed_pre_key, 'base64').length, 33);
  assert.equal(
    Buffer.from(material.signed_pre_key_signature, 'base64').length,
    64
  );
  assert.ok(Buffer.from(material.kyber_pre_key, 'base64').length > 0);
  assert.equal(
    Buffer.from(material.kyber_pre_key_signature, 'base64').length,
    64
  );

  const reconstructed = importPreKeyMaterial(material);
  await alice.establishSession(bob, reconstructed);

  const message = await alice.encrypt(bob, 'bound-bundle');
  assert.equal(message.type, SignalClient.CiphertextMessageType.PreKey);
  assert.equal(await bob.decrypt(alice, message), 'bound-bundle');
});

test('wire material supports an exhausted one-time EC pre-key', async () => {
  const bob = new RatchetParty('bob-device', 1, 4201);
  const original = await bob.createPreKeyBundle();

  const withoutOneTimePreKey = SignalClient.PreKeyBundle.new(
    original.registrationId(),
    original.deviceId(),
    null,
    null,
    original.signedPreKeyId(),
    original.signedPreKeyPublic(),
    original.signedPreKeySignature(),
    original.identityKey(),
    original.kyberPreKeyId(),
    original.kyberPreKeyPublic(),
    original.kyberPreKeySignature()
  );

  const material = exportPreKeyMaterial(withoutOneTimePreKey);
  assert.equal(material.pre_key_id, null);
  assert.equal(material.pre_key, null);

  const reconstructed = importPreKeyMaterial(material);
  assert.equal(reconstructed.preKeyId(), null);
  assert.equal(reconstructed.preKeyPublic(), null);
});

test('wire material rejects a partial optional one-time pre-key', async () => {
  const bob = new RatchetParty('bob-device', 1, 4201);
  const material = exportPreKeyMaterial(await bob.createPreKeyBundle());

  const invalid: WirePreKeyMaterial = {
    ...material,
    pre_key: null,
  };

  assert.throws(
    () => importPreKeyMaterial(invalid),
    /pre_key_id and pre_key/
  );
});

test('wire material rejects modified or unknown structure', async () => {
  const bob = new RatchetParty('bob-device', 1, 4201);
  const material = exportPreKeyMaterial(await bob.createPreKeyBundle());

  assert.throws(
    () =>
      importPreKeyMaterial({
        ...material,
        identity_key: material.identity_key + '=',
      }),
    /canonical Base64/
  );

  assert.throws(
    () =>
      importPreKeyMaterial({
        ...material,
        unexpected: 'field',
      }),
    /fields do not match/
  );
});