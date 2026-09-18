import assert from 'node:assert/strict';
import test from 'node:test';

import * as SignalClient from '@signalapp/libsignal-client';

import { RatchetParty, type WireMessage } from '../src/party.js';

async function establishPair(): Promise<{
  alice: RatchetParty;
  bob: RatchetParty;
}> {
  const alice = new RatchetParty('alice', 1, 41001);
  const bob = new RatchetParty('bob', 1, 42001);

  const bobBundle = await bob.createPreKeyBundle();
  await alice.establishSession(bob, bobBundle);

  const first = await alice.encrypt(bob, 'A1');
  assert.equal(first.type, SignalClient.CiphertextMessageType.PreKey);
  assert.equal(await bob.decrypt(alice, first), 'A1');

  const reply = await bob.encrypt(alice, 'B1');
  assert.equal(reply.type, SignalClient.CiphertextMessageType.Whisper);
  assert.equal(await alice.decrypt(bob, reply), 'B1');

  return { alice, bob };
}

test('PQXDH establishes a bidirectional ratcheted session', async () => {
  const { alice, bob } = await establishPair();

  const a2 = await alice.encrypt(bob, 'A2');
  assert.equal(a2.type, SignalClient.CiphertextMessageType.Whisper);
  assert.equal(await bob.decrypt(alice, a2), 'A2');

  const b2 = await bob.encrypt(alice, 'B2');
  assert.equal(await alice.decrypt(bob, b2), 'B2');

  const bobSession = await bob.stores.session.getSession(alice.address);
  assert.notEqual(bobSession, null);
  assert.ok(bobSession!.serialize().byteLength > 0);
});

test('out-of-order messages decrypt through skipped message keys', async () => {
  const { alice, bob } = await establishPair();

  const messages: WireMessage[] = [
    await alice.encrypt(bob, 'one'),
    await alice.encrypt(bob, 'two'),
    await alice.encrypt(bob, 'three'),
  ];

  assert.equal(await bob.decrypt(alice, messages[2]!), 'three');
  assert.equal(await bob.decrypt(alice, messages[0]!), 'one');
  assert.equal(await bob.decrypt(alice, messages[1]!), 'two');
});

test('duplicated ratchet messages are rejected', async () => {
  const { alice, bob } = await establishPair();

  const message = await alice.encrypt(bob, 'display-once');
  assert.equal(await bob.decrypt(alice, message), 'display-once');

  await assert.rejects(
    () => bob.decrypt(alice, message),
    (error: unknown) => {
      if (!(error instanceof Error)) {
        return false;
      }
      assert.equal(error.name, 'DuplicatedMessage');
      return true;
    }
  );
});

test('an old compromised session snapshot loses access after fresh ratchet entropy', async () => {
  const { alice, bob } = await establishPair();

  // Snapshot Alice after the first bidirectional exchange. This represents
  // an attacker obtaining the complete current identity + session state.
  const attacker = alice.compromisedClone();

  // Alice sends with the currently compromised sending chain. Bob receives
  // it and advances, creating fresh Bob ratchet state.
  const a2 = await alice.encrypt(bob, 'A2-compromised-chain');
  assert.equal(await bob.decrypt(alice, a2), 'A2-compromised-chain');

  // Bob's next message can still be processed by both the honest Alice and
  // the stolen snapshot. Each side independently generates its next local
  // ratchet private key while processing this new Bob ratchet key.
  const b2 = await bob.encrypt(alice, 'B2-recovery-trigger');
  assert.equal(await alice.decrypt(bob, b2), 'B2-recovery-trigger');
  assert.equal(await attacker.decrypt(bob, b2), 'B2-recovery-trigger');

  // Honest Alice now advertises a ratchet public key whose private half was
  // generated after compromise. The attacker's independently generated key
  // is different and is never sent to Bob.
  const a3 = await alice.encrypt(bob, 'A3-fresh-alice-ratchet');
  assert.equal(await bob.decrypt(alice, a3), 'A3-fresh-alice-ratchet');

  // Bob mixes Alice's fresh ratchet key and replies. Honest Alice can derive
  // the new receive chain; the compromised snapshot cannot.
  const b3 = await bob.encrypt(alice, 'B3-post-recovery');
  assert.equal(await alice.decrypt(bob, b3), 'B3-post-recovery');

  await assert.rejects(() => attacker.decrypt(bob, b3));
});