import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import * as SignalClient from '@signalapp/libsignal-client';

import { RatchetParty } from '../src/party.js';
import {
  PersistentRatchetParty,
  RETIRED_PREKEY_RETENTION_SECONDS,
} from '../src/persistent-party.js';

async function temporaryDirectory(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'ghostlink-prekey-generation-'));
}

test('pre-key generation shares signed material and separates one-time/fallback keys', async () => {
  const bob = new RatchetParty('bob', 1, 4_200);
  const generation = await bob.createPreKeyGeneration(4, 1_000_000);

  assert.equal(generation.oneTimeBundles.length, 4);
  assert.equal(generation.oneTimeKeyIds.length, 4);
  assert.equal(generation.fallbackBundle.preKeyId(), null);
  assert.equal(generation.fallbackBundle.preKeyPublic(), null);
  assert.equal(
    generation.fallbackBundle.kyberPreKeyId(),
    generation.lastResortKyberPreKeyId
  );

  const ecIds = new Set<number>();
  const kyberIds = new Set<number>();

  for (const bundle of generation.oneTimeBundles) {
    assert.equal(bundle.signedPreKeyId(), generation.signedPreKeyId);
    assert.notEqual(bundle.preKeyId(), null);
    assert.notEqual(
      bundle.kyberPreKeyId(),
      generation.lastResortKyberPreKeyId
    );
    ecIds.add(bundle.preKeyId()!);
    kyberIds.add(bundle.kyberPreKeyId());
  }

  assert.equal(ecIds.size, 4);
  assert.equal(kyberIds.size, 4);
  assert.equal(kyberIds.has(generation.lastResortKyberPreKeyId), false);
});

test('one-time and fallback generation bundles establish real libsignal sessions', async () => {
  const bob = new RatchetParty('bob', 1, 4_200);
  const alice = new RatchetParty('alice', 1, 4_201);
  const charlie = new RatchetParty('charlie', 1, 4_202);
  const dana = new RatchetParty('dana', 1, 4_203);

  const generation = await bob.createPreKeyGeneration(2, 1_000_000);

  await alice.establishSession(bob, generation.oneTimeBundles[0]!);
  const fromAlice = await alice.encrypt(bob, 'one-time');
  assert.equal(
    fromAlice.type,
    SignalClient.CiphertextMessageType.PreKey
  );
  assert.equal(await bob.decrypt(alice, fromAlice), 'one-time');

  await charlie.establishSession(bob, generation.fallbackBundle);
  const fromCharlie = await charlie.encrypt(bob, 'fallback-one');
  assert.equal(await bob.decrypt(charlie, fromCharlie), 'fallback-one');

  await dana.establishSession(bob, generation.fallbackBundle);
  const fromDana = await dana.encrypt(bob, 'fallback-two');
  assert.equal(await bob.decrypt(dana, fromDana), 'fallback-two');

  const state = bob.stores.kyberPreKey.exportState();
  assert.equal(
    state.used.includes(generation.lastResortKyberPreKeyId),
    true
  );
});

test('persistent prepare commits one pending generation and survives reopen', async () => {
  const directory = await temporaryDirectory();
  const path = join(directory, 'bob.ratchet');
  const key = randomBytes(32);

  const bob = await PersistentRatchetParty.open('bob', 1, path, key);
  const generation = await bob.preparePreKeyGeneration(4, 1_000, 3_600);
  const beforeClose = await bob.exportStateForTesting();

  assert.equal(generation.sequence, 1);
  assert.equal(generation.createdAt, 1_000);
  assert.equal(generation.expiresAt, 4_600);
  assert.equal(generation.oneTimeBundles.length, 4);
  assert.equal(beforeClose.lifecycle.publicationSequence, 1);
  assert.notEqual(beforeClose.lifecycle.pending, null);
  assert.equal(beforeClose.lifecycle.pending?.sequence, 1);
  assert.equal(beforeClose.lifecycle.pending?.publicPayload, null);
  assert.equal(beforeClose.preKey.length, 4);
  assert.equal(beforeClose.signedPreKey.length, 1);
  assert.equal(beforeClose.kyberPreKey.records.length, 5);

  bob.close();

  const reopened = await PersistentRatchetParty.open('bob', 1, path, key);
  const afterReopen = await reopened.exportStateForTesting();

  assert.deepEqual(afterReopen.lifecycle, beforeClose.lifecycle);
  assert.deepEqual(afterReopen.preKey, beforeClose.preKey);
  assert.deepEqual(afterReopen.signedPreKey, beforeClose.signedPreKey);
  assert.deepEqual(afterReopen.kyberPreKey, beforeClose.kyberPreKey);

  reopened.close();
});

test('a pending generation blocks replacement without changing the vault', async () => {
  const directory = await temporaryDirectory();
  const path = join(directory, 'bob.ratchet');
  const key = randomBytes(32);

  const bob = await PersistentRatchetParty.open('bob', 1, path, key);
  await bob.preparePreKeyGeneration(3, 1_000, 3_600);

  const beforeState = await bob.exportStateForTesting();
  const beforeFile = await readFile(path);

  await assert.rejects(
    () => bob.preparePreKeyGeneration(3, 1_100, 3_600),
    /pending pre-key generation already exists/
  );

  const afterState = await bob.exportStateForTesting();
  const afterFile = await readFile(path);

  assert.deepEqual(afterState, beforeState);
  assert.deepEqual(afterFile, beforeFile);

  bob.close();
});


test('publication acknowledgement atomically promotes pending and retires active', async () => {
  const directory = await temporaryDirectory();
  const path = join(directory, 'bob-commit.ratchet');
  const key = randomBytes(32);

  const bob = await PersistentRatchetParty.open('bob', 1, path, key);

  const first = await bob.preparePreKeyGeneration(3, 1_000, 3_600);
  await bob.stagePreKeyPublication(first.sequence, '{"sequence":1}');
  await bob.commitPreKeyPublication(first.sequence, 1_100);

  const firstState = await bob.exportStateForTesting();
  assert.equal(firstState.lifecycle.pending, null);
  assert.equal(firstState.lifecycle.active?.sequence, 1);
  assert.equal(firstState.lifecycle.active?.publishedAt, 1_100);
  assert.equal(firstState.lifecycle.active?.retiredAt, null);
  assert.deepEqual(firstState.lifecycle.retired, []);

  await bob.commitPreKeyPublication(first.sequence, 1_200);
  const idempotentState = await bob.exportStateForTesting();
  assert.deepEqual(idempotentState.lifecycle, firstState.lifecycle);

  const second = await bob.preparePreKeyGeneration(3, 1_200, 3_600);
  await bob.stagePreKeyPublication(second.sequence, '{"sequence":2}');
  await bob.commitPreKeyPublication(second.sequence, 1_300);

  const secondState = await bob.exportStateForTesting();
  assert.equal(secondState.lifecycle.pending, null);
  assert.equal(secondState.lifecycle.active?.sequence, 2);
  assert.equal(secondState.lifecycle.active?.publishedAt, 1_300);
  assert.equal(secondState.lifecycle.retired.length, 1);
  assert.equal(secondState.lifecycle.retired[0]?.sequence, 1);
  assert.equal(secondState.lifecycle.retired[0]?.retiredAt, 1_300);

  bob.close();

  const reopened = await PersistentRatchetParty.open('bob', 1, path, key);
  const afterReopen = await reopened.exportStateForTesting();
  assert.deepEqual(afterReopen.lifecycle, secondState.lifecycle);
  reopened.close();
});

test('publication acknowledgement requires staged matching pending generation', async () => {
  const directory = await temporaryDirectory();
  const path = join(directory, 'bob-invalid-commit.ratchet');
  const key = randomBytes(32);

  const bob = await PersistentRatchetParty.open('bob', 1, path, key);
  const generation = await bob.preparePreKeyGeneration(3, 1_000, 3_600);

  const before = await readFile(path);
  await assert.rejects(
    () => bob.commitPreKeyPublication(generation.sequence, 1_100),
    /has not been staged/
  );
  assert.deepEqual(await readFile(path), before);

  await bob.stagePreKeyPublication(generation.sequence, '{"sequence":1}');
  const staged = await readFile(path);

  await assert.rejects(
    () => bob.commitPreKeyPublication(generation.sequence + 1, 1_100),
    /sequence does not match/
  );
  assert.deepEqual(await readFile(path), staged);

  await assert.rejects(
    () => bob.commitPreKeyPublication(generation.sequence, 4_600),
    /outside generation lifetime/
  );
  assert.deepEqual(await readFile(path), staged);

  bob.close();
});


test('remote publication rollback leaves ratchet state and vault unchanged', async () => {
  const directory = await temporaryDirectory();
  const alicePath = join(directory, 'alice-remote-seq.ratchet');
  const bobPath = join(directory, 'bob-remote-seq.ratchet');
  const aliceKey = randomBytes(32);
  const bobKey = randomBytes(32);
  const aliceDeviceId = 'device1:' + 'a'.repeat(52);
  const bobDeviceId = 'device1:' + 'b'.repeat(52);

  const alice = await PersistentRatchetParty.open(
    aliceDeviceId,
    1,
    alicePath,
    aliceKey
  );
  const bob = await PersistentRatchetParty.open(
    bobDeviceId,
    1,
    bobPath,
    bobKey
  );

  const currentBundle = await bob.createPreKeyBundle();
  await alice.establishSessionWithAddress(
    bobDeviceId,
    2,
    currentBundle
  );

  const beforeState = await alice.exportStateForTesting();
  const beforeFile = await readFile(alicePath);

  const rollbackBundle = await bob.createPreKeyBundle();
  await assert.rejects(
    () =>
      alice.establishSessionWithAddress(
        bobDeviceId,
        1,
        rollbackBundle
      ),
    /remote publication sequence regressed/
  );

  assert.deepEqual(await alice.exportStateForTesting(), beforeState);
  assert.deepEqual(await readFile(alicePath), beforeFile);

  alice.close();
  bob.close();

  const reopened = await PersistentRatchetParty.open(
    aliceDeviceId,
    1,
    alicePath,
    aliceKey
  );
  const reopenedState = await reopened.exportStateForTesting();
  assert.deepEqual(
    reopenedState.remotePublicationSequences,
    [[bobDeviceId, 2]]
  );
  reopened.close();
});


test('garbage collection removes only retired generations past retention', async () => {
  const directory = await temporaryDirectory();
  const path = join(directory, 'bob-gc.ratchet');
  const key = randomBytes(32);
  const bob = await PersistentRatchetParty.open('bob', 1, path, key);

  const first = await bob.preparePreKeyGeneration(2, 1_000, 3_600);
  await bob.stagePreKeyPublication(first.sequence, '{"sequence":1}');
  await bob.commitPreKeyPublication(first.sequence, 1_100);

  const second = await bob.preparePreKeyGeneration(2, 1_200, 3_600);
  await bob.stagePreKeyPublication(second.sequence, '{"sequence":2}');
  await bob.commitPreKeyPublication(second.sequence, 1_300);

  const beforeState = await bob.exportStateForTesting();
  const beforeFile = await readFile(path);

  const early = await bob.garbageCollectPreKeys(
    1_300 + RETIRED_PREKEY_RETENTION_SECONDS - 1
  );
  assert.deepEqual(early, {
    retiredGenerationsRemoved: 0,
    preKeysRemoved: 0,
    signedPreKeysRemoved: 0,
    kyberPreKeysRemoved: 0,
  });
  assert.deepEqual(await bob.exportStateForTesting(), beforeState);
  assert.deepEqual(await readFile(path), beforeFile);

  const collected = await bob.garbageCollectPreKeys(
    1_300 + RETIRED_PREKEY_RETENTION_SECONDS
  );
  assert.deepEqual(collected, {
    retiredGenerationsRemoved: 1,
    preKeysRemoved: 2,
    signedPreKeysRemoved: 1,
    kyberPreKeysRemoved: 3,
  });

  const after = await bob.exportStateForTesting();
  assert.equal(after.lifecycle.retired.length, 0);
  assert.equal(after.lifecycle.active?.sequence, second.sequence);

  for (const [preKeyId, kyberPreKeyId] of first.oneTimeKeyIds) {
    assert.equal(after.preKey.some(([id]) => id === preKeyId), false);
    assert.equal(
      after.kyberPreKey.records.some(([id]) => id === kyberPreKeyId),
      false
    );
  }
  assert.equal(
    after.signedPreKey.some(([id]) => id === first.signedPreKeyId),
    false
  );
  assert.equal(
    after.kyberPreKey.records.some(
      ([id]) => id === first.lastResortKyberPreKeyId
    ),
    false
  );

  for (const [preKeyId, kyberPreKeyId] of second.oneTimeKeyIds) {
    assert.equal(after.preKey.some(([id]) => id === preKeyId), true);
    assert.equal(
      after.kyberPreKey.records.some(([id]) => id === kyberPreKeyId),
      true
    );
  }
  assert.equal(
    after.signedPreKey.some(([id]) => id === second.signedPreKeyId),
    true
  );
  assert.equal(
    after.kyberPreKey.records.some(
      ([id]) => id === second.lastResortKyberPreKeyId
    ),
    true
  );

  bob.close();

  const reopened = await PersistentRatchetParty.open('bob', 1, path, key);
  assert.deepEqual(await reopened.exportStateForTesting(), after);
  reopened.close();
});

test('garbage collection rejects clock rollback without changing the vault', async () => {
  const directory = await temporaryDirectory();
  const path = join(directory, 'bob-gc-clock.ratchet');
  const key = randomBytes(32);
  const bob = await PersistentRatchetParty.open('bob', 1, path, key);

  const first = await bob.preparePreKeyGeneration(1, 1_000, 3_600);
  await bob.stagePreKeyPublication(first.sequence, '{"sequence":1}');
  await bob.commitPreKeyPublication(first.sequence, 1_100);
  const second = await bob.preparePreKeyGeneration(1, 1_200, 3_600);
  await bob.stagePreKeyPublication(second.sequence, '{"sequence":2}');
  await bob.commitPreKeyPublication(second.sequence, 1_300);

  const beforeState = await bob.exportStateForTesting();
  const beforeFile = await readFile(path);

  await assert.rejects(
    () => bob.garbageCollectPreKeys(1_299),
    /current time predates a retired pre-key generation/
  );

  assert.deepEqual(await bob.exportStateForTesting(), beforeState);
  assert.deepEqual(await readFile(path), beforeFile);
  bob.close();
});
