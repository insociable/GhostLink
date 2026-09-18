import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  emptyPreKeyLifecycleState,
  parsePreKeyLifecycleState,
} from '../src/prekey-lifecycle-state.js';
import {
  createPartyStores,
  exportPartyStores,
  parsePartyStoresState,
  restorePartyStores,
  type PartyStoresState,
} from '../src/stores.js';
import { RatchetStateVault } from '../src/vault.js';

function lifecycleFixture() {
  return parsePreKeyLifecycleState({
    version: 1,
    publicationSequence: 3,
    pending: {
      sequence: 3,
      createdAt: 3_000,
      expiresAt: 4_000,
      signedPreKeyId: 2003,
      lastResortKyberPreKeyId: 3003,
      oneTimeKeyIds: [
        [1003, 4003],
        [1004, 4004],
      ],
      publicPayload: '{"sequence":3,"bindings":[]}',
      publishedAt: null,
      retiredAt: null,
    },
    active: {
      sequence: 2,
      createdAt: 2_000,
      expiresAt: 3_000,
      signedPreKeyId: 2002,
      lastResortKyberPreKeyId: 3002,
      oneTimeKeyIds: [[1002, 4002]],
      publicPayload: '{"sequence":2,"bindings":[]}',
      publishedAt: 2_100,
      retiredAt: null,
    },
    retired: [
      {
        sequence: 1,
        createdAt: 1_000,
        expiresAt: 2_000,
        signedPreKeyId: 2001,
        lastResortKyberPreKeyId: 3001,
        oneTimeKeyIds: [[1001, 4001]],
        publicPayload: '{"sequence":1,"bindings":[]}',
        publishedAt: 1_100,
        retiredAt: 2_100,
      },
    ],
  });
}

test('legacy stores state v1 migrates to empty lifecycle state', () => {
  const current = exportPartyStores(createPartyStores(4_200));

  const legacy = {
    version: 1,
    session: current.session,
    identity: current.identity,
    preKey: current.preKey,
    signedPreKey: current.signedPreKey,
    kyberPreKey: current.kyberPreKey,
  };

  const migrated = parsePartyStoresState(legacy);

  assert.equal(migrated.version, 2);
  assert.deepEqual(migrated.lifecycle, emptyPreKeyLifecycleState());
});

test('stores state v2 round-trips lifecycle metadata', () => {
  const current = exportPartyStores(createPartyStores(4_200));
  const lifecycle = lifecycleFixture();
  const state: PartyStoresState = {
    ...current,
    lifecycle,
  };

  const restored = restorePartyStores(state);
  const roundTrip = exportPartyStores(restored);

  assert.deepEqual(roundTrip.lifecycle, lifecycle);
  assert.equal(roundTrip.version, 2);
});

test('lifecycle state rejects duplicate one-time key identifiers', () => {
  assert.throws(
    () =>
      parsePreKeyLifecycleState({
        version: 1,
        publicationSequence: 1,
        pending: {
          sequence: 1,
          createdAt: 1_000,
          expiresAt: 2_000,
          signedPreKeyId: 2001,
          lastResortKyberPreKeyId: 3001,
          oneTimeKeyIds: [
            [1001, 4001],
            [1001, 4002],
          ],
          publicPayload: null,
          publishedAt: null,
          retiredAt: null,
        },
        active: null,
        retired: [],
      }),
    /duplicate EC pre-key/
  );
});

test('pending generation must be the newest allocated sequence', () => {
  assert.throws(
    () =>
      parsePreKeyLifecycleState({
        version: 1,
        publicationSequence: 2,
        pending: {
          sequence: 1,
          createdAt: 1_000,
          expiresAt: 2_000,
          signedPreKeyId: 2001,
          lastResortKyberPreKeyId: 3001,
          oneTimeKeyIds: [],
          publicPayload: null,
          publishedAt: null,
          retiredAt: null,
        },
        active: null,
        retired: [],
      }),
    /pending sequence must equal publicationSequence/
  );
});

test('lifecycle metadata and pending public payload are encrypted at rest', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghostlink-lifecycle-'));
  const path = join(directory, 'alice.ratchet');
  const vault = new RatchetStateVault(path, randomBytes(32));
  const current = exportPartyStores(createPartyStores(4_200));
  const lifecycle = lifecycleFixture();
  const state: PartyStoresState = {
    ...current,
    lifecycle,
  };

  await vault.save({ name: 'alice', deviceId: 1 }, state);

  const raw = await readFile(path, 'utf8');
  assert.equal(raw.includes('publicationSequence'), false);
  assert.equal(raw.includes('bindings'), false);
  assert.equal(raw.includes('signedPreKeyId'), false);

  const loaded = await vault.load({ name: 'alice', deviceId: 1 });
  assert.notEqual(loaded, null);
  assert.deepEqual(loaded?.lifecycle, lifecycle);
});
