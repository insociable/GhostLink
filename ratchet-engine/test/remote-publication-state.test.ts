import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MemoryRemotePublicationSequenceStore,
  parseRemotePublicationSequences,
} from '../src/remote-publication-state.js';

const DEVICE_A = 'device1:' + 'a'.repeat(52);
const DEVICE_B = 'device1:' + 'b'.repeat(52);

test('remote publication sequence accepts first, same and newer values', () => {
  const store = new MemoryRemotePublicationSequenceStore();

  assert.equal(store.observe(DEVICE_A, 3), 3);
  assert.equal(store.observe(DEVICE_A, 3), 3);
  assert.equal(store.observe(DEVICE_A, 4), 4);
  assert.equal(store.highest(DEVICE_A), 4);
  assert.equal(store.highest(DEVICE_B), null);
});

test('remote publication sequence rejects rollback without mutation', () => {
  const store = new MemoryRemotePublicationSequenceStore([[DEVICE_A, 4]]);
  const before = store.exportState();

  assert.throws(
    () => store.observe(DEVICE_A, 3),
    /remote publication sequence regressed/
  );
  assert.deepEqual(store.exportState(), before);
});

test('remote publication sequence state rejects invalid or duplicate entries', () => {
  assert.throws(
    () => parseRemotePublicationSequences([['not-a-device', 1]]),
    /canonical GhostLink DeviceID/
  );
  assert.throws(
    () =>
      parseRemotePublicationSequences([
        [DEVICE_A, 1],
        [DEVICE_A, 2],
      ]),
    /duplicate DeviceID/
  );
  assert.throws(
    () => parseRemotePublicationSequences([[DEVICE_A, 0]]),
    /outside the supported range/
  );
});
