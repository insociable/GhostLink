import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  mkdtemp,
  readFile,
  readdir,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { PersistentRatchetParty } from '../src/persistent-party.js';
import {
  RatchetStateVault,
  RatchetVaultError,
  RatchetVaultUnlockError,
} from '../src/vault.js';

async function temporaryDirectory(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'ghostlink-ratchet-'));
}

async function establishPersistentPair(directory: string): Promise<{
  alice: PersistentRatchetParty;
  bob: PersistentRatchetParty;
  aliceKey: Buffer;
  bobKey: Buffer;
  alicePath: string;
  bobPath: string;
}> {
  const aliceKey = randomBytes(32);
  const bobKey = randomBytes(32);
  const alicePath = join(directory, 'alice.ratchet');
  const bobPath = join(directory, 'bob.ratchet');

  const alice = await PersistentRatchetParty.open(
    'alice',
    1,
    alicePath,
    aliceKey
  );
  const bob = await PersistentRatchetParty.open('bob', 1, bobPath, bobKey);

  const bundle = await bob.createPreKeyBundle();
  await alice.establishSession(bob, bundle);

  const first = await alice.encrypt(bob, 'first');
  assert.equal(await bob.decrypt(alice, first), 'first');

  const reply = await bob.encrypt(alice, 'reply');
  assert.equal(await alice.decrypt(bob, reply), 'reply');

  return {
    alice,
    bob,
    aliceKey,
    bobKey,
    alicePath,
    bobPath,
  };
}

test('vault encrypts private state and uses private POSIX permissions', async () => {
  const directory = await temporaryDirectory();
  const key = randomBytes(32);
  const path = join(directory, 'alice.ratchet');
  const alice = await PersistentRatchetParty.open('alice', 1, path, key);

  const state = await alice.exportStateForTesting();
  const raw = await readFile(path, 'utf8');

  assert.equal(raw.includes('privateKey'), false);
  assert.equal(raw.includes(state.identity.privateKey), false);
  assert.equal(raw.includes('"session"'), false);

  if (process.platform !== 'win32') {
    const mode = (await stat(path)).mode & 0o777;
    assert.equal(mode, 0o600);
  }

  const leftovers = (await readdir(directory)).filter((name) =>
    name.includes('.tmp-')
  );
  assert.deepEqual(leftovers, []);
});

test('wrong master key and ciphertext tampering fail closed', async () => {
  const directory = await temporaryDirectory();
  const key = randomBytes(32);
  const path = join(directory, 'alice.ratchet');

  const alice = await PersistentRatchetParty.open('alice', 1, path, key);
  alice.close();

  const wrongVault = new RatchetStateVault(path, randomBytes(32));
  await assert.rejects(
    () => wrongVault.load({ name: 'alice', deviceId: 1 }),
    RatchetVaultUnlockError
  );

  const document = JSON.parse(await readFile(path, 'utf8')) as {
    ciphertext: string;
  };
  const ciphertext = Buffer.from(document.ciphertext, 'base64');
  ciphertext[0] = ciphertext[0]! ^ 0x01;
  document.ciphertext = ciphertext.toString('base64');
  await writeFile(path, JSON.stringify(document));

  const correctVault = new RatchetStateVault(path, key);
  await assert.rejects(
    () => correctVault.load({ name: 'alice', deviceId: 1 }),
    RatchetVaultUnlockError
  );
});

test('vault state is bound to its requested owner', async () => {
  const directory = await temporaryDirectory();
  const key = randomBytes(32);
  const path = join(directory, 'alice.ratchet');

  const alice = await PersistentRatchetParty.open('alice', 1, path, key);
  alice.close();

  const vault = new RatchetStateVault(path, key);
  await assert.rejects(
    () => vault.load({ name: 'bob', deviceId: 1 }),
    (error: unknown) => {
      assert.ok(error instanceof RatchetVaultError);
      assert.match(error.message, /owner does not match/);
      return true;
    }
  );
});

test('ratcheted session survives full process-style reopen', async () => {
  const directory = await temporaryDirectory();
  const pair = await establishPersistentPair(directory);

  pair.alice.close();
  pair.bob.close();

  const alice = await PersistentRatchetParty.open(
    'alice',
    1,
    pair.alicePath,
    pair.aliceKey
  );
  const bob = await PersistentRatchetParty.open(
    'bob',
    1,
    pair.bobPath,
    pair.bobKey
  );

  const second = await alice.encrypt(bob, 'after-restart-a');
  assert.equal(await bob.decrypt(alice, second), 'after-restart-a');

  const reply = await bob.encrypt(alice, 'after-restart-b');
  assert.equal(await alice.decrypt(bob, reply), 'after-restart-b');
});

test('one-time EC and Kyber pre-key consumption survives restart', async () => {
  const directory = await temporaryDirectory();
  const pair = await establishPersistentPair(directory);

  const beforeClose = await pair.bob.exportStateForTesting();
  assert.equal(
    beforeClose.preKey.some(([id]) => id === 1001),
    false
  );
  assert.equal(beforeClose.kyberPreKey.used.includes(3001), true);
  assert.ok(beforeClose.identity.trusted.length > 0);

  pair.bob.close();

  const bob = await PersistentRatchetParty.open(
    'bob',
    1,
    pair.bobPath,
    pair.bobKey
  );
  const afterReopen = await bob.exportStateForTesting();

  assert.equal(
    afterReopen.preKey.some(([id]) => id === 1001),
    false
  );
  assert.equal(afterReopen.kyberPreKey.used.includes(3001), true);
  assert.deepEqual(
    afterReopen.identity.trusted,
    beforeClose.identity.trusted
  );
});

test('failed decrypt rolls memory back and leaves vault byte-for-byte unchanged', async () => {
  const directory = await temporaryDirectory();
  const pair = await establishPersistentPair(directory);

  const message = await pair.alice.encrypt(pair.bob, 'must-authenticate');
  const tamperedBody = Uint8Array.from(message.body);
  tamperedBody[tamperedBody.length - 1] =
    tamperedBody[tamperedBody.length - 1]! ^ 0x01;

  const before = await readFile(pair.bobPath);

  await assert.rejects(() =>
    pair.bob.decrypt(pair.alice, {
      type: message.type,
      body: tamperedBody,
    })
  );

  const after = await readFile(pair.bobPath);
  assert.deepEqual(after, before);

  assert.equal(await pair.bob.decrypt(pair.alice, message), 'must-authenticate');
});

test('concurrent sends are serialized through one ratchet state', async () => {
  const directory = await temporaryDirectory();
  const pair = await establishPersistentPair(directory);

  const [one, two, three] = await Promise.all([
    pair.alice.encrypt(pair.bob, 'one'),
    pair.alice.encrypt(pair.bob, 'two'),
    pair.alice.encrypt(pair.bob, 'three'),
  ]);

  assert.equal(await pair.bob.decrypt(pair.alice, three), 'three');
  assert.equal(await pair.bob.decrypt(pair.alice, one), 'one');
  assert.equal(await pair.bob.decrypt(pair.alice, two), 'two');
});