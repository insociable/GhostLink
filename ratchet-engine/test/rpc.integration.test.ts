import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const MAX_FRAME_BYTES = 2 * 1024 * 1024;
const DEVICE_A = 'device1:' + 'a'.repeat(52);
const DEVICE_B = 'device1:' + 'b'.repeat(52);
const SERVER_PATH = fileURLToPath(
  new URL('../src/rpc-server.js', import.meta.url)
);

interface RpcSuccess {
  readonly id: number;
  readonly ok: true;
  readonly result: unknown;
}

interface RpcFailure {
  readonly id: number;
  readonly ok: false;
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}

type RpcResponse = RpcSuccess | RpcFailure;

class FrameReader {
  private buffer = Buffer.alloc(0);
  private readonly waiters: Array<{
    resolve: (value: RpcResponse) => void;
    reject: (error: Error) => void;
  }> = [];
  private ended: Error | null = null;

  constructor(stream: NodeJS.ReadableStream) {
    stream.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
      this.drain();
    });
    stream.on('end', () => {
      this.ended = new Error('RPC stdout closed');
      this.rejectAll();
    });
    stream.on('error', (error: Error) => {
      this.ended = error;
      this.rejectAll();
    });
  }

  next(): Promise<RpcResponse> {
    if (this.ended !== null) {
      return Promise.reject(this.ended);
    }
    return new Promise<RpcResponse>((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.drain();
    });
  }

  private rejectAll(): void {
    if (this.ended === null) {
      return;
    }
    while (this.waiters.length > 0) {
      this.waiters.shift()!.reject(this.ended);
    }
  }

  private drain(): void {
    while (this.waiters.length > 0 && this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (length === 0 || length > MAX_FRAME_BYTES) {
        this.ended = new Error('invalid RPC response frame length');
        this.rejectAll();
        return;
      }
      if (this.buffer.length < 4 + length) {
        return;
      }

      const payload = this.buffer.subarray(4, 4 + length);
      this.buffer = this.buffer.subarray(4 + length);

      let parsed: unknown;
      try {
        parsed = JSON.parse(payload.toString('utf8')) as unknown;
      } catch (error) {
        this.ended = new Error('invalid RPC response JSON', { cause: error });
        this.rejectAll();
        return;
      }

      this.waiters.shift()!.resolve(parsed as RpcResponse);
    }
  }
}

class RpcProcess {
  readonly process: ChildProcessWithoutNullStreams;
  private readonly reader: FrameReader;
  private nextId = 1;

  constructor() {
    this.process = spawn(process.execPath, [SERVER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.reader = new FrameReader(this.process.stdout);
  }

  async request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId;
    this.nextId += 1;

    const payload = Buffer.from(
      JSON.stringify({ id, method, params }),
      'utf8'
    );
    assert.ok(payload.length > 0 && payload.length <= MAX_FRAME_BYTES);

    const header = Buffer.allocUnsafe(4);
    header.writeUInt32BE(payload.length, 0);
    this.process.stdin.write(Buffer.concat([header, payload]));

    const response = await this.reader.next();
    assert.equal(response.id, id);

    if (!response.ok) {
      throw new Error(
        `${response.error.code}: ${response.error.message}`
      );
    }
    return response.result;
  }

  async close(): Promise<void> {
    if (this.process.exitCode !== null) {
      return;
    }
    await this.request('close', {});
    this.process.stdin.end();
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error('RPC process did not exit')),
        5000
      );
      this.process.once('exit', (code) => {
        clearTimeout(timeout);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`RPC process exited with code ${code}`));
        }
      });
    });
  }
}

async function openEngine(
  deviceId: string,
  vaultPath: string,
  key: Buffer
): Promise<RpcProcess> {
  const client = new RpcProcess();

  const pong = await client.request('ping', {});
  assert.deepEqual(pong, { rpc_version: 1 });

  const opened = await client.request('open', {
    device_id: deviceId,
    vault_path: vaultPath,
    master_key: key.toString('base64'),
  });
  assert.deepEqual(opened, { rpc_version: 1 });

  return client;
}

test('RPC rejects methods before the vault is opened', async () => {
  const client = new RpcProcess();

  await assert.rejects(
    () =>
      client.request('encrypt', {
        remote_device_id: DEVICE_B,
        plaintext: Buffer.from('test').toString('base64'),
      }),
    /NOT_OPEN/
  );

  await client.close();
});

test('RPC rejects malformed DeviceIDs and unknown methods', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghostlink-rpc-'));
  const client = await openEngine(
    DEVICE_A,
    join(directory, 'alice.ratchet'),
    randomBytes(32)
  );

  await assert.rejects(
    () =>
      client.request('encrypt', {
        remote_device_id: 'not-a-device',
        plaintext: Buffer.from('test').toString('base64'),
      }),
    /INVALID_REQUEST/
  );

  await assert.rejects(
    () => client.request('execute_shell', {}),
    /METHOD_NOT_FOUND/
  );

  await client.close();
});

test('two local RPC engines establish PQXDH and exchange arbitrary bytes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghostlink-rpc-'));
  const aliceKey = randomBytes(32);
  const bobKey = randomBytes(32);
  const alicePath = join(directory, 'alice.ratchet');
  const bobPath = join(directory, 'bob.ratchet');

  let alice = await openEngine(DEVICE_A, alicePath, aliceKey);
  let bob = await openEngine(DEVICE_B, bobPath, bobKey);

  const bobMaterial = await bob.request('create_prekey_material', {});
  await alice.request('establish_session', {
    remote_device_id: DEVICE_B,
    publication_sequence: 1,
    material: bobMaterial,
  });

  const binaryPayload = Buffer.from([
    0x00, 0xff, 0x01, 0x80, 0x42, 0x00, 0x7f,
  ]);
  const encryptedForBob = (await alice.request('encrypt', {
    remote_device_id: DEVICE_B,
    plaintext: binaryPayload.toString('base64'),
  })) as {
    message_type: number;
    ciphertext: string;
  };

  assert.notEqual(
    Buffer.from(encryptedForBob.ciphertext, 'base64').toString('hex'),
    binaryPayload.toString('hex')
  );

  const decryptedByBob = (await bob.request('decrypt', {
    remote_device_id: DEVICE_A,
    message_type: encryptedForBob.message_type,
    ciphertext: encryptedForBob.ciphertext,
  })) as { plaintext: string };

  assert.deepEqual(
    Buffer.from(decryptedByBob.plaintext, 'base64'),
    binaryPayload
  );

  const replyPayload = Buffer.from('reply-after-pqxdh', 'utf8');
  const encryptedForAlice = (await bob.request('encrypt', {
    remote_device_id: DEVICE_A,
    plaintext: replyPayload.toString('base64'),
  })) as {
    message_type: number;
    ciphertext: string;
  };

  const decryptedByAlice = (await alice.request('decrypt', {
    remote_device_id: DEVICE_B,
    message_type: encryptedForAlice.message_type,
    ciphertext: encryptedForAlice.ciphertext,
  })) as { plaintext: string };

  assert.deepEqual(
    Buffer.from(decryptedByAlice.plaintext, 'base64'),
    replyPayload
  );

  await alice.close();
  await bob.close();

  alice = await openEngine(DEVICE_A, alicePath, aliceKey);
  bob = await openEngine(DEVICE_B, bobPath, bobKey);

  const afterRestart = Buffer.from('session-survives-rpc-restart', 'utf8');
  const ciphertext = (await alice.request('encrypt', {
    remote_device_id: DEVICE_B,
    plaintext: afterRestart.toString('base64'),
  })) as {
    message_type: number;
    ciphertext: string;
  };

  const plaintext = (await bob.request('decrypt', {
    remote_device_id: DEVICE_A,
    message_type: ciphertext.message_type,
    ciphertext: ciphertext.ciphertext,
  })) as { plaintext: string };

  assert.deepEqual(
    Buffer.from(plaintext.plaintext, 'base64'),
    afterRestart
  );

  await alice.close();
  await bob.close();
});

test('pre-key publication RPC recovers and stages exact pending payload', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghostlink-rpc-lifecycle-'));
  const key = randomBytes(32);
  const vaultPath = join(directory, 'bob.ratchet');

  let bob = await openEngine(DEVICE_B, vaultPath, key);

  const prepared = (await bob.request('prepare_prekey_generation', {
    one_time_count: 3,
    issued_at: 1_000,
    lifetime_seconds: 3_600,
  })) as {
    version: number;
    publication_sequence: number;
    issued_at: number;
    expires_at: number;
    one_time: unknown[];
    fallback: {
      pre_key_id: number | null;
      pre_key: string | null;
    };
    public_payload: string | null;
  };

  assert.equal(prepared.version, 1);
  assert.equal(prepared.publication_sequence, 1);
  assert.equal(prepared.issued_at, 1_000);
  assert.equal(prepared.expires_at, 4_600);
  assert.equal(prepared.one_time.length, 3);
  assert.equal(prepared.fallback.pre_key_id, null);
  assert.equal(prepared.fallback.pre_key, null);
  assert.equal(prepared.public_payload, null);

  await assert.rejects(
    () =>
      bob.request('prepare_prekey_generation', {
        one_time_count: 3,
        issued_at: 1_100,
        lifetime_seconds: 3_600,
      }),
    /pending pre-key generation already exists/
  );

  await bob.close();

  bob = await openEngine(DEVICE_B, vaultPath, key);
  const recovered = await bob.request('get_pending_prekey_generation', {});
  assert.deepEqual(recovered, prepared);

  const payload =
    '{"fallback":{"signed":"exact"},"one_time":[],"publication_sequence":1}';

  await assert.rejects(
    () =>
      bob.request('stage_prekey_publication', {
        publication_sequence: 2,
        public_payload: payload,
      }),
    /sequence does not match/
  );

  await bob.request('stage_prekey_publication', {
    publication_sequence: 1,
    public_payload: payload,
  });

  await bob.request('stage_prekey_publication', {
    publication_sequence: 1,
    public_payload: payload,
  });

  await assert.rejects(
    () =>
      bob.request('stage_prekey_publication', {
        publication_sequence: 1,
        public_payload: payload + 'changed',
      }),
    /different public payload/
  );

  await bob.close();

  bob = await openEngine(DEVICE_B, vaultPath, key);
  const staged = (await bob.request(
    'get_pending_prekey_generation',
    {}
  )) as {
    public_payload: string | null;
  };
  assert.equal(staged.public_payload, payload);

  await bob.close();
});


test('publication acknowledgement RPC is durable and idempotent', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghostlink-rpc-commit-'));
  const key = randomBytes(32);
  const vaultPath = join(directory, 'bob.ratchet');

  let bob = await openEngine(DEVICE_B, vaultPath, key);

  const prepared = (await bob.request('prepare_prekey_generation', {
    one_time_count: 2,
    issued_at: 1_000,
    lifetime_seconds: 3_600,
  })) as {
    publication_sequence: number;
  };

  await bob.request('stage_prekey_publication', {
    publication_sequence: prepared.publication_sequence,
    public_payload: '{"sequence":1}',
  });
  await bob.request('commit_prekey_publication', {
    publication_sequence: prepared.publication_sequence,
    published_at: 1_100,
  });

  assert.equal(
    await bob.request('get_pending_prekey_generation', {}),
    null
  );

  await bob.request('commit_prekey_publication', {
    publication_sequence: prepared.publication_sequence,
    published_at: 1_200,
  });

  await bob.close();
  bob = await openEngine(DEVICE_B, vaultPath, key);

  const second = (await bob.request('prepare_prekey_generation', {
    one_time_count: 2,
    issued_at: 1_300,
    lifetime_seconds: 3_600,
  })) as {
    publication_sequence: number;
  };
  assert.equal(second.publication_sequence, 2);

  await bob.close();
});


test('remote publication sequence persists and rejects rollback after restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghostlink-rpc-remote-seq-'));
  const aliceKey = randomBytes(32);
  const bobKey = randomBytes(32);
  const alicePath = join(directory, 'alice.ratchet');
  const bobPath = join(directory, 'bob.ratchet');

  let alice = await openEngine(DEVICE_A, alicePath, aliceKey);
  const bob = await openEngine(DEVICE_B, bobPath, bobKey);

  const firstMaterial = await bob.request('create_prekey_material', {});
  await alice.request('establish_session', {
    remote_device_id: DEVICE_B,
    publication_sequence: 2,
    material: firstMaterial,
  });

  await alice.close();
  alice = await openEngine(DEVICE_A, alicePath, aliceKey);

  const rollbackMaterial = await bob.request('create_prekey_material', {});
  await assert.rejects(
    () =>
      alice.request('establish_session', {
        remote_device_id: DEVICE_B,
        publication_sequence: 1,
        material: rollbackMaterial,
      }),
    /remote publication sequence regressed/
  );

  await alice.close();
  await bob.close();
});
