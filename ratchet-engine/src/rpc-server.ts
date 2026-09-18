import { once } from 'node:events';

import * as SignalClient from '@signalapp/libsignal-client';

import { exportPreKeyMaterial, importPreKeyMaterial } from './prekey-material.js';
import { PersistentRatchetParty } from './persistent-party.js';

const RPC_VERSION = 1;
const MAX_FRAME_BYTES = 2 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 1024 * 1024;
const DEVICE_ID_PATTERN = /^device1:[a-z2-7]{52}$/;

interface RpcRequest {
  readonly id: number;
  readonly method: string;
  readonly params: unknown;
}

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

class RpcError extends Error {
  constructor(
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = 'RpcError';
  }
}

function requireObject(
  value: unknown,
  context: string
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RpcError('INVALID_REQUEST', `${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactFields(
  document: Record<string, unknown>,
  fields: readonly string[],
  context: string
): void {
  const actual = Object.keys(document).sort().join(',');
  const expected = [...fields].sort().join(',');
  if (actual !== expected) {
    throw new RpcError(
      'INVALID_REQUEST',
      `${context} fields do not match the protocol`
    );
  }
}

function requireText(
  document: Record<string, unknown>,
  field: string,
  maxLength = 4096
): string {
  const value = document[field];
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxLength ||
    value.includes('\0')
  ) {
    throw new RpcError(
      'INVALID_REQUEST',
      `${field} must be bounded non-empty text`
    );
  }
  return value;
}

function requireDeviceId(
  document: Record<string, unknown>,
  field: string
): string {
  const value = requireText(document, field, 60);
  if (!DEVICE_ID_PATTERN.test(value)) {
    throw new RpcError(
      'INVALID_REQUEST',
      `${field} must be a canonical GhostLink DeviceID`
    );
  }
  return value;
}

function decodeBase64(
  document: Record<string, unknown>,
  field: string,
  options: {
    readonly exactBytes?: number;
    readonly maxBytes?: number;
    readonly allowEmpty?: boolean;
  } = {}
): Uint8Array<ArrayBuffer> {
  const value = document[field];
  if (typeof value !== 'string') {
    throw new RpcError('INVALID_REQUEST', `${field} must be Base64 text`);
  }
  if (!options.allowEmpty && value.length === 0) {
    throw new RpcError('INVALID_REQUEST', `${field} must not be empty`);
  }

  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new RpcError(
      'INVALID_REQUEST',
      `${field} must use canonical Base64`
    );
  }
  if (
    options.exactBytes !== undefined &&
    decoded.length !== options.exactBytes
  ) {
    throw new RpcError(
      'INVALID_REQUEST',
      `${field} has an invalid decoded length`
    );
  }
  if (
    options.maxBytes !== undefined &&
    decoded.length > options.maxBytes
  ) {
    throw new RpcError(
      'INVALID_REQUEST',
      `${field} exceeds the size limit`
    );
  }

  return Uint8Array.from(decoded);
}

function requireMessageType(value: unknown): SignalClient.CiphertextMessageType {
  if (
    value !== SignalClient.CiphertextMessageType.PreKey &&
    value !== SignalClient.CiphertextMessageType.Whisper
  ) {
    throw new RpcError(
      'INVALID_REQUEST',
      'message_type is not a supported libsignal message type'
    );
  }
  return value;
}

function parseRequest(value: unknown): RpcRequest {
  const document = requireObject(value, 'request');
  requireExactFields(document, ['id', 'method', 'params'], 'request');

  const id = document.id;
  if (!Number.isSafeInteger(id) || (id as number) < 0) {
    throw new RpcError(
      'INVALID_REQUEST',
      'request id must be a non-negative safe integer'
    );
  }

  const method = document.method;
  if (typeof method !== 'string' || method.length === 0 || method.length > 64) {
    throw new RpcError('INVALID_REQUEST', 'request method is invalid');
  }

  return {
    id: id as number,
    method,
    params: document.params,
  };
}

function encodeResponse(response: RpcSuccess | RpcFailure): Buffer {
  const payload = Buffer.from(JSON.stringify(response), 'utf8');
  if (payload.length > MAX_FRAME_BYTES) {
    throw new Error('RPC response exceeds the frame limit');
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

async function writeResponse(response: RpcSuccess | RpcFailure): Promise<void> {
  const frame = encodeResponse(response);
  if (!process.stdout.write(frame)) {
    await once(process.stdout, 'drain');
  }
}

class RatchetRpcService {
  private party: PersistentRatchetParty | null = null;
  private closing = false;

  get shouldClose(): boolean {
    return this.closing;
  }

  private requireParty(): PersistentRatchetParty {
    if (this.party === null) {
      throw new RpcError('NOT_OPEN', 'ratchet engine is not open');
    }
    return this.party;
  }

  async dispatch(request: RpcRequest): Promise<unknown> {
    switch (request.method) {
      case 'ping':
        return this.ping(request.params);
      case 'open':
        return this.open(request.params);
      case 'create_prekey_material':
        return this.createPreKeyMaterial(request.params);
      case 'establish_session':
        return this.establishSession(request.params);
      case 'encrypt':
        return this.encrypt(request.params);
      case 'decrypt':
        return this.decrypt(request.params);
      case 'close':
        return this.close(request.params);
      default:
        throw new RpcError(
          'METHOD_NOT_FOUND',
          `unsupported RPC method: ${request.method}`
        );
    }
  }

  private ping(params: unknown): Record<string, number> {
    const document = requireObject(params, 'ping params');
    requireExactFields(document, [], 'ping params');
    return { rpc_version: RPC_VERSION };
  }

  private async open(params: unknown): Promise<Record<string, number>> {
    if (this.party !== null) {
      throw new RpcError('ALREADY_OPEN', 'ratchet engine is already open');
    }

    const document = requireObject(params, 'open params');
    requireExactFields(
      document,
      ['device_id', 'vault_path', 'master_key'],
      'open params'
    );

    const deviceId = requireDeviceId(document, 'device_id');
    const vaultPath = requireText(document, 'vault_path');
    const masterKey = decodeBase64(document, 'master_key', { exactBytes: 32 });

    try {
      this.party = await PersistentRatchetParty.open(
        deviceId,
        1,
        vaultPath,
        masterKey
      );
    } finally {
      masterKey.fill(0);
    }

    return { rpc_version: RPC_VERSION };
  }

  private async createPreKeyMaterial(params: unknown): Promise<unknown> {
    const document = requireObject(params, 'create_prekey_material params');
    requireExactFields(document, [], 'create_prekey_material params');

    const bundle = await this.requireParty().createPreKeyBundle();
    return exportPreKeyMaterial(bundle);
  }

  private async establishSession(params: unknown): Promise<null> {
    const document = requireObject(params, 'establish_session params');
    requireExactFields(
      document,
      ['remote_device_id', 'material'],
      'establish_session params'
    );

    const remoteDeviceId = requireDeviceId(document, 'remote_device_id');
    const bundle = importPreKeyMaterial(document.material);

    await this.requireParty().establishSessionWithAddress(
      remoteDeviceId,
      bundle
    );
    return null;
  }

  private async encrypt(params: unknown): Promise<Record<string, unknown>> {
    const document = requireObject(params, 'encrypt params');
    requireExactFields(
      document,
      ['remote_device_id', 'plaintext'],
      'encrypt params'
    );

    const remoteDeviceId = requireDeviceId(document, 'remote_device_id');
    const plaintext = decodeBase64(document, 'plaintext', {
      maxBytes: MAX_PAYLOAD_BYTES,
    });

    const message = await this.requireParty().encryptBytesTo(
      remoteDeviceId,
      plaintext
    );

    return {
      message_type: message.type,
      ciphertext: Buffer.from(message.body).toString('base64'),
    };
  }

  private async decrypt(params: unknown): Promise<Record<string, string>> {
    const document = requireObject(params, 'decrypt params');
    requireExactFields(
      document,
      ['remote_device_id', 'message_type', 'ciphertext'],
      'decrypt params'
    );

    const remoteDeviceId = requireDeviceId(document, 'remote_device_id');
    const messageType = requireMessageType(document.message_type);
    const ciphertext = decodeBase64(document, 'ciphertext', {
      maxBytes: MAX_FRAME_BYTES,
    });

    const plaintext = await this.requireParty().decryptBytesFrom(
      remoteDeviceId,
      {
        type: messageType,
        body: ciphertext,
      }
    );

    if (plaintext.byteLength > MAX_PAYLOAD_BYTES) {
      throw new RpcError(
        'ENGINE_ERROR',
        'decrypted plaintext exceeds the size limit'
      );
    }

    return {
      plaintext: Buffer.from(plaintext).toString('base64'),
    };
  }

  private close(params: unknown): null {
    const document = requireObject(params, 'close params');
    requireExactFields(document, [], 'close params');

    if (this.party !== null) {
      this.party.close();
      this.party = null;
    }
    this.closing = true;
    return null;
  }

  shutdown(): void {
    if (this.party !== null) {
      this.party.close();
      this.party = null;
    }
  }
}

function responseForError(id: number, error: unknown): RpcFailure {
  if (error instanceof RpcError) {
    return {
      id,
      ok: false,
      error: {
        code: error.code,
        message: error.message,
      },
    };
  }

  const message =
    error instanceof Error ? error.message : 'unknown ratchet engine error';

  return {
    id,
    ok: false,
    error: {
      code: 'ENGINE_ERROR',
      message,
    },
  };
}

async function main(): Promise<void> {
  const service = new RatchetRpcService();
  let buffer = Buffer.alloc(0);

  try {
    for await (const chunk of process.stdin) {
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);

      while (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (length === 0 || length > MAX_FRAME_BYTES) {
          throw new Error('invalid RPC frame length');
        }
        if (buffer.length < 4 + length) {
          break;
        }

        const payload = buffer.subarray(4, 4 + length);
        buffer = buffer.subarray(4 + length);

        let requestId = 0;
        try {
          const parsed = JSON.parse(payload.toString('utf8')) as unknown;
          const request = parseRequest(parsed);
          requestId = request.id;
          const result = await service.dispatch(request);
          await writeResponse({
            id: request.id,
            ok: true,
            result,
          });
        } catch (error) {
          await writeResponse(responseForError(requestId, error));
        }

        if (service.shouldClose) {
          return;
        }
      }
    }

    if (buffer.length !== 0) {
      throw new Error('truncated RPC frame at end of input');
    }
  } finally {
    service.shutdown();
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'unknown fatal error';
  process.stderr.write(`GhostLink ratchet RPC fatal error: ${message}\n`);
  process.exitCode = 1;
});