import * as SignalClient from '@signalapp/libsignal-client';

import {
  MAX_REGISTRATION_ID,
  validateSignalDeviceId,
} from './protocol-profile.js';

const FORMAT_VERSION = 1;
const MAX_IDENTIFIER = 0x7fff_ffff;
const MAX_KYBER_PUBLIC_KEY_BYTES = 4_096;
const EC_PUBLIC_KEY_BYTES = 33;
const SIGNATURE_BYTES = 64;

const EXPECTED_FIELDS = new Set([
  'version',
  'registration_id',
  'signal_device_id',
  'identity_key',
  'pre_key_id',
  'pre_key',
  'signed_pre_key_id',
  'signed_pre_key',
  'signed_pre_key_signature',
  'kyber_pre_key_id',
  'kyber_pre_key',
  'kyber_pre_key_signature',
]);

export interface WirePreKeyMaterial {
  readonly version: 1;
  readonly registration_id: number;
  readonly signal_device_id: number;
  readonly identity_key: string;
  readonly pre_key_id: number | null;
  readonly pre_key: string | null;
  readonly signed_pre_key_id: number;
  readonly signed_pre_key: string;
  readonly signed_pre_key_signature: string;
  readonly kyber_pre_key_id: number;
  readonly kyber_pre_key: string;
  readonly kyber_pre_key_signature: string;
}

function encodeBytes(value: Uint8Array): string {
  return Buffer.from(value).toString('base64');
}

function requireObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('pre-key material must be an object');
  }
  const document = value as Record<string, unknown>;
  if (
    Object.keys(document).length !== EXPECTED_FIELDS.size ||
    Object.keys(document).some((field) => !EXPECTED_FIELDS.has(field))
  ) {
    throw new Error('pre-key material fields do not match version 1');
  }
  return document;
}

function requireInteger(
  value: unknown,
  field: string,
  maximum = MAX_IDENTIFIER
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) <= 0 ||
    (value as number) > maximum
  ) {
    throw new Error(`${field} is outside the supported range`);
  }
  return value as number;
}

function decodeBase64(
  value: unknown,
  field: string,
  options: {
    readonly exactBytes?: number;
    readonly maxBytes?: number;
  } = {}
): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${field} must be non-empty Base64 text`);
  }

  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new Error(`${field} must use canonical Base64`);
  }
  if (
    options.exactBytes !== undefined &&
    decoded.length !== options.exactBytes
  ) {
    throw new Error(
      `${field} must decode to exactly ${options.exactBytes} bytes`
    );
  }
  if (
    options.maxBytes !== undefined &&
    decoded.length > options.maxBytes
  ) {
    throw new Error(`${field} exceeds the size limit`);
  }

  return Uint8Array.from(decoded);
}

export function exportPreKeyMaterial(
  bundle: SignalClient.PreKeyBundle
): WirePreKeyMaterial {
  const preKey = bundle.preKeyPublic();

  return {
    version: 1,
    registration_id: bundle.registrationId(),
    signal_device_id: bundle.deviceId(),
    identity_key: encodeBytes(bundle.identityKey().serialize()),
    pre_key_id: bundle.preKeyId(),
    pre_key: preKey === null ? null : encodeBytes(preKey.serialize()),
    signed_pre_key_id: bundle.signedPreKeyId(),
    signed_pre_key: encodeBytes(bundle.signedPreKeyPublic().serialize()),
    signed_pre_key_signature: encodeBytes(bundle.signedPreKeySignature()),
    kyber_pre_key_id: bundle.kyberPreKeyId(),
    kyber_pre_key: encodeBytes(bundle.kyberPreKeyPublic().serialize()),
    kyber_pre_key_signature: encodeBytes(bundle.kyberPreKeySignature()),
  };
}

export function importPreKeyMaterial(
  value: unknown
): SignalClient.PreKeyBundle {
  const document = requireObject(value);

  if (document.version !== FORMAT_VERSION) {
    throw new Error('unsupported pre-key material version');
  }

  const registrationId = requireInteger(
    document.registration_id,
    'registration_id',
    MAX_REGISTRATION_ID
  );
  const signalDeviceId = validateSignalDeviceId(
    requireInteger(document.signal_device_id, 'signal_device_id')
  );

  const rawPreKeyId = document.pre_key_id;
  const rawPreKey = document.pre_key;
  let preKeyId: number | null;
  let preKey: SignalClient.PublicKey | null;

  if (rawPreKeyId === null && rawPreKey === null) {
    preKeyId = null;
    preKey = null;
  } else if (rawPreKeyId === null || rawPreKey === null) {
    throw new Error(
      'pre_key_id and pre_key must either both be present or both be null'
    );
  } else {
    preKeyId = requireInteger(rawPreKeyId, 'pre_key_id');
    preKey = SignalClient.PublicKey.deserialize(
      decodeBase64(rawPreKey, 'pre_key', { exactBytes: EC_PUBLIC_KEY_BYTES })
    );
  }

  const identityKey = SignalClient.PublicKey.deserialize(
    decodeBase64(document.identity_key, 'identity_key', {
      exactBytes: EC_PUBLIC_KEY_BYTES,
    })
  );
  const signedPreKey = SignalClient.PublicKey.deserialize(
    decodeBase64(document.signed_pre_key, 'signed_pre_key', {
      exactBytes: EC_PUBLIC_KEY_BYTES,
    })
  );
  const signedPreKeySignature = decodeBase64(
    document.signed_pre_key_signature,
    'signed_pre_key_signature',
    { exactBytes: SIGNATURE_BYTES }
  );
  const kyberPreKey = SignalClient.KEMPublicKey.deserialize(
    decodeBase64(document.kyber_pre_key, 'kyber_pre_key', {
      maxBytes: MAX_KYBER_PUBLIC_KEY_BYTES,
    })
  );
  const kyberPreKeySignature = decodeBase64(
    document.kyber_pre_key_signature,
    'kyber_pre_key_signature',
    { exactBytes: SIGNATURE_BYTES }
  );

  return SignalClient.PreKeyBundle.new(
    registrationId,
    signalDeviceId,
    preKeyId,
    preKey,
    requireInteger(document.signed_pre_key_id, 'signed_pre_key_id'),
    signedPreKey,
    signedPreKeySignature,
    identityKey,
    requireInteger(document.kyber_pre_key_id, 'kyber_pre_key_id'),
    kyberPreKey,
    kyberPreKeySignature
  );
}