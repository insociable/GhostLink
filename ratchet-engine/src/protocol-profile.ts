export const SIGNAL_DEVICE_ID = 1;
export const MIN_REGISTRATION_ID = 1;
export const MAX_REGISTRATION_ID = 16_380;
export const MAX_PREKEY_ID = 0x7fff_ffff;

export function validateRegistrationId(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_REGISTRATION_ID ||
    value > MAX_REGISTRATION_ID
  ) {
    throw new Error(
      `registrationId must be between ${MIN_REGISTRATION_ID} and ${MAX_REGISTRATION_ID}`
    );
  }
  return value;
}

export function validateSignalDeviceId(value: number): number {
  if (value !== SIGNAL_DEVICE_ID) {
    throw new Error(`signal device ID must equal ${SIGNAL_DEVICE_ID}`);
  }
  return value;
}