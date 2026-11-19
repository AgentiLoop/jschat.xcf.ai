// Port of WebAuthnManager.CBORDecoder (DogTagKit/WebAuthnManager.swift)
// Byte strings decode to Uint8Array, map keys are stringified ("1", "-2", ...) like Swift.
import { WebAuthnError } from './types.js';
import { base64ToBytes } from '../utils.js';

export function parseAttestationObject(base64String) {
  const data = base64ToBytes(base64String);
  if (!data) throw WebAuthnError.invalidCredential();
  return parseCBOR(data);
}

export function parseCBOR(data) {
  const state = { index: 0 };
  return parseCBORValue(data, state);
}

export function parseCBORValue(data, state) {
  if (state.index >= data.length) throw WebAuthnError.invalidCredential();

  const byte = data[state.index];
  state.index += 1;

  const majorType = (byte >> 5) & 0x07;
  const additionalInfo = byte & 0x1f;

  switch (majorType) {
    case 0: // Positive integer
      return parsePositiveInteger(additionalInfo, data, state);
    case 1: // Negative integer
      return -parsePositiveInteger(additionalInfo, data, state) - 1;
    case 2: { // Byte string
      const length = parseLength(additionalInfo, data, state);
      if (state.index + length > data.length) throw WebAuthnError.invalidCredential();
      const result = data.slice(state.index, state.index + length);
      state.index += length;
      return result;
    }
    case 3: { // Text string
      const length = parseLength(additionalInfo, data, state);
      if (state.index + length > data.length) throw WebAuthnError.invalidCredential();
      const result = new TextDecoder().decode(data.subarray(state.index, state.index + length));
      state.index += length;
      return result;
    }
    case 4: { // Array
      const count = parseLength(additionalInfo, data, state);
      const array = [];
      for (let i = 0; i < count; i++) array.push(parseCBORValue(data, state));
      return array;
    }
    case 5: { // Map
      const count = parseLength(additionalInfo, data, state);
      const map = {};
      for (let i = 0; i < count; i++) {
        const key = parseCBORValue(data, state);
        const value = parseCBORValue(data, state);
        // Handle both string keys and integer keys (convert to string)
        if (typeof key === 'string' || typeof key === 'number') {
          map[String(key)] = value;
        }
        // Skip unknown key types
      }
      return map;
    }
    case 7: // Float, simple, break
      if (additionalInfo === 22) return null;
      if (additionalInfo === 20) return false;
      if (additionalInfo === 21) return true;
      throw WebAuthnError.invalidCredential();
    default:
      throw WebAuthnError.invalidCredential();
  }
}

function parseLength(additionalInfo, data, state) {
  const i = state.index;
  if (additionalInfo < 24) return additionalInfo;
  if (additionalInfo === 24) {
    if (i >= data.length) throw WebAuthnError.invalidCredential();
    state.index += 1;
    return data[i];
  }
  if (additionalInfo === 25) {
    if (i + 1 >= data.length) throw WebAuthnError.invalidCredential();
    state.index += 2;
    return (data[i] << 8) | data[i + 1];
  }
  if (additionalInfo === 26) {
    if (i + 3 >= data.length) throw WebAuthnError.invalidCredential();
    state.index += 4;
    return ((data[i] << 24) >>> 0) + ((data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]);
  }
  throw WebAuthnError.invalidCredential();
}

function parsePositiveInteger(additionalInfo, data, state) {
  const i = state.index;
  if (additionalInfo < 27) return parseLength(additionalInfo, data, state);
  if (additionalInfo === 27) {
    if (i + 7 >= data.length) throw WebAuthnError.invalidCredential();
    let result = 0n;
    for (let k = 0; k < 8; k++) result = (result << 8n) | BigInt(data[i + k]);
    state.index += 8;
    return Number(result);
  }
  throw WebAuthnError.invalidCredential();
}
