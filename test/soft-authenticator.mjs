// Software passkey authenticator used by the tests: produces the same JSON the browser
// client (public/webauthn.js) posts to /webauthn/register/complete and /authenticate/complete.
import { webcrypto as crypto } from 'node:crypto';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const cat = (...p) => new Uint8Array(Buffer.concat(p.map((x) => Buffer.from(x))));
const sha256 = async (d) => new Uint8Array(await crypto.subtle.digest('SHA-256', d));

// Minimal CBOR encoder (maps, ints, byte/text strings)
function head(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 256) return [major << 5 | 24, n];
  if (n < 65536) return [major << 5 | 25, n >> 8, n & 255];
  return [major << 5 | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function cbor(v) {
  if (typeof v === 'number') return new Uint8Array(v >= 0 ? head(0, v) : head(1, -v - 1));
  if (typeof v === 'string') { const b = new TextEncoder().encode(v); return cat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (v instanceof Map) {
    const parts = [new Uint8Array(head(5, v.size))];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return cat(...parts);
  }
  throw new Error('unsupported');
}

export class SoftAuthenticator {
  constructor(rpId, origin) {
    this.rpId = rpId;
    this.origin = origin;
    this.signCount = 0;
  }

  async create(options) {
    this.keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', this.keys.publicKey));
    this.credId = crypto.getRandomValues(new Uint8Array(32));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33)]]));
    const authData = cat(
      await sha256(new TextEncoder().encode(this.rpId)), [0x45], [0, 0, 0, 0],
      new Uint8Array(16), [0, this.credId.length], this.credId, cose,
    );
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: 'webauthn.create', challenge: b64url(Buffer.from(options.publicKey.challenge, 'base64')), origin: this.origin,
    }));
    const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return {
      id: b64url(this.credId),
      rawId: b64(this.credId),
      type: 'public-key',
      response: { attestationObject: b64(attestationObject), clientDataJSON: b64(clientDataJSON) },
    };
  }

  async get(options, { signCount } = {}) {
    this.signCount = signCount ?? this.signCount;
    const authData = cat(
      await sha256(new TextEncoder().encode(this.rpId)), [0x05],
      [(this.signCount >>> 24) & 255, (this.signCount >> 16) & 255, (this.signCount >> 8) & 255, this.signCount & 255],
    );
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
      type: 'webauthn.get', challenge: b64url(Buffer.from(options.publicKey.challenge, 'base64')), origin: this.origin,
    }));
    const signed = cat(authData, await sha256(clientDataJSON));
    // WebCrypto returns raw r||s; browsers return DER — convert to DER to exercise that path
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, signed));
    return {
      id: b64url(this.credId),
      rawId: b64(this.credId),
      type: 'public-key',
      response: {
        clientDataJSON: b64(clientDataJSON),
        authenticatorData: b64(authData),
        signature: b64(rawToDer(raw)),
        userHandle: null,
      },
    };
  }
}

function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = cat([0], v);
    return cat([0x02, v.length], v);
  };
  const body = cat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return cat([0x30, body.length], body);
}
