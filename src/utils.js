// Shared helpers — JS equivalents of the Foundation APIs the Swift code relied on.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (s) => encoder.encode(s);
export const fromUtf8 = (b) => decoder.decode(b);

/** Data(base64Encoded:) — returns null on invalid input, like Swift. */
export function base64ToBytes(b64) {
  if (typeof b64 !== 'string') return null;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Data.base64EncodedString() */
export function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function base64ToBase64url(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** UUID().uuidString (uppercase, like Foundation) */
export const uuid = () => crypto.randomUUID().toUpperCase();

/** ISO8601DateFormatter().string(from:) — no fractional seconds */
export const iso8601 = (date = new Date()) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** NSString.pathExtension */
export function pathExtension(name) {
  const base = name.split('/').pop();
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1) : '';
}

/** Client IP: X-Forwarded-For → X-Real-IP → connection (CF-Connecting-IP on Cloudflare) */
export function extractClientIP(request) {
  const h = request.headers;
  const xff = h.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  const real = h.get('x-real-ip');
  if (real) return real.trim();
  return h.get('cf-connecting-ip');
}

const CORS = { 'Access-Control-Allow-Origin': '*' };

export function textResponse(body, contentType, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      ...extraHeaders,
    },
  });
}

/** sendJSONResponse */
export function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(typeof obj === 'string' ? obj : JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extraHeaders },
  });
}

/** sendErrorResponse */
export function errorResponse(error, status = 400) {
  return jsonResponse({ success: false, error }, status);
}

/** sendFileResponse / icon responses */
export function binaryResponse(data, mimeType, extraHeaders = {}) {
  return new Response(data, {
    status: 200,
    headers: { 'Content-Type': mimeType, ...CORS, ...extraHeaders },
  });
}
