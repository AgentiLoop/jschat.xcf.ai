// Cloudflare Worker entry — the equivalent of ChatServer/main.swift + WebServer's static routes.
// Static front-end files (the Swift server's static/ folder) are served from Workers Static Assets;
// everything stateful is forwarded to the single global ChatServer Durable Object.
export { ChatServer } from './chat-server.js';

// Top-level routes the Swift server answered from static/ (StaticContentProvider.swift)
const STATIC_ROUTES = {
  '/': '/index.html',
  '/chat.js': '/chat.js',
  '/webauthn.js': '/webauthn.js',
  '/webauthnui.js': '/webauthnui.js',
  '/emoji.js': '/emoji.js',
  '/style.css': '/style.css',
  '/webauthn.css': '/webauthn.css',
  '/hybrid-webauthn-test.html': '/hybrid-webauthn-test.html',
  '/webauthn-super-test.html': '/webauthn-super-test.html',
  '/webauthn-super-test.js': '/webauthn-super-test.js',
};

const withCORS = (response, extra = {}) => {
  const r = new Response(response.body, response);
  r.headers.set('Access-Control-Allow-Origin', '*');
  for (const [k, v] of Object.entries(extra)) r.headers.set(k, v);
  return r;
};

async function serveAsset(env, request, assetPath, notFoundMessage) {
  const res = await env.ASSETS.fetch(new Request(new URL(assetPath, request.url), { method: 'GET' }));
  if (res.status === 404) {
    return new Response(JSON.stringify({ success: false, error: notFoundMessage }), {
      status: 404, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
  return withCORS(res);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isWebSocket = (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket';

    // CORS preflight (WebServer.handleCORSPreflight)
    if (request.method === 'OPTIONS' && !isWebSocket) {
      return new Response(null, {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Content-Length',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    if (request.method === 'GET' && !isWebSocket) {
      const asset = STATIC_ROUTES[url.pathname];
      if (asset) return serveAsset(env, request, asset, '404 Not Found');
      if (url.pathname.startsWith('/static/')) {
        const fileName = url.pathname.slice('/static/'.length);
        return serveAsset(env, request, `/${fileName}`, `Static file not found: ${fileName}`);
      }
    }

    const id = env.CHAT_SERVER.idFromName('global');
    return env.CHAT_SERVER.get(id).fetch(request);
  },
};
