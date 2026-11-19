// Port of the asset generators in MultiPeerChatCore/WebServer.swift
// (favicons, app icons, manifest.json, browserconfig.xml, chat-preview).
// Swift's Int division truncates, so `d(a, b)` mirrors `a / b`.
const d = (a, b) => Math.trunc(a / b);

export function generateSimpleFaviconSVG() {
  return `<svg width="32" height="32" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
  <rect width="32" height="32" rx="6" fill="#007AFF"/>
  <circle cx="11" cy="14" r="6" fill="white" opacity="0.9"/>
  <circle cx="21" cy="18" r="4" fill="white" opacity="0.7"/>
  <circle cx="9" cy="14" r="1.5" fill="#007AFF"/>
  <circle cx="11" cy="14" r="1.5" fill="#007AFF"/>
  <circle cx="13" cy="14" r="1.5" fill="#007AFF"/>
</svg>`;
}

export function generateSimplePNGFavicon() {
  return `<svg width="32" height="32" xmlns="http://www.w3.org/2000/svg">
  <rect width="32" height="32" fill="#007AFF"/>
  <text x="16" y="20" text-anchor="middle" fill="white" font-size="16">💬</text>
</svg>`;
}

/** /favicon-NxN.png and /icons/favicon-NxN.png */
export function faviconSizeFromPath(path) {
  const filename = path.replace('/icons/', '').replace(/\//g, '');
  const sizeStr = filename.includes('favicon-')
    ? filename.replace('favicon-', '').replace('.png', '').split('x')[0]
    : '32';
  return parseInt(sizeStr, 10) || 32;
}

export function generateMacOSFaviconSVG(size) {
  const gradientId = `macOSGrad${size}`;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="${gradientId}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#007AFF;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0051D5;stop-opacity:1" />
    </linearGradient>
  </defs>

  <!-- macOS-style rounded rectangle background -->
  <rect width="${size}" height="${size}" rx="${d(size, 5)}" fill="url(#${gradientId})"/>

  <!-- Chat bubble icon optimized for small sizes -->
  <g transform="translate(${d(size, 2)}, ${d(size, 2)})">
    <!-- Main chat bubble -->
    <circle cx="-${d(size, 8)}" cy="-${d(size, 16)}" r="${d(size, 4)}" fill="white" opacity="0.95"/>
    <!-- Smaller bubble -->
    <circle cx="${d(size, 8)}" cy="${d(size, 16)}" r="${d(size, 6)}" fill="white" opacity="0.8"/>
    <!-- Chat dots -->
    <circle cx="-${d(size, 6)}" cy="-${d(size, 16)}" r="${Math.max(1, d(size, 24))}" fill="#007AFF"/>
    <circle cx="-${d(size, 8)}" cy="-${d(size, 16)}" r="${Math.max(1, d(size, 24))}" fill="#007AFF"/>
    <circle cx="-${d(size, 12)}" cy="-${d(size, 16)}" r="${Math.max(1, d(size, 24))}" fill="#007AFF"/>
  </g>
</svg>`;
}

/** /icon-NNN.png */
export function generateAppIconPNG(size) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="iconGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#007AFF;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0056CC;stop-opacity:1" />
    </linearGradient>
  </defs>

  <!-- Background Circle -->
  <circle cx="${d(size, 2)}" cy="${d(size, 2)}" r="${d(size, 2) - 2}" fill="url(#iconGrad)" stroke="#0056CC" stroke-width="2"/>

  <!-- Chat Emoji -->
  <text x="${d(size, 2)}" y="${d(size, 2) + d(size, 8)}" font-size="${d(size * 3, 4)}" text-anchor="middle" dominant-baseline="middle">💬</text>
</svg>`;
}

/** /icons/apple-icon-*, android-icon-*, ms-icon-*, favicon-* */
export function appleIconSizeFromPath(path) {
  const filename = path.split('/').pop() ?? '';
  let sizeStr;
  const pick = (prefix, def) => filename.replace(prefix, '').replace('.png', '').split('x')[0] || def;
  if (filename.includes('apple-icon-')) sizeStr = pick('apple-icon-', '180');
  else if (filename.includes('android-icon-')) sizeStr = pick('android-icon-', '192');
  else if (filename.includes('ms-icon-')) sizeStr = pick('ms-icon-', '144');
  else if (filename.includes('favicon-')) sizeStr = pick('favicon-', '32');
  else sizeStr = '180';
  return parseInt(sizeStr, 10) || 180;
}

export function generateAppleAppIconData(size) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="iconGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#007AFF;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0051D5;stop-opacity:1" />
    </linearGradient>
    <filter id="shadow" x="-50%" y="-50%" width="200%" height="200%">
      <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000000" flood-opacity="0.3"/>
    </filter>
  </defs>

  <!-- Background with rounded corners for modern app icon look -->
  <rect x="0" y="0" width="${size}" height="${size}" rx="${d(size, 5)}" ry="${d(size, 5)}" fill="url(#iconGrad)" filter="url(#shadow)"/>

  <!-- Chat bubble icon centered -->
  <g transform="translate(${d(size, 2)}, ${d(size, 2)})">
    <!-- Main chat bubble -->
    <circle cx="-${d(size, 8)}" cy="-${d(size, 12)}" r="${d(size, 4)}" fill="white" opacity="0.9"/>
    <!-- Smaller chat bubble -->
    <circle cx="${d(size, 8)}" cy="${d(size, 12)}" r="${d(size, 6)}" fill="white" opacity="0.7"/>
    <!-- Chat dots -->
    <circle cx="-${d(size, 6)}" cy="-${d(size, 12)}" r="${d(size, 32)}" fill="#007AFF"/>
    <circle cx="-${d(size, 8)}" cy="-${d(size, 12)}" r="${d(size, 32)}" fill="#007AFF"/>
    <circle cx="-${d(size, 12)}" cy="-${d(size, 12)}" r="${d(size, 32)}" fill="#007AFF"/>
  </g>
</svg>`;
}

export function generateWebManifest() {
  const icon = (src, sizes, type = 'image/png', purpose) => ({ src, sizes, type, ...(purpose ? { purpose } : {}) });
  return JSON.stringify({
    name: 'XCF Chat - Secure Real-time Chat',
    short_name: 'XCF Chat',
    description: 'Secure real-time chat with emoji avatars and file sharing',
    start_url: '/',
    display: 'standalone',
    background_color: '#121212',
    theme_color: '#007AFF',
    orientation: 'portrait-primary',
    scope: '/',
    icons: [
      icon('/favicon.ico', '16x16 32x32', 'image/x-icon'),
      icon('/icons/favicon-16x16.png', '16x16'),
      icon('/icons/favicon-32x32.png', '32x32'),
      icon('/icons/apple-icon-57x57.png', '57x57'),
      icon('/icons/apple-icon-60x60.png', '60x60'),
      icon('/icons/apple-icon-72x72.png', '72x72'),
      icon('/icons/apple-icon-76x76.png', '76x76'),
      icon('/icons/favicon-96x96.png', '96x96'),
      icon('/icons/apple-icon-114x114.png', '114x114'),
      icon('/icons/apple-icon-120x120.png', '120x120'),
      icon('/icons/apple-icon-144x144.png', '144x144'),
      icon('/icons/apple-icon-152x152.png', '152x152'),
      icon('/icons/apple-icon-180x180.png', '180x180'),
      icon('/icons/android-icon-192x192.png', '192x192', 'image/png', 'any maskable'),
      icon('/icons/android-icon-512x512.png', '512x512', 'image/png', 'any maskable'),
    ],
    categories: ['social', 'communication'],
    lang: 'en-US',
  }, null, 2);
}

export function generateBrowserConfig() {
  return `<?xml version="1.0" encoding="utf-8"?>
<browserconfig>
  <msapplication>
    <tile>
      <square70x70logo src="/icons/ms-icon-70x70.png"/>
      <square150x150logo src="/icons/ms-icon-150x150.png"/>
      <square310x310logo src="/icons/ms-icon-310x310.png"/>
      <TileColor>#007AFF</TileColor>
    </tile>
  </msapplication>
</browserconfig>`;
}

const FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";

export function generatePreviewImageSVG() {
  return `<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#4a5568;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#2d3748;stop-opacity:1" />
    </linearGradient>
    <filter id="blur">
      <feGaussianBlur in="SourceGraphic" stdDeviation="2"/>
    </filter>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <rect x="50" y="50" width="1100" height="70" rx="12" fill="rgba(30, 30, 30, 0.95)" filter="url(#blur)"/>
  <text x="80" y="95" font-family="${FONT}" font-size="24" font-weight="600" fill="#cbd5e0">💬 XCF Chat</text>
  <text x="1050" y="78" font-family="${FONT}" font-size="14" font-weight="500" fill="#30D158" text-anchor="end">✅ Connected</text>
  <text x="1050" y="98" font-family="${FONT}" font-size="12" fill="#cbd5e0" text-anchor="end">3 users online</text>
  <rect x="50" y="140" width="1100" height="420" rx="15" fill="#1e1e1e" stroke="#2d3748" stroke-width="1"/>
  <rect x="70" y="160" width="300" height="380" rx="12" fill="#121212"/>
  <rect x="90" y="180" width="260" height="65" rx="8" fill="rgba(0,122,255,0.2)" stroke="#2d3748" stroke-width="1"/>
  <text x="110" y="218" font-size="20" fill="#e2e8f0" dominant-baseline="middle">👤</text>
  <text x="145" y="218" font-family="${FONT}" font-size="16" font-weight="600" fill="#e2e8f0" dominant-baseline="middle">You</text>
  <text x="110" y="280" font-family="${FONT}" font-size="18" font-weight="600" fill="#cbd5e0">Rooms</text>
  <rect x="90" y="295" width="260" height="45" rx="8" fill="#007AFF"/>
  <text x="110" y="323" font-family="${FONT}" font-size="16" font-weight="500" fill="white">Lobby</text>
  <rect x="90" y="350" width="260" height="45" rx="8" fill="#1e1e1e" stroke="#2d3748" stroke-width="1"/>
  <text x="110" y="378" font-family="${FONT}" font-size="14" fill="#e2e8f0">General</text>
  <rect x="90" y="405" width="260" height="45" rx="8" fill="#1e1e1e" stroke="#2d3748" stroke-width="1"/>
  <text x="110" y="433" font-family="${FONT}" font-size="14" fill="#e2e8f0">Random</text>
  <rect x="390" y="160" width="740" height="380" rx="12" fill="#1e1e1e"/>
  <rect x="390" y="160" width="740" height="60" rx="12" fill="#1e1e1e" stroke="#2d3748" stroke-width="0 0 1 0"/>
  <text x="410" y="195" font-family="${FONT}" font-size="18" font-weight="600" fill="#e2e8f0">Lobby</text>
  <g transform="translate(410, 240)">
    <rect x="0" y="0" width="300" height="50" rx="12" fill="#000000"/>
    <text x="15" y="20" font-size="14" fill="#e2e8f0">🐶</text>
    <text x="40" y="20" font-family="${FONT}" font-size="12" font-weight="600" fill="#e2e8f0">Alice</text>
    <text x="220" y="20" font-family="${FONT}" font-size="10" fill="#d1d5db">2:30 PM</text>
    <text x="15" y="40" font-family="${FONT}" font-size="12" fill="#e2e8f0">Hey everyone!</text>
    <rect x="420" y="60" width="280" height="50" rx="12" fill="#0a84ff"/>
    <text x="435" y="80" font-size="14" fill="white">👤</text>
    <text x="460" y="80" font-family="${FONT}" font-size="12" font-weight="600" fill="white">You</text>
    <text x="620" y="80" font-family="${FONT}" font-size="10" fill="rgba(255,255,255,0.8)">2:31 PM</text>
    <text x="435" y="100" font-family="${FONT}" font-size="12" fill="white">Hello! How's it going?</text>
    <rect x="0" y="120" width="320" height="50" rx="12" fill="#000000"/>
    <text x="15" y="140" font-size="14" fill="#e2e8f0">🦊</text>
    <text x="40" y="140" font-family="${FONT}" font-size="12" font-weight="600" fill="#e2e8f0">Bob</text>
    <text x="240" y="140" font-family="${FONT}" font-size="10" fill="#d1d5db">2:32 PM</text>
    <text x="15" y="160" font-family="${FONT}" font-size="12" fill="#e2e8f0">Great! Love this chat app</text>
  </g>
  <rect x="410" y="485" width="600" height="40" rx="20" fill="#2d3748" stroke="#2d3748" stroke-width="1"/>
  <text x="430" y="509" font-family="${FONT}" font-size="12" fill="#9ca3af">Type a message...</text>
  <rect x="1020" y="485" width="100" height="40" rx="20" fill="#007AFF"/>
  <text x="1070" y="505" font-family="${FONT}" font-size="14" font-weight="500" fill="white" text-anchor="middle" dominant-baseline="central">Send</text>
  <text x="600" y="600" font-family="${FONT}" font-size="28" font-weight="700" fill="white" text-anchor="middle">Secure Real-time Chat</text>
  <text x="600" y="620" font-family="${FONT}" font-size="14" fill="rgba(255,255,255,0.8)" text-anchor="middle">Anonymous • Passwordless • Emoji Avatars • WebAuthn FIDO2 Passkeys</text>
</svg>`;
}
