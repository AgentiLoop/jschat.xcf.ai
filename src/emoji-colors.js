// Port of WebServer.analyzeEmojiColors (POST /emoji/analyze).
// The Swift server rasterised the emoji with CoreText ("Apple Color Emoji") and averaged
// opaque pixels. Workers have no font rasteriser, so the average colour is taken from the
// fill colours of the open-source Twemoji SVG for the same emoji. The contrast/text colour
// math below is identical to the Swift implementation.

const TWEMOJI_BASE = 'https://cdn.jsdelivr.net/gh/jdecked/twemoji@latest/assets/svg/';

function twemojiCode(emoji) {
  const cps = Array.from(emoji).map((c) => c.codePointAt(0));
  const filtered = cps.includes(0x200d) ? cps : cps.filter((cp) => cp !== 0xfe0f);
  return filtered.map((cp) => cp.toString(16)).join('-');
}

function parseHex(hex) {
  if (hex.length === 3) hex = hex.split('').map((c) => c + c).join('');
  return [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16));
}

const hex2 = (n) => n.toString(16).toUpperCase().padStart(2, '0');

export async function analyzeEmojiColors(emoji) {
  const res = await fetch(TWEMOJI_BASE + twemojiCode(emoji) + '.svg', { cf: { cacheTtl: 86400, cacheEverything: true } });
  if (!res.ok) throw new Error('renderingFailed');
  const svg = await res.text();

  const fills = [...svg.matchAll(/fill="#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})"/g)].map((m) => parseHex(m[1]));
  if (!fills.length) throw new Error('colorAnalysisFailed');

  const total = fills.reduce((acc, [r, g, b]) => [acc[0] + r, acc[1] + g, acc[2] + b], [0, 0, 0]);
  const avgRed = Math.trunc(total[0] / fills.length);
  const avgGreen = Math.trunc(total[1] / fills.length);
  const avgBlue = Math.trunc(total[2] / fills.length);

  const brightness = Math.trunc((avgRed + avgGreen + avgBlue) / 3);

  let contrastRed, contrastGreen, contrastBlue;
  if (brightness > 128) {
    contrastRed = Math.max(0, avgRed - 100);
    contrastGreen = Math.max(0, avgGreen - 100);
    contrastBlue = Math.max(0, avgBlue - 100);
  } else {
    contrastRed = Math.min(255, avgRed + 100);
    contrastGreen = Math.min(255, avgGreen + 100);
    contrastBlue = Math.min(255, avgBlue + 100);
  }

  const contrastBrightness = Math.trunc((contrastRed + contrastGreen + contrastBlue) / 3);
  const textColor = contrastBrightness > 128 ? '#000000' : '#FFFFFF';

  return {
    averageColor: `#${hex2(avgRed)}${hex2(avgGreen)}${hex2(avgBlue)}`,
    contrastColor: `#${hex2(contrastRed)}${hex2(contrastGreen)}${hex2(contrastBlue)}`,
    textColor,
  };
}
