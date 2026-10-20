import { readFile } from 'node:fs/promises';

const pageUrl = process.env.SENTINEL_LIVE_PAGE_URL;
if (!pageUrl) throw new Error('SENTINEL_LIVE_PAGE_URL must point at the deployed GitHub Pages site.');

const { version } = JSON.parse(await readFile(new URL('../website/package.json', import.meta.url), 'utf8'));
const installerName = `Sentinel.AI.Setup.${version}.exe`;
const releaseRoot = `https://github.com/Matyyyy68/asystent/releases/download/v${version}/`;

async function request(url, options = {}) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetch(url, { ...options, redirect: 'follow', signal: controller.signal });
      if (response.ok) return response;
      lastError = new Error(`${url} returned HTTP ${response.status}.`);
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timeout);
    }
    if (attempt < 3) await new Promise(resolve => setTimeout(resolve, attempt * 1_000));
  }
  throw lastError;
}

const pageResponse = await request(pageUrl);
const finalPageUrl = pageResponse.url || pageUrl;
const html = await pageResponse.text();
if (!html.includes(version)) throw new Error(`Deployed page does not mention product version ${version}.`);

const links = [...html.matchAll(/\bhref\s*=\s*["']([^"']+)["']/gi)]
  .map(match => new URL(match[1], finalPageUrl).toString());
const installerUrl = new URL(installerName, releaseRoot).toString();
const sidecarUrl = `${installerUrl}.sha256`;
if (!links.includes(installerUrl) || !links.includes(sidecarUrl))
  throw new Error(`Deployed page is missing the ${version} installer or SHA-256 sidecar link.`);

const installerResponse = await request(installerUrl, { method: 'HEAD' });
const sidecarResponse = await request(sidecarUrl);
const sidecar = (await sidecarResponse.text()).trim();
const match = sidecar.match(/^([a-f\d]{64})\s+(.+)$/i);
if (!match || match[2].trim() !== installerName)
  throw new Error(`The published checksum sidecar for ${installerName} has an invalid format.`);

const externalLinks = [...new Set(links.filter(link => {
  const url = new URL(link);
  return url.protocol === 'https:' && url.origin !== new URL(finalPageUrl).origin && link !== installerUrl && link !== sidecarUrl;
}))];
for (const link of externalLinks) {
  const response = await request(link, { method: 'HEAD' });
  console.log(`PASS: external link ${response.status} ${link}`);
}

console.log(`PASS: live page ${pageResponse.status} ${finalPageUrl}`);
console.log(`PASS: installer ${installerResponse.status} ${installerUrl}`);
console.log(`PASS: SHA-256 sidecar ${sidecarResponse.status} ${match[1].toUpperCase()}`);
