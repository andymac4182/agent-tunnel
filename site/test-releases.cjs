const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright');
const repo = 'https://github.com/andymac4182/agentuplink/releases/download/';
const targets = ['x86_64-unknown-linux-gnu', 'aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc'];
function release(run) {
  const tag = `v0.1.0-main.${run}.aaaaaaaaaaaa`;
  return { tag_name: tag, draft: false, assets: targets.flatMap(target => {
    const filename = `agentuplink-${tag}-${target}.${target.endsWith('windows-msvc') ? 'zip' : 'tar.gz'}`;
    return ['', '.sha256'].map(suffix => ({ name: filename + suffix, state: 'uploaded', size: 10, browser_download_url: `${repo}${tag}/${filename}${suffix}` }));
  }) };
}
(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const partial = release(300); partial.assets.pop();
    const draft = release(400); draft.draft = true;
    for (const [name, status, data, expected] of [
      ['empty', 200, [], 'No complete development release'],
      ['latest complete', 200, [release(100), partial, draft, release(200)], 'v0.1.0-main.200.aaaaaaaaaaaa'],
      ['partial', 200, [partial], 'No complete development release'],
      ['unavailable', 403, {}, 'could not be reached'],
    ]) {
      const page = await browser.newPage();
      await page.route('https://api.github.com/**', route => route.fulfill({ status, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(data) }));
      await page.setContent('<div data-release-info>Loading</div>');
      await page.addScriptTag({ path: path.join(__dirname, 'releases.js') });
      await page.waitForFunction(text => document.body.innerText.includes(text), expected);
      if (name === 'latest complete') assert.equal(await page.locator('li a').count(), 8);
      await page.close();
      console.log(`PASS ${name}`);
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
