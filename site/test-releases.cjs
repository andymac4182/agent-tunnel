const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright');
const fs = require('node:fs');
const repo = 'https://github.com/andymac4182/agentuplink/releases/download/';
// Derived from releases.js, never copied. A fixture carrying its own copy of
// the list under test regenerates itself when that list changes, so the test
// keeps passing while the thing it tests drifts -- which is the defect
// docs/tasks.md M6-C18 was filed for, in the test suite rather than the site.
// The declaration itself is bound to [workspace.metadata.release] by
// `scripts/m6-release-checks.py --check packaging`.
const source = fs.readFileSync(path.join(__dirname, 'releases.js'), 'utf8');
const found = source.match(/^\s*const\s+targets\s*=\s*\[([^\]]*)\]\s*;/m);
if (!found) throw new Error('could not read `const targets` from releases.js; the fixture must derive from the file under test, never assume a list');
const targets = found[1].split(',').map(t => t.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
if (targets.length === 0) throw new Error('releases.js declares an empty target list; a fixture built from it would assert nothing');
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
      if (name === 'latest complete') assert.equal(await page.locator('li a').count(), targets.length * 2);
      await page.close();
      console.log(`PASS ${name}`);
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
