const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const root = __dirname;
  const server = http.createServer(async (req, res) => {
    const route = new URL(req.url, 'http://localhost').pathname;
    const files = { '/': 'index.html', '/style.css': 'style.css', '/hero.jpg': 'hero.jpg', '/theme.css': 'theme.css', '/theme.js': 'theme.js', '/brand-lab': 'brand-lab.html', '/brand-lab.css': 'brand-lab.css', '/brand-lab.js': 'brand-lab.js', '/logo-board.png': 'logo-board.png' };
    if (!files[route]) { res.writeHead(404).end(); return; }
    res.setHeader('Content-Type', route.endsWith('.css') ? 'text/css' : route.endsWith('.js') ? 'text/javascript' : route.endsWith('.jpg') ? 'image/jpeg' : route.endsWith('.png') ? 'image/png' : 'text/html');
    res.end(await fs.readFile(path.join(root, files[route])));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
    for (const [width, height] of [[1440, 1000], [1920, 1080], [390, 844], [320, 740]]) {
      const page = await browser.newPage({ viewport: { width, height } });
      const failures = [];
      page.on('pageerror', error => failures.push(error.message));
      page.on('response', response => { if (response.status() >= 400) failures.push(response.url()); });
      await page.goto(process.env.SITE_URL || `http://127.0.0.1:${server.address().port}`, { waitUntil: 'networkidle' });
      assert.equal(await page.locator('h1').innerText(), 'Agent Uplink');
      for (const theme of ['dark', 'light']) {
        await page.getByLabel('Colour theme').selectOption(theme);
        assert.equal(await page.locator('html').getAttribute('data-theme'), theme);
        await page.reload();
        assert.equal(await page.locator('html').getAttribute('data-theme'), theme);
      }
      await page.getByLabel('Colour theme').selectOption('system');
      await page.emulateMedia({ colorScheme: 'dark' });
      await page.waitForFunction(() => document.documentElement.dataset.theme === 'dark');
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert(await page.evaluate(() => [...document.querySelectorAll('a[href^="#"]')].every(a => a.hash === '' || a.hash === '#' || document.getElementById(a.hash.slice(1)))));
      assert(await page.evaluate(async () => { const image = new Image(); image.src = '/hero.jpg'; await image.decode(); return image.naturalWidth > 1000; }));
      await page.locator('.button').click();
      await page.waitForURL('**/#connection');
      await page.screenshot({ path: `/tmp/agentuplink-${width}.png`, fullPage: true });
      await page.goto(new URL('/brand-lab', page.url()).href, { waitUntil: 'networkidle' });
      assert.equal(await page.locator('.option').count(), 20);
      assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.screenshot({ path: `/tmp/agentuplink-brand-dark-${width}.png`, fullPage: true });
      await page.getByLabel('Colour theme').selectOption('light');
      assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
      assert.deepEqual(failures, []);
      console.log(`PASS ${width}x${height}: layout, links, image, navigation, console`);
      await page.close();
    }
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
