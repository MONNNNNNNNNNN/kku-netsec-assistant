'use strict';
/*
 * Browser end-to-end test (Playwright, headless Chromium; dev dependency only).
 *   npm run test:e2e            (first time: npx playwright install chromium)
 * Boots a board against the mocks, then drives the real UI. Screenshots (light, dark, phone)
 * go to a temp folder; UPDATE_SCREENSHOTS=1 writes them to docs/screenshots/ for the README.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const M = require('../../mocks/servers.js');
const { startBoard, sleep } = require('../board/helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const SHOTS = process.env.UPDATE_SCREENSHOTS === '1' ? path.join(ROOT, 'docs/screenshots') : fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'nsb-shots-'));
const LOGS = fs.readFileSync(path.join(ROOT, 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean);

test('board in a real browser: login, live cards, expand/collapse, pin, ack, snooze, toasts, bell, filters, Explain, dark mode, phone width', { timeout: 120000 }, async () => {
  fs.mkdirSync(SHOTS, { recursive: true });
  const wz = await M.mockWazuh({ username: 'ro', password: 'e2e-wz-pass' });
  const zbx = await M.mockZabbix({ token: 'e2e-zbx-tok' });
  const llm = await M.mockLlm({ mode: 'adversarial' });
  const dropDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'nsb-drop-'));
  fs.copyFileSync(path.join(ROOT, 'samples/fgt-demo.conf'), path.join(dropDir, 'FGT-DEMO-CORE_20261106.conf'));
  const { app } = await startBoard({
    lang: 'en',
    sources: {
      syslog: { enabled: true, port: 0, allow: ['127.0.0.1'], minSeverity: 'low', ratePerSec: 100000 },
      wazuh: { enabled: true, schedule: '@every 1h', url: wz.url, username: 'ro', password: 'e2e-wz-pass' },
      zabbix: { enabled: true, schedule: '@every 1h', url: zbx.url, token: 'e2e-zbx-tok' },
      configdrop: { enabled: true, schedule: '@every 1h', dir: dropDir },
    },
    llm: { url: llm.url, model: 'mock-adversarial', budgetPerHour: 20, autoMinSeverity: 'critical' },
  });
  const browser = await chromium.launch();
  const dialogs = [];
  try {
    await Promise.all(['wazuh', 'zabbix', 'configdrop'].map((s) => app.scheduler.run(s)));
    const xss = LOGS[1].replace(/agent="[^"]*"/, 'agent="<img src=x onerror=alert(1)><script>alert(2)</script>"');
    await M.sendSyslog([xss, LOGS[4], LOGS[5], LOGS[7], LOGS[2]], { port: app.syslogAddress.udp.port });
    await sleep(300);

    const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
    const page = await ctx.newPage();
    page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

    // login
    await page.goto(app.url);
    await page.fill('#u', 'op');
    await page.fill('#p', 'wrong-password');
    await page.click('button[type=submit]');
    await page.waitForSelector('.login .err:text("wrong username or password")');
    await page.fill('#p', 'op-password-123');
    await page.click('button[type=submit]');
    await page.waitForSelector('.tile.hero');
    await page.waitForFunction(() => document.querySelectorAll('#app .card').length >= 10);
    await sleep(300);
    await page.screenshot({ path: path.join(SHOTS, 'board-light.png') });

    // XSS stays text
    assert.equal(await page.locator('img[src="x"]').count(), 0, 'no injected <img>');
    const xssCard = page.locator('.card', { hasText: 'HTTP.URI.SQL.Injection' }).first();
    await xssCard.locator('button[aria-expanded]').click();
    await page.waitForSelector('.card.expanded .fields');
    assert.equal(await xssCard.locator('tr.untrusted td', { hasText: '<img src=x onerror=alert(1)>' }).count(), 1, 'payload shown as text in an untrusted row');
    assert.equal(await xssCard.locator('button[aria-expanded]').getAttribute('aria-expanded'), 'true');
    assert.ok(await page.locator('#app .card .badge.inj').count() >= 1, 'injection badge on the prompt-injection lines');
    await xssCard.scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(SHOTS, 'board-card.png') });

    // Explain (fake adversarial LLM; the guard must override "benign")
    await xssCard.locator('button', { hasText: 'Explain' }).click();
    await page.waitForSelector('.toast:has-text("Queued for AI")');
    await page.waitForFunction(() => [...document.querySelectorAll('.card.expanded .badge.ai')].some((b) => /AI: (suspicious|malicious|unknown)/.test(b.textContent)), null, { timeout: 15000 });
    assert.equal(await page.locator('.card.expanded .verdict li', { hasText: 'guard changed' }).count() >= 1, true);

    // collapse
    await xssCard.locator('button[aria-expanded="true"]').click();
    await page.waitForFunction(() => !document.querySelector('.card.expanded'));

    // pin -> pinned section; survives reload (server-side state)
    const zcard = page.locator('#app .card', { hasText: 'FortiGate HA' }).first();
    await zcard.locator('button', { hasText: 'Pin' }).click();
    await page.waitForFunction(() => document.querySelector('main .masonry .card .badge.pin'));
    await page.reload();
    await page.waitForSelector('.tile.hero');
    const firstMasonry = page.locator('main .masonry').first();
    assert.equal(await firstMasonry.locator('.card', { hasText: 'FortiGate HA' }).count(), 1, 'pinned after reload');

    // ack -> leaves Open, shows under Acknowledged
    const live = page.locator('main .masonry').nth(1);
    const ackId = await live.locator('.card').first().getAttribute('data-id');
    await live.locator('.card').first().locator('button', { hasText: 'Acknowledge' }).click();
    await page.waitForFunction((id) => !document.getElementById(`item-${id}`), ackId);
    await page.click('button.chip-f:has-text("Acknowledged")');
    await page.waitForSelector(`#item-${ackId}.card.acked`);
    await page.click('button.chip-f:has-text("Open")');

    // snooze 1h
    await page.waitForFunction(() => document.querySelectorAll('main .masonry')[1].querySelector('.card'));
    const snzId = await live.locator('.card').first().getAttribute('data-id');
    await live.locator('.card').first().locator('button[aria-label="Snooze 1h"]').click();
    await page.waitForFunction((id) => !document.getElementById(`item-${id}`), snzId);
    assert.ok(app.db.prepare('SELECT snoozed_until FROM items WHERE id = ?').get(Number(snzId)).snoozed_until > Date.now() + 3500000);

    // filter chip: wazuh only
    await page.click('.chips button:has-text("wazuh")');
    await page.waitForFunction(() => [...document.querySelectorAll('main .masonry')[1].querySelectorAll('.card .src-badge')].every((b) => b.textContent.includes('wazuh')));
    await page.click('.chips button:has-text("wazuh")');

    // F3: a 2,000-line burst must not freeze the page (coalesced SSE + in-place count patches)
    await page.evaluate(() => { window.__longest = 0; new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__longest = Math.max(window.__longest, e.duration); }).observe({ type: 'longtask', buffered: false }); });
    await M.sendSyslog(Array(2000).fill(LOGS[17]), { port: app.syslogAddress.tcp.port, proto: 'tcp' });
    await page.waitForFunction(() => [...document.querySelectorAll('#app .card')].some((c) => c.textContent.includes('PHP.CGI') && /×2000/.test(c.textContent)), null, { timeout: 15000 });
    const longest = await page.evaluate(() => window.__longest);
    assert.ok(longest < 200, `main thread blocked ${longest} ms during the burst`);

    // live: a new critical event -> grouped toast + bell count -> drawer with collapsible group
    await M.sendSyslog([LOGS[16], LOGS[18]], { port: app.syslogAddress.udp.port });
    await page.waitForSelector('.toast:has-text("fortigate")');
    await page.waitForFunction(() => Number(document.querySelector('.bell .dot').textContent) >= 1);
    await page.click('.bell');
    await page.waitForSelector('.drawer .ngroup');
    const grp = page.locator('.drawer .ngroup > button').first();
    assert.equal(await grp.getAttribute('aria-expanded'), 'true');
    await grp.click();
    assert.equal(await page.locator('.drawer .ngroup > button').first().getAttribute('aria-expanded'), 'false');
    await page.keyboard.press('Escape');
    await page.waitForSelector('.drawer', { state: 'hidden' });

    // expand all / collapse all, keyboard j + e
    await page.click('button:has-text("Expand all")');
    await page.waitForFunction(() => document.querySelectorAll('.card.expanded').length >= 5);
    await page.click('button:has-text("Collapse all")');
    await page.waitForFunction(() => !document.querySelector('.card.expanded'));
    await page.locator('body').click({ position: { x: 5, y: 500 } });
    await page.keyboard.press('j');
    await page.keyboard.press('e');
    await page.waitForFunction(() => document.querySelectorAll('.card.expanded').length === 1);

    // Thai
    await page.click('button[aria-label="TH/EN"]');
    await page.waitForSelector('h2.sec:has-text("ปักหมุด")');
    await page.click('button[aria-label="TH/EN"]');

    // dark mode
    await page.click('button[aria-label="Theme"]');
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'dark');
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    assert.equal(bg, 'rgb(23, 24, 31)');
    await page.screenshot({ path: path.join(SHOTS, 'board-dark.png') });
    await page.click('button[aria-label="Theme"]'); await page.click('button[aria-label="Theme"]');

    // D2: the live stream drops (network, sleep, server cut); a card created meanwhile must
    // appear after the automatic reconnect, without a reload
    for (const res of [...app.sse.keys()]) { app.sse.delete(res); res.destroy(); }
    const T = require('../../server/trust.js');
    app.pipeline.ingest(T.generic({ title: 'RECONNECT-CANARY', severity: 'high', key: 'reconnect' }), 'generic');
    app.pipeline.flush();
    await page.waitForSelector('#app .card:has-text("RECONNECT-CANARY")', { timeout: 8000 });

    // viewer: read-only buttons
    const vctx = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    const vp = await vctx.newPage();
    vp.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
    await vp.goto(app.url);
    await vp.fill('#u', 'view'); await vp.fill('#p', 'view-password-123'); await vp.click('button[type=submit]');
    await vp.waitForSelector('#app .card');
    assert.ok(await vp.locator('#app .card button:has-text("Pin")').first().isDisabled(), 'viewer cannot pin');
    const overflow = await vp.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `horizontal overflow ${overflow}px at 390px`);
    await vp.screenshot({ path: path.join(SHOTS, 'board-phone.png') });

    assert.deepEqual(dialogs, [], 'no script ever ran from log data');
    assert.deepEqual(errors.filter((e) => !/401|Failed to load resource/.test(e)), [], 'no console errors');
    await vctx.close(); await ctx.close();
  } finally {
    await browser.close();
    await app.close();
    for (const m of [wz, zbx, llm]) m.server.close();
  }
});
