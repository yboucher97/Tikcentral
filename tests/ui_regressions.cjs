/* Real-browser regressions against offline rendered pages. No live router access.
 * python tests/render_ui_fixtures.py /tmp/tikcentral-ui
 * npm install --no-save playwright
 * npx playwright install chromium
 * node tests/ui_regressions.cjs /tmp/tikcentral-ui
 * CHROMIUM_PATH may point to an already installed browser.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

(async () => {
  const fixtures = path.resolve(process.argv[2]);
  const browser = await chromium.launch({headless: true, executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--no-sandbox']});
  const context = await browser.newContext({viewport: {width: 1440, height: 1000}, colorScheme: 'dark'});
  const errors = [], prefs = {};
  let failSave = false, slowRead = false, slowWrite = false, writes = 0, maxWrites = 0;
  await context.addInitScript(() => {
    window.copied = [];
    Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => window.copied.push(text)}});
  });
  await context.route('https://tikcentral.test/**', async route => {
    const req = route.request(), url = new URL(req.url());
    if (url.pathname === '/api/ui/preferences') {
      if (req.method() === 'PUT') {
        writes++; maxWrites = Math.max(maxWrites, writes);
        const {key, value} = req.postDataJSON();
        if (slowWrite) await new Promise(resolve => setTimeout(resolve, 120));
        if (!failSave) prefs[key] = value;
        writes--;
        return route.fulfill({status: failSave ? 503 : 200, json: {ok: !failSave}});
      }
      if (slowRead) await new Promise(resolve => setTimeout(resolve, 3000));
      return route.fulfill({json: {preferences: prefs, csrf: 'offline-test'}}).catch(() => {});
    }
    if (url.pathname.startsWith('/static/')) return route.fulfill({path: path.join(__dirname, '../app', url.pathname)});
    const name = url.pathname === '/routers' ? 'routers' : url.pathname === '/operations/1' ? 'router' : url.pathname === '/' ? 'dashboard' : 'checks';
    return route.fulfill({contentType: 'text/html', body: fs.readFileSync(path.join(fixtures, name + '.html'), 'utf8')});
  });
  const page = await context.newPage();
  page.on('pageerror', err => errors.push(err.message));
  const go = async url => {await page.goto('https://tikcentral.test' + url); await page.waitForSelector('.tc-table-tools', {state: 'attached'});};
  const waitSaved = () => page.waitForFunction(() => [...document.querySelectorAll('.tc-view-saved')].every(x => x.dataset.state === 'saved'));
  try {
    await go('/routers');
    const table = page.locator('table').first();
    assert.equal(await table.locator('thead th').first().isVisible(), true, 'first column must be visible');
    assert.equal(await table.locator('.tc-copy-btn').count(), 0, 'no duplicate inline copy buttons');
    const winbox = table.locator('tbody tr').first().locator('td').nth(9);
    await winbox.locator('button').click();
    assert.equal(await page.evaluate(() => copied.at(-1)), 'tikcentral.example.invalid:23003');

    // Restore a view with only the last column visible (previously failed).
    await page.locator('.tc-colbtn').click();
    const checks = page.locator('.tc-colmenu label input');
    const n = await checks.count();
    await checks.nth(n - 1).check();
    for (let i = 0; i < n - 1; i++) await checks.nth(i).uncheck();
    await waitSaved();
    await go('/routers');
    assert.equal(await table.locator('th:visible').count(), 1);
    assert.equal((await table.locator('th:visible').innerText()).trim(), 'Actions');
    await page.locator('.tc-colbtn').click();
    await page.locator('.tc-reset-columns').click();
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('.tc-colmenu').isVisible(), false);

    // Two quick changes must reach the server in order, without abort races.
    await waitSaved(); slowWrite = true; maxWrites = 0;
    await page.locator('#tcDensityToggle').click();
    await page.locator('#tcDensityToggle').click();
    await waitSaved(); slowWrite = false;
    assert.equal(prefs['ui:density'], 'comfortable');
    assert.equal(maxWrites, 1);
    failSave = true;
    await page.locator('#tcDensityToggle').click();
    await page.waitForFunction(() => document.querySelector('.tc-view-saved').dataset.state === 'error');
    failSave = false;
    await go('/routers'); await waitSaved();
    assert.equal(await page.locator('body').evaluate(b => b.classList.contains('tc-compact')), true);
    assert.equal(prefs['ui:density'], 'compact');
    await page.locator('#tcDensityToggle').click();

    await go('/checks');
    assert.equal(await page.locator('.tc-table-wrap').count(), 2, 'key/value tables get no nonfunctional filter toolbar');
    assert.equal(await page.locator('.tc-count').nth(1).textContent(), '0 rows', 'empty placeholders are not data');
    const first = page.locator('.tc-table-wrap').first();
    await first.locator('tbody tr').first().locator('td').nth(2).locator('button').click();
    assert.equal(await page.evaluate(() => copied.at(-1)), 'WAN recovered\nBackup link restored');
    await first.locator('.tc-copy-table').click();
    assert.ok((await page.evaluate(() => copied.at(-1))).includes('"WAN recovered\nBackup link restored"'), 'multiline TSV field must be quoted');
    await first.locator('.tc-local-search').fill('nonexistent');
    assert.equal(await first.locator('.tc-table-empty').isVisible(), true);
    assert.equal(await first.locator('.tc-copy-table').isDisabled(), true);
    await first.locator('.tc-table-empty button').click();
    assert.equal(await first.locator('.tc-count').textContent(), '2 rows');
    await first.locator('.tc-filter-toggle').click();
    await first.locator('.tc-date-to').fill('2026-09-19T08:15');
    assert.equal(await first.locator('.tc-count').textContent(), '1 of 2 rows', 'end minute includes seconds');
    await first.locator('.tc-reset').click();
    const heading = first.locator('th').first();
    await heading.focus(); await page.keyboard.press('Enter');
    assert.equal(await heading.getAttribute('aria-sort'), 'ascending');
    await page.keyboard.press('Space');
    assert.equal(await heading.getAttribute('aria-sort'), 'descending');

    await page.locator('#tcCommandBtn').click();
    await page.locator('#tcPaletteSearch').fill('alerts');
    await page.keyboard.press('ArrowDown');
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('href')), '/alerts');
    await page.keyboard.press('Escape');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'tcCommandBtn');

    await go('/routers');
    await page.locator('#tcMenuBtn').click(); await waitSaved();
    assert.equal(await page.locator('.tc-sidebar').isVisible(), false);
    await go('/routers');
    assert.equal(await page.locator('.tc-sidebar').isVisible(), false);
    await page.locator('#tcMenuBtn').click(); await waitSaved();

    for (const [width, theme] of [[1440, 'dark'], [1920, 'light'], [390, 'light'], [768, 'dark']]) {
      await page.setViewportSize({width, height: width < 821 ? 844 : 1000});
      await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'no page overflow at ' + width);
      if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, `routers-${width}-${theme}.png`), animations: 'disabled'});
    }
    await page.locator('#tcMenuBtn').click();
    assert.equal(await page.locator('#tcNavBackdrop').isVisible(), true);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#tcNavBackdrop').isVisible(), false);

    await page.setViewportSize({width: 1440, height: 1000});
    await go('/operations/1');
    assert.equal(await page.locator('.tc-workspace-section.active').getAttribute('data-tab'), 'Summary');
    await page.locator('.tc-workspace-tabs button[data-tab=Activity]').click();
    await waitSaved(); await go('/operations/1');
    assert.equal(await page.locator('.tc-workspace-section.active').getAttribute('data-tab'), 'Activity');
    await page.locator('.tc-workspace-tabs button[data-tab=Summary]').click();
    if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, 'router-summary.png'), animations: 'disabled'});

    slowRead = true;
    const start = Date.now(); await go('/routers');
    assert.ok(Date.now() - start < 2800, 'slow preference service cannot stall UI initialization');
    assert.equal(await page.locator('.tc-view-saved').getAttribute('data-state'), 'error');
    assert.deepEqual(errors, []);
    console.log('UI regressions: PASS (columns, preferences, copy, dates, empty states, keyboard, responsive layout, router tabs, stalled API)');
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
