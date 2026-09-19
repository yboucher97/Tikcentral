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
  const errors = [], prefs = {}, mutations = [];
  let fixtureRole = 'admin';
  let failSave = false, slowRead = false, slowWrite = false, writes = 0, maxWrites = 0;
  await context.addInitScript(() => {
    window.copied = [];
    Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => window.copied.push(text)}});
  });
  await context.route('https://tikcentral.test/**', async route => {
    const req = route.request(), url = new URL(req.url());
    if (!['GET', 'HEAD'].includes(req.method()) && url.pathname !== '/api/ui/preferences') mutations.push(req.method() + ' ' + url.pathname);
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
    const name = url.pathname === '/routers' ? 'routers' : url.pathname === '/operations/1' ? 'router-' + fixtureRole : url.pathname === '/' ? 'dashboard' : 'checks';
    return route.fulfill({contentType: 'text/html', body: fs.readFileSync(path.join(fixtures, name + '.html'), 'utf8')});
  });
  const page = await context.newPage();
  page.on('pageerror', err => errors.push(err.message));
  const go = async url => {await page.goto('https://tikcentral.test' + url); await page.waitForSelector('.tc-table-tools', {state: 'attached'});};
  const waitSaved = () => page.waitForFunction(() => [...document.querySelectorAll('.tc-view-saved')].every(x => x.dataset.state === 'saved'));
  const snapshot = async raw => page.evaluate(raw => {
    const doc = raw ? new DOMParser().parseFromString(raw, 'text/html') : document;
    const root = doc.querySelector('.tc-content');
    return {
      links: [...root.querySelectorAll('a[href]')].map(a => a.getAttribute('href')),
      forms: [...root.querySelectorAll('form')].map(f => JSON.stringify({
        action: f.getAttribute('action'), method: f.getAttribute('method'),
        fields: [...f.querySelectorAll('[name]')].map(x => [x.name, x.value, x.type, x.getAttribute('onclick')]),
        confirmations: [...f.querySelectorAll('[onclick]')].map(x => x.getAttribute('onclick')),
      })).sort(),
      headings: [...root.querySelectorAll('h2,h3')].map(x => x.textContent.trim()),
      tables: [...root.querySelectorAll('table')].map(t => [...t.querySelectorAll('th')].map(x => x.textContent.trim()).join('|')).sort(),
    };
  }, raw);
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
    await page.locator('#tcCommandBtn').click();
    await page.keyboard.press('ArrowUp');
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('href')), '/training/intelligence-guide');
    await page.keyboard.press('Escape');

    await go('/routers');
    await page.locator('#tcMenuBtn').click(); await waitSaved();
    assert.equal(await page.locator('.tc-sidebar').isVisible(), false);
    await go('/routers');
    assert.equal(await page.locator('.tc-sidebar').isVisible(), false);
    await page.locator('#tcMenuBtn').click(); await waitSaved();
    const fleetGroup = page.locator('[data-nav-group=fleet]');
    await fleetGroup.locator('summary').click();
    await page.waitForFunction(() => localStorage.getItem('tikcentral:account-pref:1:ui:nav-group:fleet') === 'true');
    await waitSaved(); await go('/routers');
    assert.equal(await fleetGroup.evaluate(x => x.open), true, 'expanded navigation group must persist');
    await fleetGroup.locator('summary').click();
    await page.waitForFunction(() => localStorage.getItem('tikcentral:account-pref:1:ui:nav-group:fleet') === 'false');
    await waitSaved();

    for (const [width, theme] of [[1440, 'dark'], [1920, 'light'], [390, 'light'], [768, 'dark']]) {
      await page.setViewportSize({width, height: width < 821 ? 844 : 1000});
      if (await page.evaluate(() => document.documentElement.dataset.theme) !== theme) await page.locator('#tcTheme').click();
      await waitSaved();
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'no page overflow at ' + width);
      if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, `routers-${width}-${theme}.png`), animations: 'disabled'});
    }
    await page.locator('#tcMenuBtn').click();
    assert.equal(await page.locator('#tcNavBackdrop').isVisible(), true);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#tcNavBackdrop').isVisible(), false);

    await page.setViewportSize({width: 1440, height: 1000});
    await go('/operations/1');
    const original = await snapshot(fs.readFileSync(path.join(fixtures, 'router-admin.html'), 'utf8'));
    const organized = await snapshot(null);
    for (const href of original.links) assert.ok(organized.links.includes(href), 'router destination lost: ' + href);
    for (const href of ['/timeline/1', '/incidents/1', '/network-quality/1', '/site/1', '/notes/1', '/changes/1', '/ai/1']) {
      assert.ok(organized.links.includes(href), 'destination from the consolidated router context bar lost: ' + href);
    }
    for (const heading of original.headings) assert.ok(organized.headings.includes(heading), 'router content lost: ' + heading);
    assert.deepEqual(organized.forms, original.forms, 'form actions, values and confirmations must survive layout changes');
    assert.deepEqual(organized.tables, original.tables, 'all history tables must remain available');
    assert.equal(await page.locator('#tcObjectContext .tc-contextbar').count(), 0, 'no duplicate router identity header');
    assert.equal(await page.locator('.tc-workspace-section.active').getAttribute('data-tab'), 'Summary');
    await page.locator('.tc-workspace-tabs button[data-tab=Summary]').focus();
    await page.keyboard.press('ArrowRight');
    assert.equal(await page.locator('[role=tab][aria-selected=true]').getAttribute('data-tab'), 'Connectivity');
    await page.keyboard.press('Home');
    assert.equal(await page.locator('[role=tab][aria-selected=true]').getAttribute('data-tab'), 'Summary');

    await page.locator('.tc-router-toolbox > summary').click();
    await page.locator('#tcRouterToolSearch').fill('dns');
    assert.equal(await page.locator('.tc-router-tool-groups a:visible').count(), 1);
    assert.equal(await page.locator('.tc-router-tool-groups a:visible').getAttribute('href'), '/network-quality/1');
    await page.locator('#tcRouterToolSearch').fill('unfindable');
    assert.equal(await page.locator('.tc-tool-empty').isVisible(), true);
    await page.locator('#tcRouterToolSearch').fill('');
    if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, 'router-tools.png'), animations: 'disabled', fullPage: true});
    await page.locator('.tc-router-toolbox > summary').click();
    await page.locator('#tcGlobalSearch').fill('WAN link recovered');
    assert.equal(await page.locator('.tc-workspace-section[data-tab=Activity] tbody tr:visible').count(), 1);
    assert.equal(await page.locator('.tc-router-hero').isVisible(), true);
    assert.equal(await page.locator('#tcPageSearchStatus').isVisible(), true);
    await page.locator('#tcGlobalSearch').fill('content-that-is-not-here');
    assert.equal(await page.locator('.tc-workspace-section:visible').count(), 0);
    assert.ok((await page.locator('#tcPageSearchStatus').textContent()).startsWith('No matching content'));
    await page.locator('.tc-workspace-tabs button[data-tab=Summary]').click();
    assert.equal(await page.locator('#tcGlobalSearch').inputValue(), '');
    assert.equal(await page.locator('.tc-workspace-section.active').count(), 1);
    await page.locator('.tc-workspace-tabs button[data-tab=Activity]').click();
    await waitSaved(); await go('/operations/1');
    assert.equal(await page.locator('.tc-workspace-section.active').getAttribute('data-tab'), 'Activity');
    const events = page.locator('.tc-workspace-section[data-tab=Activity] .tc-table-wrap').last();
    await events.locator('.tc-local-search').fill('warning');
    await page.locator('#tcGlobalSearch').fill('Gateway');
    await page.locator('#tcPageSearchClear').click();
    assert.equal(await events.locator('.tc-local-search').inputValue(), 'warning', 'page search must restore prior table filters');
    await page.locator('.tc-workspace-tabs button[data-tab=Summary]').click();
    if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, 'router-summary.png'), animations: 'disabled'});

    // Navigation completeness and role restrictions are checked in the browser,
    // including controls which have moved into tabs and tool disclosures.
    const navigation = JSON.parse(fs.readFileSync(path.join(fixtures, 'navigation.json'), 'utf8'));
    for (const role of ['admin', 'technician', 'viewer']) {
      fixtureRole = role; await go('/operations/1');
      const before = await snapshot(fs.readFileSync(path.join(fixtures, 'router-' + role + '.html'), 'utf8'));
      const after = await snapshot(null);
      assert.deepEqual(after.forms, before.forms, role + ' forms changed during organization');
      const destinations = await page.locator('#tcSidebar a[href]').evaluateAll(links => links.map(a => a.getAttribute('href')));
      for (const href of navigation[role]) assert.ok(destinations.includes(href), role + ' sidebar destination missing: ' + href);
      if (role !== 'admin') for (const href of ['/admin/users', '/settings', '/ssh', '/enroll']) assert.ok(!destinations.includes(href));
      if (role === 'viewer') assert.equal(await page.locator('.tc-content form[method=post] button:not(:disabled):not(.tc-copy-btn)').count(), 0);
      if (role === 'admin') {
        for (const width of [390, 768]) {
          await page.setViewportSize({width, height: 844});
          assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'router overflow at ' + width);
          assert.ok(await page.locator('.tc-workspace-tabs').evaluate(x => x.scrollWidth <= x.clientWidth + 1), 'all router tabs must be discoverable on mobile');
          if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, 'router-' + width + '.png'), animations: 'disabled'});
          for (const tab of ['Connectivity', 'Configuration', 'Assets', 'Activity', 'Summary']) {
            await page.locator('.tc-workspace-tabs button[data-tab=' + tab + ']').click();
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), tab + ' overflow at ' + width);
          }
        }
        await page.setViewportSize({width: 1440, height: 1000});
        await page.locator('#tcTheme').click(); await waitSaved();
        if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, 'router-light.png'), animations: 'disabled'});
      }
    }
    fixtureRole = 'admin';
    await go('/');
    const dashboardBefore = await snapshot(fs.readFileSync(path.join(fixtures, 'dashboard.html'), 'utf8'));
    const dashboardAfter = await snapshot(null);
    assert.deepEqual(dashboardAfter.forms, dashboardBefore.forms);
    assert.deepEqual(dashboardAfter.tables, dashboardBefore.tables);
    assert.equal(await page.locator('.tc-dashboard-utilities > .panel').count(), 2);
    if (process.env.UI_SCREENSHOTS) await page.screenshot({path: path.join(fixtures, 'dashboard.png'), animations: 'disabled'});
    assert.deepEqual(mutations, [], 'navigation and layout controls must never trigger router actions or AI');

    slowRead = true;
    const start = Date.now(); await go('/routers');
    assert.ok(Date.now() - start < 2800, 'slow preference service cannot stall UI initialization');
    assert.equal(await page.locator('.tc-view-saved').getAttribute('data-state'), 'error');
    assert.deepEqual(errors, []);
    console.log('UI regressions: PASS (feature/form parity, roles, navigation, tool discovery, search, columns, preferences, copy, dates, keyboard, responsive layout, stalled API)');
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
