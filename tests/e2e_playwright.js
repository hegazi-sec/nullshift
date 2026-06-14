/**
 * NullShift — Full Playwright E2E Test Suite
 */

const { chromium } = require('playwright');

const BASE  = 'http://127.0.0.1:8765';
const ADMIN = 'admin';
const PASS  = 'AIslam@Hegazy234@';

// ── helpers ──────────────────────────────────────────────────────────────────
let passed = 0, failed = 0, skipped = 0;
const results = [];

function ok(name, got, want) {
  const p = got === want;
  if (p) { passed++; } else { failed++; }
  results.push({ name, ok: p, got, want });
  console.log(`  ${p ? '✓' : '✗'} ${name}` + (p ? '' : `\n      got:  ${JSON.stringify(got)}\n      want: ${JSON.stringify(want)}`));
  return p;
}
function contains(name, haystack, needle) {
  const p = (haystack || '').includes(needle);
  if (p) { passed++; } else { failed++; }
  results.push({ name, ok: p });
  console.log(`  ${p ? '✓' : '✗'} ${name}` + (p ? '' : `\n      missing: "${needle}"`));
  return p;
}
function notNull(name, val) {
  const p = val !== null && val !== undefined;
  if (p) { passed++; } else { failed++; }
  results.push({ name, ok: p });
  console.log(`  ${p ? '✓' : '✗'} ${name}`);
  return p;
}
function skip(name, reason) {
  skipped++;
  results.push({ name, ok: 'skip', reason });
  console.log(`  - ${name} (skipped: ${reason})`);
}

async function section(label, fn) {
  console.log(`\n── ${label} ──`);
  try { await fn(); }
  catch (e) {
    failed++;
    results.push({ name: label + ' [CRASH]', ok: false, error: e.message });
    console.log(`  ✗ CRASH: ${e.message}`);
  }
}

async function login(page, user = ADMIN, pass = PASS) {
  await page.goto(`${BASE}/login`);
  await page.waitForLoadState('domcontentloaded');
  await page.fill('input[name="username"]', user);
  await page.fill('input[name="password"]', pass);
  await page.click('button[type="submit"]');
  await page.waitForLoadState('domcontentloaded');
}

async function getCsrf(page) {
  return page.evaluate(() => {
    const c = document.cookie.split('; ').find(r => r.startsWith('csrftoken='));
    return c ? c.split('=')[1] : '';
  });
}

// ── MAIN ─────────────────────────────────────────────────────────────────────
(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx     = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page    = await ctx.newPage();

  // ─── 1. API health endpoints ──────────────────────────────────────────────
  await section('1. API endpoints', async () => {
    const h = await page.request.get(`${BASE}/health`);
    ok('GET /health → 200', h.status(), 200);
    const hj = await h.json();
    ok('/health returns status:ok', hj.status, 'ok');

    const debug = await page.request.get(`${BASE}/debug/llm`);
    ok('GET /debug/llm → 200', debug.status(), 200);
    const dj = await debug.json();
    notNull('/debug/llm has configured_providers', dj.configured_providers);
    ok('at least 1 provider configured', (dj.configured_providers || []).length >= 1, true);
  });

  // ─── 2. Login page ────────────────────────────────────────────────────────
  await section('2. Login page', async () => {
    await page.goto(`${BASE}/login`);
    await page.waitForLoadState('domcontentloaded');

    contains('page title contains NullShift', await page.title(), 'NullShift');
    contains('brand name visible', await page.locator('.brand-name').textContent().catch(() => ''), 'NullShift');
    contains('security footer', await page.locator('.login-footer').textContent().catch(() => ''), 'Unauthorised access');
    notNull('username input', await page.$('input[name="username"]'));
    notNull('password input', await page.$('input[name="password"]'));
    notNull('submit button', await page.$('button[type="submit"]'));

    // Card top accent line
    notNull('login card present', await page.$('.card'));

    // Bad credentials — should stay on login
    await page.fill('input[name="username"]', 'baduser');
    await page.fill('input[name="password"]', 'badpass123');
    await page.click('button[type="submit"]');
    await page.waitForLoadState('domcontentloaded');
    ok('bad creds stay on /login', page.url().includes('/login'), true);
  });

  // ─── 3. Login → Chat UI ───────────────────────────────────────────────────
  await section('3. Login → Chat UI', async () => {
    await login(page);

    ok('redirected away from /login', page.url().includes('/login'), false);
    contains('chat brand visible', await page.locator('.brand').first().textContent().catch(() => ''), 'NullShift');

    // Layout
    notNull('sidebar present', await page.$('.sidebar'));
    notNull('new-chat button', await page.$('#newChatBtn'));
    notNull('chat area', await page.$('.chat-area'));
    notNull('message textarea', await page.$('textarea'));

    // Welcome chips
    const chips = await page.$$('.hint-chip');
    ok('welcome hint chips rendered (≥1)', chips.length >= 1, true);

    // Debug panel toggle
    notNull('debug toggle', await page.$('#debugToggle'));
  });

  // ─── 4. Welcome chips interaction ────────────────────────────────────────
  await section('4. Hint chips interaction', async () => {
    const chips = await page.$$('.hint-chip');
    if (!chips.length) { skip('chip click', 'no chips found'); return; }

    const chipText = await chips[0].textContent();
    await chips[0].click();
    await page.waitForTimeout(300);
    const val = await page.locator('textarea').inputValue();
    ok('chip click fills textarea', val.length > 0, true);
    contains('textarea contains chip text', val, chipText.slice(0, 10));

    // Clear it
    await page.fill('textarea', '');
  });

  // ─── 5. Send message flow (UI-level) ─────────────────────────────────────
  await section('5. Chat send flow', async () => {
    // Ensure fresh conv
    await page.click('#newChatBtn');
    await page.waitForTimeout(400);

    await page.fill('textarea', 'Hello, give me a quick status summary');

    // User message should appear immediately on Enter
    await page.keyboard.press('Enter');
    const userMsg = await page.waitForSelector('.msg-wrap.user', { timeout: 3000 }).catch(() => null);
    notNull('user message bubble appears', userMsg);

    // Typing indicator should appear
    const typing = await page.$('#typingIndicator');
    notNull('typing indicator shown', typing);

    // Wait for bot response (SDK can take ~15s; we wait up to 30s)
    await page.waitForSelector('.msg-wrap.assistant:not(#typingIndicator)', { timeout: 30000 }).catch(() => null);
    const botMsgs = page.locator('.msg-wrap.assistant:not(#typingIndicator)');
    notNull('bot response rendered', await botMsgs.count() > 0 ? true : null);

    // Typing indicator should be gone
    const typingGone = await page.$('#typingIndicator');
    ok('typing indicator removed after response', typingGone, null);

    // Response has a bubble with text
    const bubbleText = await botMsgs.locator('.bubble').first().textContent().catch(() => '');
    ok('bot bubble has text content', bubbleText.length > 0, true);
  });

  // ─── 6. Sidebar conversation list ────────────────────────────────────────
  await section('6. Sidebar', async () => {
    await page.waitForTimeout(500);
    const convItems = await page.$$('.conv-item');
    ok('conversations appear in sidebar (≥1)', convItems.length >= 1, true);

    // New chat resets textarea
    await page.click('#newChatBtn');
    await page.waitForTimeout(300);
    const val = await page.locator('textarea').inputValue();
    ok('new chat clears textarea', val, '');

    // Clicking a conv item loads it — pick the first item that isn't currently active
    // (the active one is the blank new-chat just created; we want the previous conv
    // from section 5 which has bot messages)
    const freshItems = await page.$$('.conv-item:not(.active)');
    const itemToClick = freshItems.length >= 1 ? freshItems[0] : (await page.$$('.conv-item'))[0];
    if (itemToClick) {
      await itemToClick.click();
      await page.waitForSelector('.msg-wrap', { timeout: 5000 }).catch(() => null);
      const msgs = await page.$$('.msg-wrap');
      ok('clicking a conversation loads messages', msgs.length >= 1, true);
    } else {
      skip('conv item click', 'no items in sidebar');
    }
  });

  // ─── 7. Textarea auto-grow ───────────────────────────────────────────────
  await section('7. Textarea auto-grows', async () => {
    await page.click('#newChatBtn');
    await page.waitForTimeout(300);
    const h1 = await page.locator('textarea').evaluate(el => el.clientHeight);
    await page.fill('textarea', 'line1\nline2\nline3\nline4\nline5\nline6');
    await page.waitForTimeout(200);
    const h2 = await page.locator('textarea').evaluate(el => el.scrollHeight);
    ok('textarea scrollHeight grows with multiline input', h2 > h1, true);
    await page.fill('textarea', '');
  });

  // ─── 8. Admin page structure ─────────────────────────────────────────────
  await section('8. Admin page structure', async () => {
    await page.goto(`${BASE}/admin`);
    await page.waitForLoadState('domcontentloaded');

    contains('admin title', await page.title(), 'Settings');

    const tabs = await page.$$('.tab');
    ok('3 tabs present', tabs.length >= 3, true);

    const tabTexts = await Promise.all(tabs.map(t => t.textContent()));
    contains('Users tab', tabTexts.join('|'), 'Users');
    contains('Providers tab', tabTexts.join('|'), 'LLM Providers');
    contains('Usage tab', tabTexts.join('|'), 'Usage');

    // Topbar
    contains('topbar brand', await page.locator('.topbar .brand').textContent().catch(() => ''), 'NullShift');
    notNull('Chat nav link', await page.$('a.btn-nav[href="/"]'));
    notNull('Logout nav link', await page.$('a.btn-nav[href="/logout"]'));
  });

  // ─── 9. Admin → Users tab ────────────────────────────────────────────────
  await section('9. Admin / Users tab', async () => {
    await page.goto(`${BASE}/admin`);
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(900); // let loadUsers() fire

    notNull('users data table', await page.$('table.data-table'));
    const rows = await page.$$('table.data-table tbody tr');
    ok('at least 1 user row', rows.length >= 1, true);

    const adminCell = await page.locator('td:has-text("admin")').first().textContent().catch(() => '');
    contains('admin user in table', adminCell, 'admin');

    // Pill badges
    const pills = await page.$$('.pill.green, .pill.gray');
    ok('status pills rendered (≥1)', pills.length >= 1, true);

    // Create user form
    notNull('create form', await page.$('#createForm'));

    const uname = `pw_e2e_${Date.now().toString(36)}`;
    await page.fill('#createForm input[name="username"]', uname);
    await page.fill('#createForm input[name="password"]', 'TestPass@9876543');
    await page.selectOption('#createForm select[name="role"]', 'l1');
    await page.click('#createForm button[type="submit"]');
    await page.waitForTimeout(1000);

    const rowsAfter = await page.$$('table.data-table tbody tr');
    ok('user count increased after create', rowsAfter.length > rows.length, true);
  });

  // ─── 10. Admin → LLM Providers tab ──────────────────────────────────────
  await section('10. Admin / Providers tab', async () => {
    await page.goto(`${BASE}/admin`);
    await page.waitForLoadState('domcontentloaded');
    await page.click('.tab:has-text("LLM Providers")');
    await page.waitForTimeout(1500);

    // Active-provider dropdown (populated dynamically)
    notNull('active-provider select', await page.$('#activeProvider'));
    const opts = await page.$$('#activeProvider option');
    ok('≥10 options in dropdown (auto + providers)', opts.length >= 10, true);
    const optVals = await Promise.all(opts.map(o => o.getAttribute('value')));
    for (const name of ['auto', 'anthropic', 'openai', 'gemini', 'groq', 'xai', 'perplexity', 'openrouter', 'deepseek', 'ollama']) {
      ok(`dropdown has option: ${name}`, optVals.includes(name), true);
    }

    // Chain editor section
    notNull('chain editor div', await page.$('#chainEditor'));
    const chainRows = await page.$$('.chain-row');
    ok('chain rows rendered (≥1)', chainRows.length >= 1, true);

    // Each row has control buttons
    const upBtns   = await page.$$('[data-chain-up]');
    const downBtns = await page.$$('[data-chain-down]');
    const rmBtns   = await page.$$('[data-chain-rm]');
    ok('up-arrow buttons present', upBtns.length >= 1, true);
    ok('down-arrow buttons present', downBtns.length >= 1, true);
    ok('remove buttons present', rmBtns.length >= 1, true);

    // Add/save controls
    notNull('add-provider select', await page.$('#addProviderSel'));
    notNull('add-to-chain button', await page.$('#addToChainBtn'));
    notNull('save-chain button', await page.$('#saveChainBtn'));

    // Provider cards
    const cards = await page.$$('.provider-card');
    ok('≥9 provider cards', cards.length >= 9, true);

    const listText = (await page.locator('#providerList').textContent()).toLowerCase();
    for (const name of ['anthropic', 'openai', 'gemini', 'groq', 'grok', 'perplexity', 'openrouter', 'deepseek', 'ollama']) {
      contains(`${name} card present`, listText, name);
    }

    // Ollama card has Base URL field specifically
    const ollamaBaseInput = await page.locator('#providerList input[data-field="ollama_base_url"]').first();
    ok('Ollama base URL input found', await ollamaBaseInput.count() > 0, true);
  });

  // ─── 11. Chain reorder via UI ────────────────────────────────────────────
  await section('11. Chain editor reorder', async () => {
    await page.goto(`${BASE}/admin`);
    await page.waitForLoadState('domcontentloaded');
    await page.click('.tab:has-text("LLM Providers")');
    await page.waitForTimeout(1500);

    const chainRows = await page.$$('.chain-row');
    if (chainRows.length < 2) { skip('reorder', 'fewer than 2 rows'); return; }

    const firstName = await chainRows[0].getAttribute('data-name');
    const secondName = await chainRows[1].getAttribute('data-name');

    // Click the ▼ button on the first row using proper selector
    await page.click(`.chain-row:nth-child(1) [data-chain-down]`);
    await page.waitForTimeout(300);

    const rowsAfter = await page.$$('.chain-row');
    ok('same row count after reorder', rowsAfter.length, chainRows.length);

    const newFirst = await rowsAfter[0].getAttribute('data-name');
    const newSecond = await rowsAfter[1].getAttribute('data-name');
    ok('second item moved to first slot', newFirst, secondName);
    ok('first item moved to second slot', newSecond, firstName);

    // Save chain and wait for confirmation
    await page.click('#saveChainBtn');
    // Wait until status text contains 'saved' (up to 8s; loadProviders re-fetches after save)
    await page.waitForFunction(
      () => document.getElementById('chainStatus')?.textContent?.toLowerCase().includes('saved'),
      { timeout: 8000 }
    ).catch(() => null);
    const statusText = await page.locator('#chainStatus').textContent().catch(() => '');
    contains('chain saved confirmation', statusText.toLowerCase(), 'saved');
  });

  // ─── 12. Chain order persists via API ────────────────────────────────────
  await section('12. Settings API round-trip', async () => {
    const csrf = await getCsrf(page);
    const chainPayload = ['groq', 'anthropic', 'openai', 'claude_agent_sdk'];

    const putRes = await page.request.put(`${BASE}/api/admin/settings`, {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      data: { provider_chain: JSON.stringify(chainPayload) },
    });
    ok('PUT /api/admin/settings → 200', putRes.status(), 200);
    const pj = await putRes.json();
    ok('response has ok:true', pj.ok, true);

    const getRes = await page.request.get(`${BASE}/api/admin/settings`);
    ok('GET /api/admin/settings → 200', getRes.status(), 200);
    const gj = await getRes.json();
    notNull('settings has allowed_keys', gj.allowed_keys);
    ok('provider_chain in allowed_keys', gj.allowed_keys.includes('provider_chain'), true);
    ok('gemini_api_key in allowed_keys', gj.allowed_keys.includes('gemini_api_key'), true);
    ok('ollama_base_url in allowed_keys', gj.allowed_keys.includes('ollama_base_url'), true);

    const prRes = await page.request.get(`${BASE}/api/admin/providers`);
    ok('GET /api/admin/providers → 200', prRes.status(), 200);
    const prj = await prRes.json();
    ok('user_chain returned', Array.isArray(prj.user_chain), true);
    ok('user_chain[0] = groq', (prj.user_chain || [])[0], 'groq');
    ok('default_chain returned', Array.isArray(prj.default_chain), true);
    ok('default_chain has 13 entries', (prj.default_chain || []).length, 13);
    ok('providers catalog has 13 entries', (prj.providers || []).length, 13);
  });

  // ─── 13. Admin → Usage tab ───────────────────────────────────────────────
  await section('13. Admin / Usage tab', async () => {
    await page.goto(`${BASE}/admin`);
    await page.waitForLoadState('domcontentloaded');
    await page.click('.tab:has-text("Usage")');
    await page.waitForTimeout(1000);

    notNull('usage body', await page.$('#usageBody'));
    const usageText = (await page.locator('#usageBody').textContent()).toLowerCase();
    contains('provider chain card visible', usageText, 'chain');
    contains('active provider shown', usageText, 'active');

    notNull('refresh button', await page.$('#refreshUsageBtn'));
    await page.click('#refreshUsageBtn');
    await page.waitForTimeout(800);
    const afterRefresh = await page.locator('#usageBody').textContent();
    ok('usage body populated after refresh', afterRefresh.length > 10, true);
  });

  // ─── 14. Admin users API (raw) ───────────────────────────────────────────
  await section('14. Admin users API', async () => {
    const r = await page.request.get(`${BASE}/admin/users`);
    ok('GET /admin/users → 200', r.status(), 200);
    const j = await r.json();
    ok('users array present', Array.isArray(j.users), true);
    ok('at least 2 users (admin + created)', j.users.length >= 2, true);
    const adminUser = j.users.find(u => u.username === 'admin');
    ok('admin user present', !!adminUser, true);
    ok('admin.role = admin', adminUser?.role, 'admin');
    ok('admin.is_active is truthy', !!adminUser?.is_active, true);
  });

  // ─── 15. Logout + auth guard ─────────────────────────────────────────────
  await section('15. Logout + auth guard', async () => {
    await page.goto(`${BASE}/logout`);
    await page.waitForLoadState('domcontentloaded');
    ok('logout redirects to /login', page.url().includes('/login'), true);

    // After logout, / should redirect to /login
    await page.goto(`${BASE}/`);
    await page.waitForLoadState('domcontentloaded');
    ok('unauthenticated / → /login', page.url().includes('/login'), true);

    // /admin returns 401 JSON (API-style guard, not HTML redirect)
    const adminRes = await page.request.get(`${BASE}/admin`);
    ok('unauthenticated /admin → 401', adminRes.status(), 401);
  });

  // ─── 16. Debug + diagnostic endpoints ────────────────────────────────────
  await section('16. Diagnostic endpoints', async () => {
    // These are unauthenticated
    const llmDbg = await page.request.get(`${BASE}/debug/llm`);
    ok('GET /debug/llm → 200', llmDbg.status(), 200);
    const lj = await llmDbg.json();
    ok('/debug/llm has any_configured flag', 'any_configured' in lj, true);
    ok('at least 1 provider configured', lj.any_configured, true);
    contains('claude_agent_sdk listed', (lj.configured_providers || []).join(','), 'claude_agent_sdk');

    const siemDbg = await page.request.get(`${BASE}/debug/siem`);
    ok('GET /debug/siem → 200', siemDbg.status(), 200);
  });

  // ─── summary ─────────────────────────────────────────────────────────────
  await browser.close();

  const total = passed + failed + skipped;
  console.log('\n' + '═'.repeat(58));
  console.log(`  RESULTS   passed: ${passed}   failed: ${failed}   skipped: ${skipped}   total: ${total}`);
  console.log('═'.repeat(58));
  if (failed > 0) {
    console.log('\nFailed checks:');
    results.filter(r => r.ok === false).forEach(r => console.log(`  ✗ ${r.name}`));
  }
  process.exit(failed > 0 ? 1 : 0);
})();
