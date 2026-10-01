// Offline security audit checks: no browser fetch, installer, or shell execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const { parseText } = require('../tools/lib/links.js');
const { buildMihomo } = require('../tools/lib/mihomo.js');
const { buildSingbox } = require('../tools/lib/singbox.js');

function ui() {
  const storage = new Map();
  const sandbox = { window: {}, localStorage: {
    getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v),
  }, document: {}, URL, Blob, setTimeout: () => {}, navigator: {} };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'tools/lib/ui.js'), 'utf8'), sandbox);
  return { api: sandbox.window.UI, storage };
}

test('browser code has no outbound transport, analytics, or remote active asset', () => {
  const files = ['tools/xray/index.html', 'tools/mihomo/index.html', 'tools/lib/ui.js',
    'tools/lib/links.js', 'tools/lib/mihomo.js', 'tools/lib/xray.js', 'tools/lib/singbox.js', 'tools/lib/ui.css'];
  for (const file of files) {
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    assert.doesNotMatch(text, /\b(?:fetch|sendBeacon|XMLHttpRequest|WebSocket|EventSource)\s*\(|(?:script|iframe)\b[^>]*src=["']https?:|@import\b|url\(\s*["']?https?:|document\.cookie|serviceWorker|gtag\(|analytics/i, file);
  }
});

test('persisted UI preference payloads exclude connection input and credentials', () => {
  for (const engine of ['xray', 'mihomo']) {
    const text = fs.readFileSync(path.join(root, `tools/${engine}/index.html`), 'utf8');
    const payload = /store\.set\([^,]+, JSON\.stringify\(\{([^}]+)\}\)\)/.exec(text);
    assert.ok(payload);
    assert.doesNotMatch(payload[1], /subscription|links|secret|password|privateKey|proxyDomains|directDomains/);
  }
  const { api, storage } = ui();
  api.store.set('xray', '{"blockQuic":true}');
  assert.equal(storage.get('pm:xray'), '{"blockQuic":true}');
});

test('HTML chips escape imported names, endpoints, and error text', () => {
  const { api } = ui();
  const el = {};
  api.renderParsed(el, { proxies: [{ type: 'vless', name: '<img src=x onerror=alert(1)>', server: '" onmouseover="x', port: 443 }],
    errors: [{ text: '<script>unsafe</script>', line: 2, error: '<b>bad</b>' }] }, []);
  assert.doesNotMatch(el.innerHTML, /<img|<script|<b>/);
  assert.match(el.innerHTML, /&lt;img/);
  assert.match(el.innerHTML, /&quot;/);
});

test('SSH heredoc quotes its delimiter and avoids delimiter collisions', () => {
  const { api } = ui();
  const text = api.routerCommand({ 'config.yaml': 'PMEOF\n$(touch NEVER_EXECUTED)\nPMEOFX\n' }, '/opt/etc/mihomo', 'xkeen -mihomo');
  assert.match(text, /<<'PMEOFXX'/);
  assert.match(text, /\$\(touch NEVER_EXECUTED\)/);
  assert.match(text, /xkeen -restart/);
});

test('generated remote rules and subscriptions are configuration, not browser fetches', () => {
  const result = buildMihomo([], { subscription: 'https://example.invalid/sub/synthetic', secret: 'synthetic', blockAds: true });
  assert.equal(result.config['proxy-providers'].subscription.interval, 3600);
  assert.equal(result.config['rule-providers']['ads@domain'].interval, 86400);
  assert.equal(result.config['external-controller'], '127.0.0.1:9090');
  assert.equal(result.config['allow-lan'], true); // forwarding retained; admin controller is loopback
  assert.equal(result.config['external-ui-url'], '');
});

test('audit regression refuses unsupported sing-box pins without connecting', () => {
  const input = 'hy2://' + 'synthetic' + '@example.invalid:443?pinSHA256=' + 'ab'.repeat(32);
  assert.throws(() => buildSingbox(parseText(input).proxies), /pin|certificate/i);
});
