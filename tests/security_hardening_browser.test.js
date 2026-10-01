// Offline hardening regressions. Fixtures are synthetic; no network or client binaries.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const { parseLink, parseText } = require('../tools/lib/links.js');
const { buildSingbox, singboxConvert } = require('../tools/lib/singbox.js');
const { buildMihomo } = require('../tools/lib/mihomo.js');
const { buildXray } = require('../tools/lib/xray.js');
const PIN = 'ab'.repeat(32); // synthetic SHA256, not a live certificate

function ui() {
  const sandbox = { window: {}, document: {}, navigator: {}, setTimeout() {} };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'tools/lib/ui.js'), 'utf8'), sandbox);
  return sandbox.window.UI;
}

function hy2(query = '') {
  return parseLink('hy2://' + 'synthetic' + '@example.invalid:443?' + query + '#synthetic-hy2');
}

function shellFixture(run) {
  assert.ok(process.env.TMPDIR, 'Hermes scratch TMPDIR must be configured');
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'pm-hardening-'));
  try {
    run(dir, script => spawnSync('bash', ['--noprofile', '--norc', '-s'], {
      cwd: dir, input: script, encoding: 'utf8', timeout: 10000,
      env: { ...process.env, BASH_ENV: '', ENV: '' },
    }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('sing-box refuses Hysteria certificate pins rather than disabling verification', () => {
  for (const pin of [PIN]) {
    for (const insecure of ['', '&insecure=1']) {
      const proxy = hy2('pinSHA256=' + pin + insecure);
      assert.throws(() => singboxConvert(proxy), /pinSHA256.*sing-box/);
      assert.throws(() => buildSingbox([proxy]), /pinSHA256.*sing-box/);
    }
  }
  const pinned = hy2('pinSHA256=' + PIN);
  const verified = hy2('sni=example.invalid&alpn=h3&obfs=salamander&obfs-password=synthetic');
  verified.name = 'synthetic-verified';
  const result = buildSingbox([pinned, verified]);
  assert.equal(result.count, 1);
  assert.equal(result.skipped.length, 1);
  assert.equal(result.skipped[0].name, pinned.name);
  assert.match(result.skipped[0].error, /pinSHA256.*sing-box/);
  const outbound = result.config.outbounds.find(p => p.type === 'hysteria2');
  assert.equal(outbound.tls.insecure, undefined);
  assert.equal(outbound.password, verified.password);
  assert.equal(outbound.tls.server_name, verified.sni);
  assert.deepEqual(outbound.tls.alpn, ['h3']);
  assert.deepEqual(outbound.obfs, { type: 'salamander', password: 'synthetic' });
  assert.equal(singboxConvert(hy2('insecure=1')).outbound.tls.insecure, true);
});

test('unrepresentable TLS certificate pins are not silently dropped by other converters', () => {
  for (const type of ['vless', 'vmess', 'trojan']) {
    for (const insecure of [false, true]) {
      const proxy = parseLink('vless://' + 'synthetic' + '@example.invalid:443?security=tls&pcs=' + PIN);
      Object.assign(proxy, { type, password: 'synthetic', cipher: 'auto', alterId: 0 });
      proxy.tls.insecure = insecure;
      assert.throws(() => singboxConvert(proxy), /pcs.*sing-box/);
      assert.throws(() => buildSingbox([proxy]), /pcs.*sing-box/);
      assert.throws(() => buildMihomo([proxy], { secret: 'synthetic' }), /pcs.*Mihomo/);
      const xray = buildXray([proxy]);
      assert.equal(xray.files['04_outbounds.json'].outbounds[0].streamSettings.tlsSettings.pinnedPeerCertSha256, PIN);
      assert.equal(xray.warnings.length, 0);
    }
  }
  // Hysteria's supported Mihomo fingerprint remains a pin, even when insecure=1 was requested.
  const pinned = hy2('pinSHA256=' + PIN + '&insecure=1');
  const mihomo = buildMihomo([pinned], { secret: 'synthetic' }).config.proxies[0];
  assert.equal(mihomo.fingerprint, PIN);
  assert.equal(mihomo['skip-cert-verify'], undefined);
  const xray = buildXray([pinned]).files['04_outbounds.json'].outbounds[0];
  assert.equal(xray.streamSettings.tlsSettings.pinnedPeerCertSha256, PIN);
  assert.equal(xray.streamSettings.tlsSettings.allowInsecure, undefined);
});

test('Mihomo controller defaults to loopback without breaking XKeen traffic forwarding', () => {
  const proxy = hy2('sni=example.invalid&alpn=h3');
  const result = buildMihomo([proxy], { secret: 'synthetic', services: ['youtube'], finalProxy: true });
  assert.equal(result.config['external-controller'], '127.0.0.1:9090');
  assert.equal(result.config.secret, 'synthetic');
  assert.equal(result.config['allow-lan'], true); // transparent router traffic, not controller exposure
  assert.equal(result.config['redir-port'], 5000);
  assert.equal(result.config['tproxy-port'], 5001);
  assert.equal(result.config['routing-mark'], 255);
  assert.equal(result.config.proxies[0].password, proxy.password);
  assert.equal(result.config.proxies[0]['skip-cert-verify'], undefined);
  assert.ok(result.config['rule-providers']['youtube@domain']);
  assert.equal(result.config.rules.at(-1), 'MATCH,Прокси');
  assert.doesNotMatch(result.yaml, /http:\/\/IP-роутера:9090/);
  assert.match(result.yaml, /ssh -L 9090:127\.0\.0\.1:9090/);
  assert.match(buildMihomo([proxy]).config.secret, /^[a-f0-9]{24}$/);
});

test('Mihomo never auto-downloads dashboard code and accepts only explicit local preinstallation', () => {
  const proxy = hy2();
  const defaults = buildMihomo([proxy], { secret: 'synthetic' });
  assert.equal(defaults.config['external-ui'], '');
  // An absent field inherits Mihomo 1.19's mutable metacubexd URL. Empty is deliberate.
  assert.equal(defaults.config['external-ui-url'], '');
  assert.match(defaults.yaml, /external-ui-url: ""/);
  assert.doesNotMatch(defaults.yaml, /releases\/latest|metacubexd|dist\.zip/);
  for (const externalUI of ['zashboard', './reviewed-ui', '/opt/share/reviewed-ui']) {
    const manual = buildMihomo([proxy], { secret: 'synthetic', externalUI,
      externalUIURL: 'https://example.invalid/synthetic-untrusted.zip' });
    assert.equal(manual.config['external-ui'], externalUI);
    assert.equal(manual.config['external-ui-url'], '');
    assert.doesNotMatch(manual.yaml, /synthetic-untrusted/);
    assert.match(manual.yaml, /предустановлен/);
  }
  for (const externalUI of ['https://example.invalid/ui', '//example.invalid/ui', '../ui', 'ui/../ui', 'ui\nunsafe', true]) {
    assert.throws(() => buildMihomo([proxy], { secret: 'synthetic', externalUI }), /externalUI.*локальн/);
  }
});

test('router command protects both existing and new credential files before publishing', () => {
  const { routerCommand } = ui();
  const xray = buildXray([hy2()], { finalProxy: true });
  const files = Object.fromEntries(Object.entries(xray.files).map(([name, value]) => [name, JSON.stringify(value)]));
  files['config.yaml'] = buildMihomo([hy2()], { secret: 'synthetic', services: [] }).yaml;
  files['literal.txt'] = 'PMEOF\n$(touch NEVER_EXECUTED)\n`touch NEVER_EXECUTED`\n$HOME\nPMEOFX\n';
  const command = routerCommand(files, "router files' synthetic", 'xkeen -mihomo');
  assert.match(command, /umask\s+0?077/);
  assert.match(command, /mktemp/);
  assert.match(command, /chmod\s+0?600/);
  assert.match(command, /<<'PMEOFXX'/);
  shellFixture((dir, shell) => {
    const target = path.join(dir, "router files' synthetic");
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, 'config.yaml'), 'synthetic-old', { mode: 0o644 });
    const result = shell(`
umask 022
chmod() {
  [ "$1" = 600 ] && [ "$(umask)" = 0077 ] || return 91
  printf 'secured\n' >> permission-events
  command chmod "$@"
}
mv() {
  [ -s permission-events ] || return 92
  command mv "$@"
}
xkeen() {
  [ "$1" = -restart ] && [ "$(umask)" = 0077 ] || return 93
  printf 'restarted\n' >> restart-events
}
${command}
[ "$(umask)" = 0022 ] || exit 94
`);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    for (const [name, body] of Object.entries(files)) {
      assert.equal(fs.readFileSync(path.join(target, name), 'utf8'), body.replace(/\n?$/, '\n'));
    }
    assert.equal(fs.existsSync(path.join(dir, 'NEVER_EXECUTED')), false);
    assert.equal(fs.readFileSync(path.join(dir, 'permission-events'), 'utf8'), 'secured\n'.repeat(Object.keys(files).length));
    assert.equal(fs.readFileSync(path.join(dir, 'restart-events'), 'utf8'), 'restarted\n');
    assert.deepEqual(fs.readdirSync(target).sort(), Object.keys(files).sort());
    // Windows/MSYS cannot prove POSIX ACL isolation. On POSIX, additionally prove actual modes.
    if (process.platform !== 'win32') {
      for (const name of Object.keys(files)) assert.equal(fs.statSync(path.join(target, name)).mode & 0o777, 0o600);
    }
  });
});

test('router command refuses write failures without publishing credentials or restarting', () => {
  const { routerCommand } = ui();
  for (const step of ['mktemp', 'chmod', 'cat', 'mv']) {
    shellFixture((dir, shell) => {
      fs.mkdirSync(path.join(dir, 'router'));
      fs.writeFileSync(path.join(dir, 'router/config.yaml'), 'synthetic-old');
      const command = routerCommand({ 'config.yaml': 'synthetic-new' }, 'router', 'xkeen -mihomo');
      const result = shell(`
xkeen() { printf 'restarted\n' >> restart-events; }
${step}() { return 73; }
${command}
`);
      assert.equal(result.error, undefined);
      assert.equal(result.status, 73, step + ': ' + result.stderr);
      assert.equal(fs.readFileSync(path.join(dir, 'router/config.yaml'), 'utf8'), 'synthetic-old');
      assert.equal(fs.existsSync(path.join(dir, 'restart-events')), false);
      assert.deepEqual(fs.readdirSync(path.join(dir, 'router')), ['config.yaml']);
    });
  }
});

test('browser-global builders preserve verified protocol and routing configs without network access', () => {
  const sandbox = { window: { crypto: require('node:crypto').webcrypto }, URL, URLSearchParams, TextDecoder, atob };
  for (const name of ['links', 'singbox', 'mihomo', 'xray']) {
    vm.runInNewContext(fs.readFileSync(path.join(root, 'tools/lib/' + name + '.js'), 'utf8'), sandbox);
  }
  const { PM } = sandbox.window;
  const links = [
    'vless://' + 'synthetic' + '@example.invalid:443?security=reality&pbk=synthetic&sid=01&flow=xtls-rprx-vision#synthetic-reality',
    'vless://' + 'synthetic' + '@example.invalid:443?security=tls&type=ws&path=%2Fsynthetic&host=example.invalid&alpn=h2#synthetic-ws',
    'trojan://' + 'synthetic' + '@example.invalid:443?type=grpc&serviceName=synthetic#synthetic-grpc',
    'ss://' + Buffer.from('aes-128-gcm:' + 'synthetic').toString('base64url') + '@example.invalid:443#synthetic-ss',
    'hy2://' + 'synthetic' + '@example.invalid:443?alpn=h3#synthetic-hy2',
    'wireguard://' + 'synthetic' + '@example.invalid:51820?publickey=synthetic&address=192.0.2.2%2F32#synthetic-wg',
  ];
  const parsed = PM.parseText(links.join('\n'));
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.proxies.length, links.length);
  const sb = PM.buildSingbox(parsed.proxies, { inbound: { port: 1082 }, final: 'Авто' });
  assert.equal(sb.count, links.length);
  assert.equal(sb.skipped.length, 0);
  assert.equal(sb.config.inbounds[0].listen, '127.0.0.1');
  assert.equal(sb.config.route.final, 'Авто');
  assert.equal(sb.config.endpoints[0].type, 'wireguard');
  assert.equal(sb.config.outbounds.find(p => p.type === 'vless').tls.reality.public_key, 'synthetic');
  assert.equal(sb.config.outbounds.find(p => p.type === 'vless' && p.transport).transport.path, '/synthetic');
  const mh = PM.buildMihomo(parsed.proxies, { services: ['youtube'], perService: true, blockQuic: true });
  assert.equal(mh.count, links.length);
  assert.equal(mh.config['external-controller'], '127.0.0.1:9090');
  assert.equal(mh.config['external-ui-url'], '');
  assert.ok(mh.config['proxy-groups'].some(p => p.name === 'YouTube'));
  assert.ok(mh.config.rules.includes('RULE-SET,youtube@domain,YouTube'));
  const xr = PM.buildXray(parsed.proxies, { services: ['youtube'], finalProxy: true });
  assert.equal(xr.count, links.length);
  assert.equal(xr.skipped.length, 0);
  assert.equal(xr.files['05_routing.json'].routing.rules.at(-1).balancerTag, 'proxy-balancer');
  assert.equal(xr.files['04_outbounds.json'].outbounds[1].streamSettings.wsSettings.path, '/synthetic');
  assert.throws(() => PM.buildSingbox(PM.parseText('hy2://' + 'synthetic' + '@example.invalid:443?pinSHA256=' + PIN).proxies), /pinSHA256.*sing-box/);
});
