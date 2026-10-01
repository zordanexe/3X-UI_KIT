// Offline SEC-2 / LOGIC-1 regressions: synthetic credentials, no router or client binaries.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const { parseLink, parseText } = require('../tools/lib/links.js');
const { buildSingbox } = require('../tools/lib/singbox.js');
const { buildMihomo } = require('../tools/lib/mihomo.js');
const { buildXray } = require('../tools/lib/xray.js');
const PIN = 'ab'.repeat(32); // A full synthetic 32-byte SHA-256 digest, not a live certificate.
const OTHER_PIN = 'cd'.repeat(32);

test('LOGIC-1 removes staging and refuses restart if a directory appears during the write', () => {
  shellFixture((dir, shell) => {
    fs.mkdirSync(path.join(dir, 'router'));
    const command = ui().routerCommand({ 'config.yaml': 'synthetic-secret' }, 'router', 'xkeen -mihomo');
    const result = shell(`
xkeen() { printf restarted > restart-events; }
cat() { command cat "$@"; mkdir router/config.yaml; }
${command}`);
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0, 'must recheck after staging: ' + result.stderr);
    assert.equal(fs.existsSync(path.join(dir, 'restart-events')), false);
    assert.deepEqual(fs.readdirSync(path.join(dir, 'router')), ['config.yaml']);
    assert.deepEqual(fs.readdirSync(path.join(dir, 'router/config.yaml')), []);
  });
});

for (const kind of ['directory', 'directory symlink']) {
  test('LOGIC-1 refuses a ' + kind + ' destination before publishing any file or restarting', () => {
    shellFixture((dir, shell) => {
      fs.mkdirSync(path.join(dir, 'router'));
      const target = path.join(dir, 'router/config.yaml');
      let destination = target;
      if (kind === 'directory symlink') {
        destination = path.join(dir, 'linked-directory');
        fs.mkdirSync(destination);
        const setup = shell('ln -s ../linked-directory router/config.yaml\n');
        assert.equal(setup.error, undefined);
        assert.equal(setup.status, 0, setup.stderr);
        assert.equal(fs.lstatSync(target).isSymbolicLink(), true, 'must exercise a real symlink, not a copied directory');
      } else {
        fs.mkdirSync(target);
      }
      fs.writeFileSync(path.join(destination, 'sentinel'), 'synthetic-old');
      const command = ui().routerCommand({ 'new-first.json': 'synthetic-new', 'config.yaml': 'synthetic-secret' },
        'router', 'xkeen -mihomo');
      const result = shell('xkeen() { printf restarted > restart-events; }\n' + command);
      assert.equal(result.error, undefined);
      assert.notEqual(result.status, 0, 'must refuse a directory destination: ' + result.stderr);
      assert.equal(fs.existsSync(path.join(dir, 'restart-events')), false);
      assert.deepEqual(fs.readdirSync(path.join(dir, 'router')).sort(), ['config.yaml']);
      assert.deepEqual(fs.readdirSync(destination), ['sentinel']);
      assert.equal(fs.readFileSync(path.join(destination, 'sentinel'), 'utf8'), 'synthetic-old');
      if (kind === 'directory symlink') assert.equal(fs.lstatSync(target).isSymbolicLink(), true);
    });
  });
}

test('SEC-2 never ignores supplied pins when TLS is disabled or replaced by REALITY', () => {
  for (const security of ['none', 'reality']) {
    for (const alias of ['pcs', 'pinSHA256']) {
      for (const value of ['', ':::', PIN]) {
        const input = 'vless://synthetic@example.invalid:443?security=' + security + '&pbk=synthetic&' +
          alias + '=' + encodeURIComponent(value) + '&insecure=1';
        assert.throws(() => parseLink(input), /pcs|pinSHA256|SHA.?256/i, input);
      }
    }
  }
});

test('SEC-2 preserves valid Xray pcs pin lists without accepting empty list members', () => {
  const pins = PIN.toUpperCase().match(/../g).join(':') + ', ' + OTHER_PIN;
  const proxy = parseLink(link('vless', 'pcs=' + encodeURIComponent(pins) + '&insecure=1'));
  assert.equal(proxy.tls.pin, PIN + ',' + OTHER_PIN);
  assert.equal(buildXray([proxy]).files['04_outbounds.json'].outbounds[0]
    .streamSettings.tlsSettings.pinnedPeerCertSha256, PIN + ',' + OTHER_PIN);
  assert.throws(() => buildSingbox([proxy]), /pcs.*sing-box/);
  assert.throws(() => buildMihomo([proxy], { secret: 'synthetic' }), /pcs.*Mihomo/);
  for (const value of [PIN + ',', ',' + PIN, PIN + ',, ' + OTHER_PIN, PIN + ',:::', PIN + ',abc']) {
    assert.throws(() => parseLink(link('vless', 'pcs=' + encodeURIComponent(value))), /pcs|SHA.?256/i);
  }
  // Hysteria/Mihomo fingerprints are single hashes, not Xray comma-separated pin lists.
  assert.throws(() => parseLink(link('hy2', 'pcs=' + encodeURIComponent(pins))), /pcs|SHA.?256/i);
  assert.throws(() => parseLink(link('vless', 'pinSHA256=' + encodeURIComponent(pins))), /pinSHA256|SHA.?256/i);
});

test('SEC-2 valid certificate hashes retain pinning across supported converters', () => {
  for (const protocol of ['vless', 'trojan', 'hy2', 'hysteria2']) {
    for (const alias of ['pcs', 'pinSHA256']) {
      const variants = [PIN, PIN.toUpperCase(), PIN.toUpperCase().match(/../g).join(':')];
      if (alias === 'pinSHA256') variants.push(PIN.toUpperCase().match(/../g).join('-'));
      for (const value of variants) {
        const query = alias + '=' + encodeURIComponent(value) + '&insecure=1';
        const proxy = parseLink(link(protocol, query));
        const isHy2 = proxy.type === 'hysteria2';
        assert.equal(isHy2 ? proxy.pinSHA256 : proxy.tls.pin, PIN);
        assert.equal(buildXray([proxy]).files['04_outbounds.json'].outbounds[0]
          .streamSettings.tlsSettings.pinnedPeerCertSha256, PIN);
        assert.throws(() => buildSingbox([proxy]), /pcs|pinSHA256/i);
        if (isHy2) {
          const outbound = buildMihomo([proxy], { secret: 'synthetic' }).config.proxies[0];
          assert.equal(outbound.fingerprint, PIN);
          assert.equal(outbound['skip-cert-verify'], undefined);
        } else {
          assert.throws(() => buildMihomo([proxy], { secret: 'synthetic' }), /pcs.*Mihomo/);
        }
      }
    }
    const aliases = 'pcs=' + PIN + '&pinSHA256=' + encodeURIComponent(PIN.toUpperCase().match(/../g).join(':'));
    const proxy = parseLink(link(protocol, aliases + '&pcs=' + PIN));
    assert.equal(proxy.type === 'hysteria2' ? proxy.pinSHA256 : proxy.tls.pin, PIN);
  }
  // Absence of a pin still preserves an explicitly requested insecure connection.
  const unpinned = parseLink(link('hy2', 'insecure=1'));
  assert.equal(unpinned.pinSHA256, '');
  assert.equal(buildSingbox([unpinned]).config.outbounds.find(p => p.type === 'hysteria2').tls.insecure, true);
  assert.equal(buildMihomo([unpinned], { secret: 'synthetic' }).config.proxies[0]['skip-cert-verify'], true);
});

test('SEC-2 rejects conflicting pin aliases and repeated query values', () => {
  for (const protocol of ['vless', 'trojan', 'hy2', 'hysteria2']) {
    for (const query of [
      'pcs=' + PIN + '&pinSHA256=' + OTHER_PIN,
      'pinSHA256=' + PIN + '&pcs=' + OTHER_PIN,
      'pcs=' + PIN + '&pcs=' + OTHER_PIN,
      'pinSHA256=' + PIN + '&pinSHA256=' + OTHER_PIN,
      'pcs=' + PIN + '&pcs=%3A%3A%3A',
      'pinSHA256=' + PIN + '&pinSHA256=',
    ]) {
      assert.throws(() => parseLink(link(protocol, query + '&insecure=1')), /pcs|pinSHA256|SHA.?256/i, query);
    }
  }
});

function link(protocol, query) {
  const tls = protocol === 'vless' ? 'security=tls&' : '';
  return protocol + '://synthetic@example.invalid:443?' + tls + query;
}

function ui() {
  const sandbox = { window: {}, document: {}, navigator: {}, setTimeout() {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../tools/lib/ui.js'), 'utf8'), sandbox);
  return sandbox.window.UI;
}

function shellFixture(run) {
  assert.ok(process.env.TMPDIR, 'Hermes scratch TMPDIR must be configured');
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'pm-review-'));
  try {
    run(dir, script => spawnSync('sh', ['-s'], {
      cwd: dir, input: script, encoding: 'utf8', timeout: 10000,
      env: { ...process.env, BASH_ENV: '', ENV: '', MSYS: 'winsymlinks:nativestrict' },
    }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

for (const protocol of ['vless', 'trojan', 'hy2', 'hysteria2']) {
  for (const alias of ['pcs', 'pinSHA256']) {
    test('SEC-2 ' + protocol + ' refuses empty/malformed supplied ' + alias + ' before insecure conversion', () => {
      const malformed = ['', ':::', '---', ' ', 'abc', 'AB:CD:EF', 'g'.repeat(64),
        'ab'.repeat(31), 'ab'.repeat(33), ':' + PIN, PIN + ':', PIN.slice(0, 2) + '::' + PIN.slice(2)];
      for (const pin of malformed) {
        const input = link(protocol, alias + '=' + encodeURIComponent(pin) + '&insecure=1');
        assert.throws(() => parseLink(input), /pcs|pinSHA256|SHA.?256/i, input);
        const parsed = parseText(input);
        assert.equal(parsed.proxies.length, 0, input);
        assert.equal(parsed.errors.length, 1, input);
        assert.match(parsed.errors[0].error, /pcs|pinSHA256|SHA.?256/i);
        // None of the real builders may receive a silently downgraded insecure proxy.
        for (const build of [buildSingbox, buildMihomo, buildXray]) {
          assert.throws(() => build(parsed.proxies, { secret: 'synthetic' }));
        }
      }
    });
  }
}
