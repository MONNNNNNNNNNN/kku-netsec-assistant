// Pick real BOTSv1 (CC0) lines for regression fixtures: test/fixtures/real/botsv1-fortigate.json
const zlib = require('node:zlib'), fs = require('node:fs'), rl = require('node:readline'), path = require('node:path');
const want = { ocsp: /url="?\/M[A-Za-z0-9%]{60,}/, longpath: /url="?\/joomla\/administrator\/components\/com_extplorer/, cerber: /app="?Cerber\.Botnet/, ips: /subtype="?ips .*severity="?critical/ };
(async () => {
  const out = {};
  for await (const l of rl.createInterface({ input: fs.createReadStream(path.join(__dirname, 'botsv1', 'botsv1.fgt_utm.json.gz')).pipe(zlib.createGunzip()) })) {
    const r = l && JSON.parse(l).result; if (!r || !r._raw) continue;
    for (const [k, re] of Object.entries(want)) if (!out[k] && re.test(r._raw)) out[k] = r._raw.replace(/^[A-Z][a-z]{2} [ \d]?\d \d\d:\d\d:\d\d \S+ /, '');
    if (Object.keys(out).length === Object.keys(want).length) break;
  }
  const f = path.join(__dirname, '../test/fixtures/real/botsv1-fortigate.json');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, `${JSON.stringify({ source: 'Splunk BOTSv1 (CC0 1.0), botsv1.fgt_utm.json.gz sha256 56b3830f15ff5e0eb693ef17091ca3326f8241efea5c1b5a8124b9f0dec74a77; FortiOS 5.x (2016), FGT60D', lines: out }, null, 2)}\n`);
  console.log(Object.keys(out));
})();
