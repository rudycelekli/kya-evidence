import { createServer } from 'node:http';
import { openPassportRegistry } from 'kya-evidence/passport/registry';
import { parseJson } from 'kya-evidence';

const [database, address = 'http://127.0.0.1:7337'] = process.argv.slice(2);
const origin = new URL(address);
if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || origin.href !== origin.origin + '/') {
  throw new Error('Expected a loopback HTTP origin');
}
const registry = openPassportRegistry(database, origin.origin);
const limit = 16_384;
const digestPattern = '[a-f0-9]{64}';
const pathMatch = new RegExp('^/(passports|v1/passports|v1/fingerprints)/(' + digestPattern + ')$');

function json(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  response.end(JSON.stringify(body) + '\n');
}

function links(passport) {
  return { ...passport, url: origin.origin + '/passports/' + passport.passportId };
}

function escape(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

function passportPage(passport) {
  const key = passport.current;
  return `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>KYA Passport</title><style>
body{background:#f2f5f7;color:#14232c;font:1rem/1.55 Inter,system-ui,sans-serif;margin:0}
main{max-width:48rem;margin:8vh auto;padding:1.5rem}
h1{font-size:clamp(2rem,6vw,3.5rem);margin:0}
dl{padding:1.5rem;background:white;border-top:3px solid #176955}
dt{font-weight:650;margin-top:.8rem}dd{margin:0;overflow-wrap:anywhere}
a{color:#075743}
</style><main><p>KYA Passport</p><h1>${escape(passport.agentId)}</h1>
<dl><dt>Status</dt><dd>${passport.status}</dd>
<dt>Registered principal</dt><dd>${escape(passport.principalId)}</dd>
<dt>Passport ID</dt><dd><code>${passport.passportId}</code></dd>
${key ? `<dt>Active key fingerprint</dt><dd><code>${key.fingerprint}</code></dd>
<dt>Manifest fingerprint</dt><dd><code>${key.manifestDigest}</code></dd>` : ''}
<dt>Signed revisions</dt><dd>${passport.history.length}</dd></dl>
<h2>Key history</h2><ul>
${passport.fingerprints.map(fingerprint => `<li><code>${fingerprint}</code> · ${key?.fingerprint === fingerprint ? 'Active' : 'Inactive'}</li>`).join('')}
</ul><p><a href="/v1/passports/${passport.passportId}">View signed history</a></p>
<p>Registration verifies control of the signing keys and records a declared agent identity.</p>
</main></html>`;
}

const server = createServer({ requestTimeout: 10_000, headersTimeout: 5_000 }, async (request, response) => {
  try {
    if (request.method === 'POST' && request.url === '/v1/events') {
      const chunks = [];
      let length = 0;
      for await (const chunk of request.iterator({ destroyOnReturn: false })) {
        length += chunk.length;
        if (length > limit) {
          response.setHeader('connection', 'close');
          return json(response, 413, { error: 'Event too large' });
        }
        chunks.push(chunk);
      }
      let event;
      try {
        event = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      } catch {
        return json(response, 400, { error: 'Invalid event JSON' });
      }
      try {
        return json(response, 200, links(registry.append(event)));
      } catch (error) {
        if (error.code?.startsWith('ERR_SQLITE')) throw error;
        return json(response, 422, { error: 'Passport event refused' });
      }
    }
    const match = pathMatch.exec(request.url);
    if (request.method !== 'GET' || !match) return json(response, 404, { error: 'Not found' });
    const [, type, id] = match;
    if (type === 'v1/fingerprints') {
      return json(response, 200, { passports: registry.lookup(id).map(key => origin.origin + '/passports/' + key) });
    }
    const passport = registry.read(id);
    if (!passport) return json(response, 404, { error: 'Passport not found' });
    if (type === 'v1/passports') return json(response, 200, links(passport));
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    });
    response.end(passportPage(passport));
  } catch {
    json(response, 500, { error: 'Registry unavailable' });
  }
});

server.listen(Number(origin.port || 80), origin.hostname, () => console.log(origin.origin));
server.on('close', () => registry.close());
