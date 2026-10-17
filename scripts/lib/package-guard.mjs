// Shared package content guard, used by scripts/pack.mjs (refuses to build) and scripts/release-readiness.mjs
// (reports). It is a blocklist, so it can only catch what it names; it is not a secret scanner and not a privacy
// proof. Patterns are written so this file never matches them itself.

// Path segments and file names that must never be in the package inventory.
const PRIVATE_SEGMENT = /(?:^|\/)(?:\.env(?:\.[^/]*)?|\.private|\.swarm|\.claude-flow|\.claude|\.kya|\.npmrc|node_modules)(?:\/|$)/;
const PRIVATE_FILE = /(?:\.(?:pem|key|p12|pfx)$|(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)[^/]*$)/i;
export const isForbiddenPath = name => PRIVATE_SEGMENT.test(name) || PRIVATE_FILE.test(name);

// Everything is scanned as text except known binary extensions.
const BINARY = /\.(?:png|jpe?g|gif|ico|webp|avif|pdf|zip|gz|tgz|bz2|xz|7z|woff2?|ttf|otf|eot|mp[34]|mov|wasm)$/i;
export const isTextLike = name => !BINARY.test(name);

const HOME_USER = ['/Users/', 'rudycelekli'].join('');
const PRIVATE_KEY = '-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?' + 'PRIVATE KEY-----';
// Documented placeholder names that may follow /Users/ or /home/ (fixtures, docs, CI runner home).
const PLACEHOLDER_NAMES = new Set(['a', 'you', 'user', 'username', 'name', 'me', 'example', 'alice', 'bob', 'jane', 'janedoe', 'person', 'someone', 'runner', 'USER', 'YOU', 'NAME']);
const ABS_HOME = /\/(?:Users|home)\/([A-Za-z0-9._-]+)/g;
const SECRETS = [
  new RegExp(PRIVATE_KEY),
  /sk-(?:proj-)?[A-Za-z0-9]{24,}/,
  /gh[pos]_[A-Za-z0-9]{36}/,
  /npm_[A-Za-z0-9]{36}/,
  /AKIA[0-9A-Z]{16}/
];

/** True when the text carries a private home path, a secret-shaped token or a private key header. */
export function textMarker(text) {
  if (text.includes(HOME_USER)) return true;
  for (const re of SECRETS) if (re.test(text)) return true;
  for (const m of text.matchAll(ABS_HOME)) if (!PLACEHOLDER_NAMES.has(m[1])) return true;
  return false;
}
