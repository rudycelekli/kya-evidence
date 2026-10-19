// Explains WHY two renderings of the assessment vectors file differ, in a few hundred characters, so a drift
// failure on another machine is diagnosable from the log alone. Returns null when the texts are identical.
const CONTEXT = 200;
const show = (v, max = 120) => { const t = JSON.stringify(v); const s = t === undefined ? 'undefined' : t; return s.length > max ? s.slice(0, max - 3) + '...' : s; };
const isObj = v => v !== null && typeof v === 'object';

function locate(a, b, path = '$') {
  if (!isObj(a) || !isObj(b) || Array.isArray(a) !== Array.isArray(b)) return Object.is(a, b) ? null : { path, a, b };
  if (Array.isArray(a)) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) { const d = locate(a[i], b[i], `${path}[${i}]`); if (d) return d; }
    return a.length === b.length ? null : { path: `${path}.length`, a: a.length, b: b.length };
  }
  const keys = [...Object.keys(a), ...Object.keys(b).filter(k => !Object.hasOwn(a, k))];
  for (const k of keys) {
    if (!Object.hasOwn(a, k)) return { path: `${path}.${k}`, a: undefined, b: b[k] };
    if (!Object.hasOwn(b, k)) return { path: `${path}.${k}`, a: a[k], b: undefined };
    const d = locate(a[k], b[k], `${path}.${k}`); if (d) return d;
  }
  return null;
}

export function describeDrift(committed, generated) {
  if (committed === generated) return null;
  let at = 0; const n = Math.min(committed.length, generated.length);
  while (at < n && committed.charCodeAt(at) === generated.charCodeAt(at)) at++;
  const line = committed.slice(0, at).split('\n').length;
  const ctx = t => JSON.stringify(t.slice(Math.max(0, at - CONTEXT / 2), at + CONTEXT / 2));
  let where = 'JSON path unavailable (a file is not valid JSON)', id = 'none (outside the vectors array)', values = '';
  try {
    const a = JSON.parse(committed), b = JSON.parse(generated), d = locate(a, b);
    if (d) {
      where = d.path; values = `; committed value ${show(d.a)}; generated value ${show(d.b)}`;
      const m = /^\$\.vectors\[(\d+)\]/.exec(d.path);
      if (m) id = String(b.vectors?.[Number(m[1])]?.id ?? a.vectors?.[Number(m[1])]?.id ?? 'unknown');
    } else where = 'no structural difference (whitespace or key order only)';
  } catch { /* keep the defaults */ }
  return `Assessment vector drift: first differing byte offset ${at} (line ${line}); first differing vector id ${id}; JSON path ${where}${values}; committed context ${ctx(committed)}; generated context ${ctx(generated)}; lengths ${committed.length} and ${generated.length}`;
}
