// Display safety for strings that came from outside: agent names, labels, ids, file names, error text.
// JSON.stringify escapes C0 controls but leaves DEL, C1 controls (U+009B is a CSI introducer on some terminals), bidirectional
// overrides and isolates, zero-width and invisible characters, and U+2028/U+2029 untouched. Those can reorder or hide text
// in a terminal, a log viewer or a rendered report. These helpers neutralize them without changing what a JSON consumer reads back.
// Not a trust boundary: digests and signatures are always computed over the original bytes, never over sanitized text.

// DEL and C1; soft hyphen; Arabic letter mark; Hangul and other invisible fillers; Mongolian free variation selectors and
// vowel separator; zero-width, directional marks and embeddings, line and paragraph separators (U+200B-U+200F, U+2028-U+202E);
// word joiner, invisible operators, isolates and deprecated format characters (U+2060-U+206F); BOM and zero-width no-break
// space; interlinear annotation anchors; the Tags block, which carries invisible ASCII.
const UNSAFE = new RegExp('[\\u007f-\\u009f\\u00ad\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\u3164\\ufeff\\uffa0\\ufff9-\\ufffb\\u{e0000}-\\u{e007f}]', 'gu');
const C0 = /[\u0000-\u0008\u000b-\u001f]/g;
const C0_ALL = /[\u0000-\u001f]/g;
const hex = (cp, min) => cp.toString(16).padStart(min, '0');

/** Escape each unsafe code point as a JSON string escape. Valid only inside a JSON string literal, which is the only place such characters occur in JSON.stringify output. */
function jsonEscape(text) {
  return text.replace(UNSAFE, ch => {
    const cp = ch.codePointAt(0);
    if (cp <= 0xffff) return '\\u' + hex(cp, 4);
    const v = cp - 0x10000;
    return '\\u' + hex(0xd800 + (v >> 10), 4) + '\\u' + hex(0xdc00 + (v & 0x3ff), 4);
  });
}

/** JSON.stringify whose output is safe to print: the parsed value is identical, the bytes carry no invisible or reordering characters. */
export function terminalJson(value, replacer, space) {
  const text = JSON.stringify(value, replacer, space);
  return text === undefined ? text : jsonEscape(text);
}

/** Replace every unsafe character, including all C0 controls, with a space. Used for single printable lines. */
export function stripUnsafe(value, replacement = ' ') {
  return String(value ?? '').replace(C0_ALL, replacement).replace(UNSAFE, replacement);
}

/** Printable text that keeps newlines and tabs: every other control or invisible character becomes a visible U+XXXX marker. */
export function terminalText(value) {
  return String(value ?? '').replace(C0, ch => `[U+${hex(ch.codePointAt(0), 4).toUpperCase()}]`).replace(UNSAFE, ch => `[U+${hex(ch.codePointAt(0), 4).toUpperCase()}]`);
}

/** For rendered documents (Markdown, HTML): make invisible and reordering characters visible instead of dropping them. */
export const visibleControls = terminalText;

/** True when the text carries a character these helpers would neutralize. */
export function hasUnsafe(value) {
  return typeof value === 'string' && (new RegExp(C0_ALL.source).test(value) || new RegExp(UNSAFE.source, 'u').test(value));
}

/** Escape invisible and reordering characters inside already serialized JSON text (for example canonical JSON). The parsed value does not change. */
export const escapeJsonText = jsonEscape;
