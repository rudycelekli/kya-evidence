import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runVectors } from '../scripts/run-vectors.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const vectors = JSON.parse(await readFile(join(root, 'evidence/assessment-vectors.json'), 'utf8'));
const vector = vectors.vectors.find(v => v.id === 'assess.proof-key-spelling-crlf-line-endings-rejected');
assert.equal(vector.digestReproducible, false);
assert.equal(vector.expected.rejectedEvidence[0].reasonContains, '');
const result = structuredClone(vector.expected);
delete result.rejectedEvidence[0].reasonContains;
result.rejectedEvidence[0].reason = '\uFFFD';
const valid = Buffer.from(JSON.stringify(result), 'utf8');
const replacement = Buffer.from('\uFFFD', 'utf8');
const marker = valid.indexOf(replacement);
assert.ok(marker >= 0);

async function withRunner(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'kya-output-encoding-'));
  try {
    const file = join(dir, 'vectors.json'), impl = join(dir, 'impl.mjs');
    const run = async (bytes, cases = [vector]) => {
      await writeFile(file, JSON.stringify({ ...vectors, vectors: cases }));
      await writeFile(impl, `for await (const _ of process.stdin) {}\nprocess.stdout.write(Buffer.from(${JSON.stringify([...bytes])}));\n`);
      return runVectors({ impl: `"${process.execPath}" "${impl}"`, vectorsFile: file, root, timeoutMs: 10000 });
    };
    await fn(run);
  } finally { await rm(dir, { recursive: true, force: true }); }
}

test('well formed UTF-8 replacement characters remain valid implementation output', async () => {
  await withRunner(async run => {
    const r = await run(valid);
    assert.equal(r.outcomes[0].status, 'pass');
    assert.equal(r.summary.vectors.pass, 1);
  });
});

test('malformed UTF-8 cannot become a passing free-form rejection reason', async () => {
  await withRunner(async run => {
    const malformed = [[0xff], [0xc0, 0xaf], [0xe2, 0x82], [0xed, 0xa0, 0x80]];
    for (const bytes of malformed) {
      const output = Buffer.concat([valid.subarray(0, marker), Buffer.from(bytes), valid.subarray(marker + replacement.length)]);
      const r = await run(output);
      assert.equal(r.outcomes[0].status, 'fail', JSON.stringify(bytes));
      assert.equal(r.summary.vectors.pass, 0);
      assert.equal(r.report.summary.pass, 0);
      assert.match(r.outcomes[0].detail, /strict JSON value/);
    }
  });
});

test('UTF-8 decoding preserves BOM refusal and exact unsupported reply behavior', async () => {
  await withRunner(async run => {
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    assert.equal((await run(Buffer.concat([bom, valid]))).outcomes[0].status, 'fail');
    const refusal = vectors.vectors.find(v => v.operation === 'canonicalize' && v.expected.refused);
    const unsupported = Buffer.from(JSON.stringify({ schema: 'kya.impl-result/v1', operation: refusal.operation, unsupported: true }));
    assert.equal((await run(unsupported, [refusal])).outcomes[0].status, 'unsupported');
    assert.equal((await run(Buffer.concat([bom, unsupported]), [refusal])).outcomes[0].status, 'fail');
    assert.equal((await run(Buffer.concat([unsupported, Buffer.from([0xff])]), [refusal])).outcomes[0].status, 'fail');
  });
});
