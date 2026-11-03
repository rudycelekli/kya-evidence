// Admission for the aggregate footer emitted by Node's TAP test reporter. This
// checks completion/count integrity; it is not a general TAP assertion parser.
const FIELDS = ['tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo'];
const require = (condition, message) => { if (!condition) throw Error(message); };

export function parseMutationFooter(output) {
  require(typeof output === 'string', 'Mutation output must be TAP text');
  const lines = output.replaceAll('\r\n', '\n').split('\n');
  if (lines.at(-1) === '') lines.pop();
  const counts = {}, start = lines.length - FIELDS.length - 1;
  require(start >= 0, 'Missing mutation aggregate footer');
  for (let i = 0; i < FIELDS.length; i++) {
    const match = /^# (tests|suites|pass|fail|cancelled|skipped|todo) (0|[1-9]\d*)$/.exec(lines[start + i]);
    require(match !== null, 'Malformed mutation aggregate count');
    const [, name, value] = match;
    require(name === FIELDS[i] && !Object.hasOwn(counts, name), 'Incomplete mutation aggregate footer');
    const number = Number(value);
    require(Number.isSafeInteger(number) && number >= 0, 'Unsafe mutation aggregate count: ' + name);
    counts[name] = number;
  }
  require(!lines.slice(0, start).some(line => /^# (?:tests|suites|pass|fail|cancelled|skipped|todo) (?:0|[1-9]\d*)$/.test(line)), 'Duplicate mutation aggregate count');
  require(lines.length === start + FIELDS.length + 1 && /^# duration_ms \d+(?:\.\d+)?$/.test(lines.at(-1)), 'Mutation aggregate footer is not terminal');
  require(counts.tests > 0, 'Mutation test population is empty');
  require(counts.cancelled === 0 && counts.skipped === 0 && counts.todo === 0, 'Mutation test population is unfinished');
  require(counts.pass + counts.fail === counts.tests, 'Mutation aggregate population does not reconcile');
  return counts;
}

function completedRun(processResult) {
  require(processResult !== null && typeof processResult === 'object', 'Mutation process result required');
  require(processResult.error == null && processResult.signal == null, 'Mutation test execution failed');
  require(Number.isSafeInteger(processResult.status) && processResult.status >= 0, 'Invalid mutation exit status');
  const counts = parseMutationFooter(processResult.stdout);
  require((processResult.status === 0) === (counts.fail === 0), 'Mutation exit status disagrees with assertion aggregate');
  return counts;
}

export function admitMutationBaseline(processResult) {
  const counts = completedRun(processResult);
  require(processResult.status === 0 && counts.pass === counts.tests && counts.fail === 0, 'Mutation baseline did not run cleanly');
  return counts;
}

export function admitMutationCandidate(processResult, baseline) {
  const counts = completedRun(processResult);
  require(counts.tests === baseline.tests && counts.suites === baseline.suites, 'Mutant did not exercise identical complete aggregate population');
  return { counts, killed: processResult.status > 0 && counts.fail > 0 };
}
