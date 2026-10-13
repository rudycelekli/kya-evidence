export { CORE_PROFILE,EVALUATOR_DIGEST,EVALUATOR_DESCRIPTOR,SCENARIOS,evaluateScenario } from './domain/index.mjs';
export { runConformance,createReferenceAdapter } from './application/index.mjs';
// Explicit infrastructure factories: importing the context never launches a process.
export { createCommandAdapter } from './infrastructure/command.mjs';
export { probeRuntimes } from './infrastructure/probes.mjs';
