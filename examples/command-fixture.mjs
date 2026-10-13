// Synthetic command example: no model, network or actual tool side effects.
import { createReferenceAdapter } from '../src/conformance/index.mjs';
import { parseJson,canonical } from '../src/shared/canonical.mjs';
let input='';for await(const chunk of process.stdin){input+=chunk;if(Buffer.byteLength(input)>131072)process.exit(2);}
process.stdout.write(canonical(await createReferenceAdapter({mode:'careful'}).run(parseJson(input))));
