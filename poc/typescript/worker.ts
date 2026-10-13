import { execute } from './core.ts';
import { makeHandler } from './handler.ts';
export default { fetch: makeHandler(execute) };
