// Where the live test environment keeps its local files: settings, OpenTofu state, live.env and service credentials.
// One directory per clone, shared by all of its git worktrees, so a credential issued in one worktree is seen
// (and revoked) from every other. STRONGROOM_LIVE_DIR overrides it.
import { execFileSync } from 'node:child_process';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function liveDir() {
  if (process.env.STRONGROOM_LIVE_DIR) return resolve(process.env.STRONGROOM_LIVE_DIR);
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    // git before 2.31 echoes the unknown --path-format back instead of failing: accept only an absolute path.
    if (isAbsolute(common)) return resolve(dirname(common), '.strongroom/live');
  } catch { /* not a git checkout */ }
  return resolve(repo, '.strongroom/live');
}
