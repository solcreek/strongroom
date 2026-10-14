import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
const cli = resolve('packages/strongroom/src/cli.ts');
export async function runCli(args, { input = '', env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { ...process.env, STRONGROOM_TOKEN: '', STRONGROOM_URL: '', STRONGROOM_TOKEN_FILE: '', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b);
    child.on('error', reject); child.on('close', code => resolve({ code, stdout, stderr })); child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}
