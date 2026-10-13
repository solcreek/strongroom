import { run } from './rust-env.mjs';
run('cargo', ['test', '--locked', '-p', 'strongroom-core']);
