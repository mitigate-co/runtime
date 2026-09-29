// Disposable native-store/actual-binary fixture. No real code or external host.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

assert.equal(process.argv.length, 3, 'Pass the built Mitigate executable.');
const cli = resolve(process.argv[2]);
const prefix = join(resolve(tmpdir()), 'mitigate-enrollment-cli-');
const directory = await mkdtemp(prefix);
const state = join(directory, 'enrollment');
let connections = 0;
let violation = false;
const sockets = new Set();
const server = createServer(socket => {
  connections++;
  sockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
  socket.once('data', data => {
    // A TLS client hello precedes any application credential. A plaintext POST
    // here would expose the code and must fail the fixture.
    if (data[0] !== 22 || data[1] !== 3) violation = true;
    socket.end('This fixture is not a TLS server.\n');
  });
});
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const platform = `https://127.0.0.1:${server.address().port}`;
const code = `mcp1:00000000-0000-4000-8000-000000000001:${'A'.repeat(43)}`;

function command(action, flags = [], input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(cli, ['enroll', action, '--platform', platform, '--state', state, '--json', ...flags], {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
    });
    const timeout = setTimeout(() => child.kill(), 30_000);
    const stdout = [], stderr = [];
    let size = 0;
    for (const [pipe, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) {
      pipe.on('data', data => { size += data.length; if (size > 16_384) child.kill(); else chunks.push(data); });
    }
    child.once('error', error => { clearTimeout(timeout); reject(error); });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
    child.once('close', status => {
      clearTimeout(timeout);
      try {
        const out = Buffer.concat(stdout).toString(), err = Buffer.concat(stderr).toString();
        assert(!out.includes(code) && !err.includes(code), 'Credential appeared in diagnostics.');
        assert(!violation, 'Client sent a credential without TLS.');
        assert(size <= 16_384 && status !== null, 'Fixture command failed to terminate within bounds.');
        const body = JSON.parse(status === 0 ? out : err);
        assert.equal(status === 0 ? err : out, '', 'Unexpected partial report.');
        resolve({ status, body });
      } catch (error) { reject(error); }
    });
  });
}

let cleanupConfirmed = false;
try {
  const start = await command('start', ['--stdin'], `${code}\n`);
  assert.equal(start.status, 2);
  assert.equal(start.body.error, 'enrollment_connection');
  assert.equal(connections, 1, 'Start must make exactly one attempt.');
  const pending = await command('status');
  assert.equal(pending.status, 0);
  assert.equal(pending.body.status, 'pending');
  assert.equal(pending.body.schema_version, 2);
  assert.equal(pending.body.sync_status, 'not_checked');
  assert.equal(connections, 1, 'Status must remain local.');
  const retry = await command('retry');
  assert.equal(retry.body.error, 'enrollment_connection');
  assert.equal(connections, 2);
  assert.deepEqual((await command('status')).body, pending.body, 'Retry rotated pending identity.');
  const duplicate = await command('start', ['--stdin'], `${code}\n`);
  assert.equal(duplicate.body.error, 'enrollment_exists');
  assert.equal(connections, 2);
  assert.equal((await command('forget', ['--confirm'])).body.status, 'forgotten');
  cleanupConfirmed = true;
  assert.equal((await command('forget', ['--confirm'])).status, 0);
  await access(state); // Immutable anchor is deliberately retained.
  assert.equal((await command('status')).body.error, 'enrollment_missing');
  assert.equal(connections, 2, 'Forgetting/status must not contact Platform.');
  console.log('Enrollment CLI verified: failed TLS, persistent retry, local status and precise native deletion.');
} finally {
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => server.close(resolve));
  if (!cleanupConfirmed) {
    try { cleanupConfirmed = (await command('forget', ['--confirm'])).status === 0; } catch {}
  }
  // Retain the exact recovery anchor if native deletion cannot be observed.
  if (cleanupConfirmed && resolve(directory).startsWith(prefix) && resolve(state) === join(resolve(directory), 'enrollment')) {
    await rm(directory, { recursive: true });
  } else {
    console.error('Native fixture cleanup was not confirmed; its temporary anchor is retained.');
    process.exitCode = 1;
  }
}
