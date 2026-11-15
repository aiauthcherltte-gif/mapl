// W4-only launcher: current Worker, real workerd/SQLite, no Wrangler or account login.
process.env.WRANGLER_SEND_METRICS = 'false';
process.env.DO_NOT_TRACK = '1';
const { build } = await import('esbuild');
const { Miniflare } = await import('miniflare');
const { createInterface } = await import('node:readline');
const { outputFiles: [worker] } = await build({
  entryPoints: ['src/worker.ts'], bundle: true, format: 'esm', platform: 'browser',
  loader: { '.html': 'text', '.txt': 'text' }, write: false,
});
let mf;
const stop = async () => { if (mf) { await mf.dispose(); mf = undefined; } };
const reply = value => process.stdout.write(JSON.stringify(value) + '\n');
try {
  for await (const line of createInterface({ input: process.stdin })) {
    const command = JSON.parse(line);
    if (command.action === 'start') {
      if (mf || !/^[0-9a-f]{32}$/.test(command.root_id)) throw Error('invalid start');
      mf = new Miniflare({
        host: '127.0.0.1', port: 8790, cf: false, liveReload: false,
        modules: true, script: worker.text, compatibilityDate: '2025-10-04',
        compatibilityFlags: [], durableObjectsPersist: false,
        durableObjects: { APPROVAL: { className: 'MaplApproval', useSQLite: true } },
        bindings: {
          MODE: 'test', ORIGIN: 'http://localhost:8790', RP_ID: 'localhost',
          TEST_ROOT_ID: command.root_id, SETUP_CODE: 'LOCAL-W4-SETUP-ONLY',
          RUNNER_TOKEN: 'local-w4-runner-fixture-'.repeat(3),
          REQUESTER_TOKEN: 'local-w4-requester-fixture-'.repeat(3),
        },
        outboundService: () => { throw Error('W4 forbids outbound Worker networking'); },
      });
      const ready = await mf.ready;
      if (ready.hostname !== '127.0.0.1' || ready.port !== '8790') throw Error('bind mismatch');
      reply({ ready: ready.origin, worker: 'unmodified src/worker.ts', sqlite: true,
        external_network: 'refused', telemetry: false });
    } else if (command.action === 'stop') {
      await stop(); reply({ stopped: true });
    } else throw Error('unknown control command');
  }
} finally { await stop(); }
