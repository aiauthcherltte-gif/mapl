// Node VM logic witnesses. No browser, network, or authenticator is used.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
const flush = async () => { for (let n = 0; n < 15; n++) await Promise.resolve(); };
const record = (revision = 1, approval = 'pending') => ({request: {revision, content_hash: String(revision).repeat(64), expires_at: '2026-11-14T08:00:00Z'},
  content_hash: String(revision).repeat(64), approval, execution: 'not_started', server_now: '2026-11-14T06:00:00Z',
  view: {title: 'revision ' + revision, change: '', deadline: '', conditions: '', state: approval, details_text: ''}, confirmation: 'revision ' + revision});
const credential = {id: 'a', type: 'public-key', response: {clientDataJSON: new Uint8Array([1]), authenticatorData: new Uint8Array([2]), signature: new Uint8Array([3])}};
async function harness() {
  const nodes = new Map(), calls = [], intervals = [], queue = [];
  const node = id => { if (!nodes.has(id)) nodes.set(id, {textContent: '', hidden: false, disabled: false, addEventListener(kind, fn) { this[kind] = fn; }}); return nodes.get(id); };
  const context = vm.createContext({document: {getElementById: node}, location: {pathname: '/r/abc'}, performance: {now: () => 0},
    Uint8Array, atob, btoa, setInterval: fn => intervals.push(fn), navigator: {credentials: {get: async () => credential}},
    fetch: async (path, options) => { calls.push({path, body: options.body && JSON.parse(options.body)}); const value = queue.shift();
      if (value instanceof Error) throw value; const answer = await value; if (!answer) throw Error('missing fixture');
      return {ok: !answer.error, json: async () => answer}; }});
  queue.push(record());
  vm.runInContext(source, context);
  await flush();
  return {node, calls, queue, context, poll: () => intervals[0](), async click(id) { if (!node(id).disabled) await node(id).click(); await flush(); }};
}
const tests = {
  async changed_revision_cancels_confirmation() {
    const h = await harness(); await h.click('approve'); h.queue.push(record(2)); h.poll(); await flush();
    assert.equal(h.node('confirmation').hidden, true); assert.match(h.node('error').textContent, /내용이 바뀌었습니다/);
  },
  async in_flight_refresh_cannot_switch_signed_revision() {
    const h = await harness(), poll = deferred(), auth = deferred();
    await h.click('approve'); h.queue.push(poll.promise); h.poll();
    h.context.navigator.credentials.get = () => auth.promise;
    h.queue.push({challenge: 'AQ', allowCredentials: []});
    const deciding = h.click('confirm-approve'); await flush(); poll.resolve(record(2)); await flush();
    h.queue.push(record(1, 'approved'), record(2)); auth.resolve(credential); await deciding;
    const verify = h.calls.find(call => call.path.endsWith('/verify'));
    assert.ok(!verify || verify.body.revision === 1, 'must never submit unseen revision 2');
  },
  async options_include_display_binding() {
    const h = await harness(); await h.click('approve'); h.queue.push({error: 'revision_changed'}, record(2)); await h.click('confirm-approve');
    const options = h.calls.find(call => call.path.endsWith('/options'));
    assert.equal(options.body.revision, 1); assert.equal(options.body.content_hash, '1'.repeat(64));
  },
  async lost_reply_and_refresh_failure_disable_controls() {
    const h = await harness(); await h.click('approve');
    h.queue.push({challenge: 'AQ', allowCredentials: []}, Error('lost response'), Error('no connection'));
    await h.click('confirm-approve');
    for (const id of ['approve', 'decline', 'confirm-approve']) assert.equal(h.node(id).disabled, true, id);
  },
  async successful_refresh_clears_stale_error() {
    const h = await harness(); h.queue.push(Error('no connection')); h.poll(); await flush();
    h.queue.push(record(1, 'approved')); h.poll(); await flush(); assert.equal(h.node('error').textContent, '');
  },
  async lost_reply_then_server_truth_clears_error() {
    const h = await harness(); await h.click('approve');
    h.queue.push({challenge: 'AQ', allowCredentials: []}, Error('lost response'), record(1, 'approved'));
    await h.click('confirm-approve'); assert.equal(h.node('error').textContent, ''); assert.equal(h.node('actions').hidden, true);
  },
  async changed_hash_cancels_confirmation_even_at_same_revision() {
    const h = await harness(); await h.click('approve'); const next = record(); next.content_hash = '2'.repeat(64);
    h.queue.push(next); h.poll(); await flush(); assert.equal(h.node('confirmation').hidden, true);
    assert.match(h.node('error').textContent, /내용이 바뀌었습니다/);
  },
  async delayed_poll_failure_cannot_restore_stale_error() {
    const h = await harness(), poll = deferred(); h.queue.push(poll.promise); h.poll();
    await h.click('approve'); h.queue.push({challenge: 'AQ', allowCredentials: []}, record(1, 'approved'), record(1, 'approved'));
    await h.click('confirm-approve'); poll.reject(Error('old poll failed')); await flush();
    assert.equal(h.node('error').textContent, ''); assert.equal(h.node('state').textContent, 'approved');
  },
  async changed_options_stop_before_credentials_and_show_new_revision() {
    const h = await harness(); let calls = 0; h.context.navigator.credentials.get = async () => { calls++; return credential; };
    await h.click('approve'); h.queue.push({error: 'revision_changed'}, record(2)); await h.click('confirm-approve');
    assert.equal(calls, 0); assert.equal(h.node('confirmation').hidden, true);
    assert.equal(h.node('title').textContent, 'revision 2'); assert.match(h.node('error').textContent, /내용이 바뀌었습니다/);
  },
  async verification_refusal_remains_relevant_until_state_changes() {
    const h = await harness(); await h.click('approve');
    h.queue.push({challenge: 'AQ', allowCredentials: []}, {error: 'uv_missing'}, record()); await h.click('confirm-approve');
    assert.equal(h.node('error').textContent, 'uv_missing'); assert.equal(h.node('state').textContent, 'pending');
    h.queue.push(record(1, 'approved')); h.poll(); await flush(); assert.equal(h.node('error').textContent, '');
  },
  async failed_state_read_recovers_controls_only_on_server_truth() {
    const h = await harness(); await h.click('approve');
    h.queue.push({challenge: 'AQ', allowCredentials: []}, Error('lost'), Error('offline')); await h.click('confirm-approve');
    assert.equal(h.node('confirm-approve').disabled, true);
    h.queue.push(record(1, 'approved')); h.poll(); await flush();
    assert.equal(h.node('confirmation').hidden, true); assert.equal(h.node('actions').hidden, true); assert.equal(h.node('error').textContent, '');
  },
};
let failed = 0;
for (const [name, run] of Object.entries(tests)) { try { await run(); console.log('PASS', name); } catch (error) { failed++; console.log('FAIL', name, error.message); } }
console.log(`${Object.keys(tests).length - failed} PASS, ${failed} FAIL (Node VM; browser E2E NOT RUN)`);
process.exitCode = failed ? 1 : 0;
