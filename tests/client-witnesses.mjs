// Ported Node VM logic witnesses; explicit refresh uses visibilitychange to retain revised polling policy. No browser, network, or authenticator is used.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../public/app.js.txt', import.meta.url), 'utf8');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
const flush = async () => { for (let n = 0; n < 15; n++) await Promise.resolve(); };
const record = (revision = 1, approval = 'pending') => ({request: {revision, content_hash: String(revision).repeat(64), expires_at: '2026-11-14T08:00:00Z'},
  content_hash: String(revision).repeat(64), approval, execution: 'not_started', server_now: '2026-11-14T06:00:00Z',
  site_host: 'mapl-test.fixture.workers.dev', view: {title: 'revision ' + revision, change: '', deadline: '', conditions: '', state: approval, details_text: ''}, confirmation: 'revision ' + revision});
const credential = {id: 'a', type: 'public-key', response: {clientDataJSON: new Uint8Array([1]), authenticatorData: new Uint8Array([2]), signature: new Uint8Array([3])}};
async function harness(pathname = '/r/abc', initial = record()) {
  const nodes = new Map(), calls = [], intervals = [], queue = [];
  const node = id => { if (!nodes.has(id)) nodes.set(id, {style: {setProperty() {}}, getBoundingClientRect() { return {height: 120}; }, children: [], appendChild(child) { this.children.push(child); }, textContent: '', hidden: false, disabled: false, insertBefore() {}, addEventListener(kind, fn) { this[kind] = fn; }}); return nodes.get(id); };
  const context = vm.createContext({document: {getElementById: node, querySelector: node, createElement: tag => node(Symbol(tag)), hidden: false, addEventListener(kind,fn) { this[kind]=fn; }}, location: {pathname}, performance: {now: () => 0},
    Uint8Array, atob, btoa, setInterval: fn => intervals.push(fn), navigator: {credentials: {get: async () => credential}},
    fetch: async (path, options) => { calls.push({path, body: options.body && JSON.parse(options.body)}); const value = queue.shift();
      if (value instanceof Error) throw value; const answer = await value; if (!answer) throw Error('missing fixture');
      return {ok: !answer.error, json: async () => answer}; }});
  queue.push(initial);
  vm.runInContext(source, context);
  await flush();
  return {node, calls, queue, context, intervals, poll: () => context.document.visibilitychange(), async click(id) { if (!node(id).disabled) await node(id).click(); await flush(); }};
}
const tests = {
  async kst_deadline_minute_refresh_preserves_server_date_and_zone() {
    const r = record(); r.view.deadline = '11월\u00a014일\u00a017:00\u00a0KST까지 (999분 남음)';
    const h = await harness('/r/abc', r); h.intervals.at(-1)();
    assert.equal(h.node('deadline').textContent, '11월\u00a014일\u00a017:00\u00a0KST까지 (120분 남음)');
  },
  async list_renders_server_title_meta_and_state_in_one_link() {
    const rows = ['aaaaaa', 'bbbbbb'].map(id => ({request:{request_id:id.repeat(5)+'aa'}, list_title:'화면 자료 게시 gen/0006 → gen/0005', list_meta:'요청 11월\u00a017일\u00a000:00\u00a0KST · #'+id, display_state:'승인 대기'}));
    const h = await harness('/', {requests:rows, last_response:'11월\u00a017일\u00a000:01\u00a0KST'});
    assert.equal(h.node('runner-summary').textContent, '실행기 마지막 응답 11월\u00a017일\u00a000:01\u00a0KST · 켜짐·꺼짐은 이 정보만으로 알 수 없습니다');
    for (const [i, row] of h.node('request-list').children.entries()) {
      assert.equal(row.children.length, 1);
      assert.equal(row.children[0].href, '/r/'+rows[i].request.request_id);
      assert.deepEqual(row.children[0].children.map(n => n.textContent), [rows[i].list_title,rows[i].list_meta,rows[i].display_state]);
    }
    assert.equal(h.node('request-list').children.length, 2);
  },
  async client_has_no_local_clock_formatting() { assert.doesNotMatch(source, /toLocale|Intl|getHours|getMinutes/); },
  async full_fixed_host_has_comparison_prefix() {
    const h = await harness();
    assert.equal(h.node('site-host').textContent, '주소창과 비교: mapl-test.fixture.workers.dev');
  },
  async changed_revision_during_os_sheet_never_signs_new_revision() {
    const h = await harness(), auth = deferred(); h.context.navigator.credentials.get = () => auth.promise;
    h.queue.push({challenge: 'AQ'}, record(1, 'approved')); const deciding = h.click('approve'); await flush();
    h.queue.push(record(1, 'approved')); auth.resolve(credential); await deciding;
    assert.equal(h.calls.find(x => x.path.endsWith('/verify')).body.revision, 1);
  },
  async in_flight_refresh_cannot_switch_signed_revision() {
    const h = await harness(), poll = deferred(), auth = deferred();
    h.queue.push(poll.promise); h.poll();
    h.context.navigator.credentials.get = () => auth.promise;
    h.queue.push({challenge: 'AQ', allowCredentials: []});
    const deciding = h.click('approve'); await flush(); poll.resolve(record(2)); await flush();
    h.queue.push(record(1, 'approved'), record(2)); auth.resolve(credential); await deciding;
    const verify = h.calls.find(call => call.path.endsWith('/verify'));
    assert.ok(!verify || verify.body.revision === 1, 'must never submit unseen revision 2');
  },
  async options_include_display_binding() {
    const h = await harness(); h.queue.push({error: 'revision_changed'}, record(2)); await h.click('approve');
    const options = h.calls.find(call => call.path.endsWith('/options'));
    assert.equal(options.body.revision, 1); assert.equal(options.body.content_hash, '1'.repeat(64));
  },
  async lost_reply_and_refresh_failure_disable_controls() {
    const h = await harness();
    h.queue.push({challenge: 'AQ', allowCredentials: []}, Error('lost response'), Error('no connection'));
    await h.click('approve');
    for (const id of ['approve', 'decline']) assert.equal(h.node(id).disabled, true, id);
  },
  async successful_refresh_clears_stale_error() {
    const h = await harness(); h.queue.push(Error('no connection')); h.poll(); await flush();
    h.queue.push(record(1, 'approved')); h.poll(); await flush(); assert.equal(h.node('error').textContent, '');
  },
  async lost_reply_then_server_truth_clears_error() {
    const h = await harness();
    h.queue.push({challenge: 'AQ', allowCredentials: []}, Error('lost response'), record(1, 'approved'));
    await h.click('approve'); assert.equal(h.node('error').textContent, ''); assert.equal(h.node('actions').hidden, true);
  },
  async no_confirmation_panel_and_tap_binds_hash() {
    const h = await harness(); h.queue.push({error: 'revision_changed'}, record(2)); await h.click('approve');
    assert.equal(h.calls.find(x => x.path.endsWith('/options')).body.content_hash, '1'.repeat(64));
    assert.ok(!source.includes("el('confirm-approve')"));
  },
  async delayed_poll_failure_cannot_restore_stale_error() {
    const h = await harness(), poll = deferred(); h.queue.push(poll.promise); h.poll();
    h.queue.push({challenge: 'AQ', allowCredentials: []}, record(1, 'approved'), record(1, 'approved'));
    await h.click('approve'); poll.reject(Error('old poll failed')); await flush();
    assert.equal(h.node('error').textContent, ''); assert.equal(h.node('state').textContent, 'approved');
  },
  async changed_options_stop_before_credentials_and_show_new_revision() {
    const h = await harness(); let calls = 0; h.context.navigator.credentials.get = async () => { calls++; return credential; };
    h.queue.push({error: 'revision_changed'}, record(2)); await h.click('approve');
    assert.equal(calls, 0);     assert.equal(h.node('title').textContent, 'revision 2'); assert.match(h.node('error').textContent, /내용이 바뀌었습니다/);
  },
  async verification_refusal_remains_relevant_until_state_changes() {
    const h = await harness();
    h.queue.push({challenge: 'AQ', allowCredentials: []}, {error: 'uv_missing'}, record()); await h.click('approve');
    assert.equal(h.node('error').textContent, 'uv_missing'); assert.equal(h.node('state').textContent, 'pending');
    h.queue.push(record(1, 'approved')); h.poll(); await flush(); assert.equal(h.node('error').textContent, '');
  },
  async failed_state_read_recovers_controls_only_on_server_truth() {
    const h = await harness();
    h.queue.push({challenge: 'AQ', allowCredentials: []}, Error('lost'), Error('offline')); await h.click('approve');
    assert.equal(h.node('approve').disabled, true);
    h.queue.push(record(1, 'approved')); h.poll(); await flush();
    assert.equal(h.node('actions').hidden, true); assert.equal(h.node('error').textContent, '');
  },
};
let failed = 0;
for (const [name, run] of Object.entries(tests)) { try { await run(); console.log('PASS', name); } catch (error) { failed++; console.log('FAIL', name, error.message); } }
console.log(`${Object.keys(tests).length - failed} PASS, ${failed} FAIL (Node VM; browser E2E NOT RUN)`);
process.exitCode = failed ? 1 : 0;
