'use strict';
const el = id => document.getElementById(id);
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const text = (id, value) => { el(id).textContent = value; };
let busy = false;
let record = null;
let serverMillis = 0;
let receivedAt = 0;
let confirming = null;
let uncertain = true;
let refreshSequence = 0;
let revisionNotice = false;
let actionError = null;
const binding = value => ({revision: value.request.revision, content_hash: value.content_hash});
const matches = (value, expected) => value.request.revision === expected.revision && value.content_hash === expected.content_hash;
const stateKey = value => JSON.stringify([value.request.revision, value.content_hash, value.approval, value.execution]);
const requestId = location.pathname.startsWith('/r/') ? location.pathname.slice(3) : null;

async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : {'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'same-origin'});
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || 'request_refused');
    error.refusal = true;
    throw error;
  }
  return result;
}
function credentialsOptions(options) {
  options.challenge = decode(options.challenge);
  if (options.user) options.user.id = decode(options.user.id);
  if (options.allowCredentials) options.allowCredentials = options.allowCredentials.map(c => ({...c, id: decode(c.id)}));
  return {publicKey: options};
}
function serialized(credential) {
  const response = credential.response;
  const result = {id: credential.id, type: credential.type, response: {clientDataJSON: encode(response.clientDataJSON)}};
  if (response.attestationObject) result.response.attestationObject = encode(response.attestationObject);
  else Object.assign(result.response, {authenticatorData: encode(response.authenticatorData), signature: encode(response.signature)});
  return result;
}
function render() {
  if (!record) return;
  const view = record.view;
  for (const id of ['title', 'change', 'deadline', 'conditions']) text(id, view[id]);
  // Avoid replacing an unchanged state node, so its mutation history is meaningful.
  const state = uncertain ? '연결 확인 중 · 서버의 현재 상태를 확인하지 못했습니다.' : view.state;
  if (el('state').textContent !== state) text('state', state);
  text('details', view.details_text);
  const pending = record.approval === 'pending' && record.execution === 'not_started';
  el('actions').hidden = !pending || Boolean(confirming) || uncertain;
  el('confirmation').hidden = !pending || !confirming;
  text('confirmation-text', record.confirmation);
  for (const id of ['approve', 'decline', 'confirm-approve', 'cancel-confirm']) el(id).disabled = busy || uncertain;
}
async function refresh() {
  if (!requestId) return;
  const sequence = ++refreshSequence;
  let next;
  try { next = await api('/api/requests/' + requestId); }
  catch (error) {
    if (sequence !== refreshSequence) return;
    uncertain = true; render();
    throw error;
  }
  // A GET started before an action must never overwrite its follow-up read.
  if (sequence !== refreshSequence) return;
  const changed = revisionNotice || (confirming && !matches(next, confirming));
  if (changed) confirming = null;
  record = next;
  uncertain = false;
  serverMillis = Date.parse(record.server_now);
  receivedAt = performance.now();
  if (record.approval !== 'pending') confirming = null;
  if (actionError && actionError.key !== stateKey(record)) actionError = null;
  text('error', changed ? '내용이 바뀌었습니다 · 다시 확인하세요.' : (actionError ? actionError.message : ''));
  revisionNotice = false;
  render();
}
async function decide() {
  if (busy || uncertain || !confirming) return;
  const shown = confirming;
  ++refreshSequence;
  busy = true;
  actionError = null;
  render();
  text('error', '');
  try {
    const options = await api('/api/requests/' + requestId + '/approve/options', shown);
    const credential = await navigator.credentials.get(credentialsOptions(options));
    if (confirming !== shown || uncertain || !matches(record, shown)) throw new Error('revision_changed');
    const payload = {credential: serialized(credential), revision: shown.revision};
    const path = '/api/requests/' + requestId + '/approve/verify';
    if (record.test_scenario === 'double_click') {
      const answers = await Promise.allSettled([api(path, payload), api(path, payload)]);
      if (!answers.some(answer => answer.status === 'fulfilled')) throw answers[0].reason;
    } else await api(path, payload);
    confirming = null;
  } catch (error) {
    // Read server truth before offering another action after a lost response.
    revisionNotice = error.message === 'revision_changed' || error.message === 'superseded';
    if (error.refusal && !revisionNotice) actionError = {key: stateKey(record), message: error.message};
    uncertain = true;
  } finally {
    try { await refresh(); }
    catch (_) { text('error', '연결을 확인하지 못했습니다. 현재 상태를 다시 확인 중입니다.'); }
    busy = false;
    render();
  }
}
el('approve').addEventListener('click', () => {
  if (busy || uncertain || !record || record.approval !== 'pending') return;
  confirming = Object.freeze(binding(record)); actionError = null; text('error', ''); render();
});
el('cancel-confirm').addEventListener('click', () => { if (!busy) { confirming = null; render(); } });
el('confirm-approve').addEventListener('click', decide);
el('decline').addEventListener('click', async () => {
  if (busy || uncertain) return;
  ++refreshSequence;
  busy = true;
  actionError = null;
  render();
  try { await api('/api/requests/' + requestId + '/decline', {}); }
  catch (_) { uncertain = true; }
  finally {
    try { await refresh(); }
    catch (_) { text('error', '연결을 확인하지 못했습니다. 현재 상태를 다시 확인 중입니다.'); }
    busy = false; render();
  }
});
el('register').addEventListener('click', async () => {
  if (busy) return;
  busy = true;
  el('register').disabled = true;
  try {
    const code = el('setup-code').value.trim();
    const options = await api('/api/register/options', {code});
    const credential = await navigator.credentials.create(credentialsOptions(options));
    const result = await api('/api/register/verify', {code, credential: serialized(credential)});
    text('registration-status', '시험용 패스키 1개 등록됨 · ' + new Date(result.registered_at).toLocaleTimeString('ko-KR'));
    el('setup-code').value = '';
    el('setup-code').disabled = true;
  } catch (error) { text('error', error.message || error.name); el('register').disabled = false; }
  finally { busy = false; }
});
if (location.pathname === '/register') el('registration').hidden = false;
else {
  el('request').hidden = false;
  refresh().catch(() => text('error', '연결을 확인하지 못했습니다.'));
  setInterval(() => { if (!busy) refresh().catch(() => text('error', '연결을 확인하지 못했습니다.')); }, 2000);
  setInterval(() => {
    if (!record) return;
    const now = serverMillis + performance.now() - receivedAt;
    const expires = Date.parse(record.request.expires_at);
    const minutes = Math.max(0, Math.floor((expires - now) / 60000));
    text('deadline', record.view.deadline.replace(/\(\d+분 남음\)/, '(' + minutes + '분 남음)'));
  }, 1000);
}
