/** Frozen browser acceptance tests E2E-1..3. No browser is launched by this file.
 * Coordinator must first authorize runs and assign an Ego TaskSpace slot.
 * Supply an Ego adapter: {page.cdp, navigate, click, fill, text, evaluate,
 * screenshot, waitForText, finish, listTaskSpaces}; never use another browser.
 * Screenshots are returned to the coordinator for authorized artifact storage.
 */
const band = '시험판 · 시험용 대상만 바뀜 · 실제 승인·실행과 연결 안 됨';
const expect = (condition, message) => { if (!condition) throw new Error(message); };
export class NotRun extends Error {
  constructor(message) { super(`NOT RUN: ${message}`); this.name = 'NotRun'; }
}

/** Use only the supplied Ego page's documented raw CDP bridge. Lifecycle
 * callbacks belong to the coordinator-confirmed TaskSpace, not another browser.
 */
export function createEgoHarness(configuration) {
  const h = {...configuration, virtualReady: false};
  const origin = new URL(h.origin);
  if (origin.hostname !== 'localhost' || origin.protocol !== 'http:' || origin.port === '8771'
      || !origin.port || origin.username || origin.password || origin.pathname !== '/')
    throw new NotRun('localhost test origin required');
  if (!/^[0-9a-f]{32}$/.test(h.requestId)) throw new NotRun('test request id required');
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  h.evaluate = async fn => {
    const response = await h.page.cdp('Runtime.evaluate', {expression: `(${fn.toString()})()`,
      returnByValue: true, awaitPromise: true, userGesture: true});
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.text || 'browser expression refused');
    return response.result?.value;
  };
  const expression = async source => {
    const response = await h.page.cdp('Runtime.evaluate', {expression: source,
      returnByValue: true, awaitPromise: true, userGesture: true});
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.text || 'browser expression refused');
    return response.result?.value;
  };
  h.text = selector => expression(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? ''`);
  h.navigate = async value => {
    const url = new URL(value);
    if (url.origin !== origin.origin || !/^\/(register|r\/[0-9a-f]{32})$/.test(url.pathname))
      throw new NotRun('E2E navigation outside test routes refused');
    await h.page.cdp('Page.navigate', {url: url.href});
    for (let n = 0; n < 100; n++) {
      try {
        if (await expression(`location.href === ${JSON.stringify(url.href)} && document.readyState === 'complete'`)) return;
      } catch (_) { /* navigation may replace the execution context */ }
      await pause(100);
    }
    throw new Error('test page did not load');
  };
  h.fill = (selector, value) => expression(`(() => { const e=document.querySelector(${JSON.stringify(selector)});
    if(!e) throw new Error('test field absent'); e.value=${JSON.stringify(value)};
    e.dispatchEvent(new Event('input',{bubbles:true})); return true; })()`);
  h.click = async selector => {
    if (!h.virtualReady) throw new NotRun('virtual authenticator not probed; click refused');
    return expression(`(() => { const e=document.querySelector(${JSON.stringify(selector)});
      if(!e || e.disabled || e.hidden) throw new Error('test control unavailable'); e.click(); return true; })()`);
  };
  h.waitForText = async (selector, expected) => {
    for (let n = 0; n < 300; n++) {
      if ((await h.text(selector)).includes(expected)) return;
      await pause(100);
    }
    throw new Error(`test text absent: ${selector}: ${expected}`);
  };
  h.screenshot = async name => ({name, mimeType: 'image/png',
    data: (await h.page.cdp('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false})).data});
  return h;
}

export async function guardedVirtual(h, action) {
  if (!h || !h.runsAuthorized || !h.taskSpaceId || !h.slotConfirmed)
    throw new NotRun('coordinator run authorization and confirmed Ego TaskSpace required');
  let authenticatorId;
  let virtualReady = false;
  try {
    await h.page.cdp('WebAuthn.enable', {});
    const added = await h.page.cdp('WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
      defaultBackupEligibility: true, defaultBackupState: true}});
    authenticatorId = added?.authenticatorId;
    if (!authenticatorId) throw new Error('addVirtualAuthenticator returned no authenticatorId');
    const probe = await h.page.cdp('WebAuthn.getCredentials', {authenticatorId});
    if (!probe || !Array.isArray(probe.credentials)) throw new Error('getCredentials returned no credentials array');
    virtualReady = true;
    h.virtualReady = true;
    // This point must precede every registration click. Never fall back to a device.
    return await action(authenticatorId);
  } catch (error) {
    if (!virtualReady) throw new NotRun(error.message);
    throw error;
  } finally {
    h.virtualReady = false;
    let removal;
    try {
      if (authenticatorId) removal = await h.page.cdp('WebAuthn.removeVirtualAuthenticator', {authenticatorId});
    } finally {
      h.receipts = {taskSpaceId: h.taskSpaceId, removal,
        finish: await h.finish({keep: []}), remaining: await h.listTaskSpaces()};
      expect(!h.receipts.remaining.some(s => s.id === h.taskSpaceId), 'Ego TaskSpace left behind');
    }
  }
}

async function register(h) {
  await h.navigate(h.origin + '/register');
  expect((await h.text('#band')) === band, 'registration band missing');
  await h.fill('#setup-code', h.setupCode);
  await h.click('#register');
  await h.waitForText('#registration-status', '시험용 패스키 1개 등록됨');
}
async function open(h) {
  await h.navigate(h.origin + '/r/' + h.requestId);
  await h.waitForText('#state', '승인 대기');
  expect((await h.text('#band')) === band, 'detail band missing');
}
async function approve(h) {
  await h.click('#approve');
  await h.click('#confirm-approve');
}

export async function test_E2E_1(h) {
  return guardedVirtual(h, async () => {
    await h.page.cdp('Emulation.setDeviceMetricsOverride', {width: 390, height: 844,
      deviceScaleFactor: 1, mobile: true});
    await register(h);
    await open(h);
    const screenshots = [await h.screenshot('default')];
    expect(await h.evaluate(() => document.documentElement.scrollWidth <= 390), 'horizontal overflow');
    await h.click('details > summary');
    screenshots.push(await h.screenshot('details'));
    await approve(h);
    await h.waitForText('#state', '완료 · 시험 대상 포인터가 gen/0006을 가리킴 (모의 실행)');
    screenshots.push(await h.screenshot('final'));
    expect(await h.evaluate(() => document.documentElement.scrollWidth <= 390), 'final horizontal overflow');
    return {id: 'E2E-1', auth_source: 'virtual_authenticator', screenshots};
  });
}
export async function test_E2E_2(h) {
  return guardedVirtual(h, async authenticatorId => {
    await register(h);
    await open(h);
    await h.page.cdp('WebAuthn.setUserVerified', {authenticatorId, isUserVerified: false});
    // CDP may reject the UV-required get before an assertion is returned. The
    // server must still retain pending; the coordinator records exact API output.
    await approve(h);
    await h.waitForText('#error', 'uv_missing');
    expect((await h.text('#state')) === '승인 대기', 'UV refusal changed state');
    return {id: 'E2E-2', auth_source: 'virtual_authenticator'};
  });
}
export async function test_E2E_3(h) {
  return guardedVirtual(h, async () => {
    expect(h.scenario === 'claim_response_lost', 'wrong E2E scenario');
    await register(h);
    await open(h);
    await approve(h);
    await h.waitForText('#state', '실행 여부 확인 안 됨');
    // Install observation only after claim, per MAPL3R M5(c).
    await h.evaluate(() => {
      globalThis.maplObservedStates = [document.querySelector('#state').textContent];
      new MutationObserver(() => globalThis.maplObservedStates.push(document.querySelector('#state').textContent))
        .observe(document.querySelector('#state'), {childList: true, subtree: true, characterData: true});
    });
    await h.waitForText('#state', '실행 안 됨 · 포인터 바뀐 것 없음 (Mac 보고)');
    const observed = await h.evaluate(() => globalThis.maplObservedStates);
    expect(observed.every(value => !value.includes('대기')), 'waiting text after claim');
    return {id: 'E2E-3', auth_source: 'virtual_authenticator', observed};
  });
}
