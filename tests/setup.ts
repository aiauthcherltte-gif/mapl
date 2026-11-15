import { beforeAll, afterAll } from 'vitest';
import { fetchMock } from 'cloudflare:test';
beforeAll(() => { fetchMock.activate(); fetchMock.disableNetConnect(); });
afterAll(() => { fetchMock.assertNoPendingInterceptors(); fetchMock.deactivate(); });
