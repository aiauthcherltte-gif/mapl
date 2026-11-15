import { verifyAssertion, verifyRegistration } from '../src/webauthn';
import { b64decode } from '../src/canonical';
export default { async fetch(r: Request) { const p = await r.json() as any; const ch = b64decode(p.challenge); const c = await verifyRegistration(p.registration, ch, p.origin, p.rp); const start = performance.now(); for (let i = 0; i < 50; i++)
        await verifyAssertion(p.assertion, c, ch, p.origin, p.rp); return Response.json({ verified: true, iterations: 50, ms_per_verification: (performance.now() - start) / 50, nodejs_compat: false, metric: 'local elapsed time; not an operational metric' }); } };
