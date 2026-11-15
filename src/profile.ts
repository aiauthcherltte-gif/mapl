import { type Env } from './platform';
export function validProfile(env: Env): boolean {
    if (env.MODE !== 'test') return false;
    if (typeof env.RUNNER_TOKEN_SHA256 === 'string' && env.RUNNER_TOKEN_SHA256 === env.REQUESTER_TOKEN_SHA256) return false;
    if (env.ORIGIN === 'http://localhost:8790' && env.RP_ID === 'localhost') return true;
    if (env.RUNNER_TOKEN_SHA256 === env.REQUESTER_TOKEN_SHA256) return false;
    const sub = env.SUBDOMAIN;
    return typeof sub === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(sub) &&
        env.RP_ID === 'mapl-test.' + sub + '.workers.dev' && env.ORIGIN === 'https://' + env.RP_ID;
}
