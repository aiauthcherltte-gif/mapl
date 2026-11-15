# mapl (mapl-test only)

A test Cloudflare Worker, SQLite Durable Object, mobile passkey UI and the reviewed W3 mock Mac runner, copied from AI-Framework commit `5c80efd45`. Only the fixed `test-screen/CURRENT.json` mock target and `screen_publication/1` are supported. Use synthetic data only. This package does not authorise deploying an operational Worker, account actions, a real kit or ledger access.

The reviewed `deploy-profile.json` now contains `SUBDOMAIN: ai-auth-cherltte` and the two public SHA-256 role digests. The fixed target is **https://mapl-test.ai-auth-cherltte.workers.dev**. Change the profile and run `node scripts/configure.mjs` for a later reviewed configuration update; commit its deterministic output `wrangler.toml` together with that profile. Tests require the committed config to equal configure output, independent of `WORKERS_CI_COMMIT_SHA`. The generated config includes the Worker entrypoint, SQLite DO binding and v1 migration, test vars, workers.dev enabled, preview URLs disabled and `send_metrics = false`. The local test config remains separate.

Keep the existing Cloudflare Workers Builds settings: **build command empty; deploy command `npx wrangler deploy`; root directory repository root**. No command setting change is needed for the normal automatic dependency installation. The [official build-image documentation](https://developers.cloudflare.com/workers/ci-cd/builds/build-image/) describes automatic dependency installation and lockfile-based package-manager detection. The [build configuration documentation](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/) says Builds uses the Wrangler version in package.json. This repo has package-lock.json and pins Wrangler 4.42.1; dependency versions and lockfile are unchanged. The exact internal npm install invocation (`npm ci` versus `npm install`) is [unconfirmed]; neither page specifies it. Actual Builds execution has not been tested.

`.npmrc` sets `yes=false` so default npx refuses an implicit missing-package install. If dependency installation is disabled or unavailable, publishing must stop; the fallback one-line **build command is `npm ci --ignore-scripts`**, and the deploy command remains **`npx wrangler deploy`**. `npm run deploy` additionally checks local Wrangler's pinned version and generated config. A Wrangler custom build hook performs the same checks when Wrangler honors it; official Builds documentation says custom-build configuration is not honored by Builds, so this hook is not a Builds guarantee. `npm run build` is the optional full validation command and does not rely on a Mac venv or Git history depth. Use Node 22+ with native workerd support.

[Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) documents `send_metrics` as controlling this project's Wrangler usage reporting. It is false in the committed configuration; this applies to Wrangler reading that project configuration, including the deploy invocation in Builds. Whether the hosted Builds environment overrides this or emits separate service telemetry is [unconfirmed]. This repository cannot disable platform-side Builds telemetry or change account build settings. No other account telemetry setting is changed by code.

GET `/version` remains read-only and returns test mode, operational=false, registration state and public root ID. Its legacy commit field can be null and is not used as commit evidence: the default deploy command cannot inject `WORKERS_CI_COMMIT_SHA` into committed vars. The official Builds configuration page confirms that SHA is a build environment variable, which does not by itself become a runtime var.

## Local verification

Use empty task-local npmrc files, a dedicated cache, and lifecycle scripts disabled:

```sh
mkdir -p evidence
: > /Users/rcp/AIFrameworkRuns/MAPLW67P/empty-user.npmrc
: > /Users/rcp/AIFrameworkRuns/MAPLW67P/empty-global.npmrc
npm ci --ignore-scripts --no-audit --no-fund --no-update-notifier --registry=https://registry.npmjs.org --userconfig=/Users/rcp/AIFrameworkRuns/MAPLW67P/empty-user.npmrc --globalconfig=/Users/rcp/AIFrameworkRuns/MAPLW67P/empty-global.npmrc --cache=/Users/rcp/AIFrameworkRuns/MAPLW67P/npm-cache
node scripts/verify-local.mjs
npm run test:tools
```

The lockfile and all dependency versions are unchanged. Python runner tests use the existing MAPLI venv with its locked cryptography dependency (no new Python installation):

```sh
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B -c 'import sys,unittest; sys.path.insert(0,"."); suite=unittest.TestSuite(unittest.defaultTestLoader.discover(path,top_level_dir=".") for path in ("planning/impl/mapl_test/tests","planning/impl/mapl_cloudflare/tests")); result=unittest.TextTestRunner(verbosity=1).run(suite); sys.exit(not result.wasSuccessful())'
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B -c 'import sys;sys.path.insert(0,".");from planning.impl.mapl_cloudflare.integration import main;main()' --evidence /Users/rcp/AIFrameworkRuns/MAPLW67P/w4-new-evidence
```

The offline mock launcher suite (including same-root reseeding) is `env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B tests/mock-mac-fixture.py`.

The W4 integration is loopback only and uses synthetic software signatures. It cannot run against a public target.

## Secrets and Mac token scope

In Cloudflare, add `SETUP_CODE` and `RECOVERY_EPOCH` as **Secret (encrypted)**, not plaintext Variables. A later `wrangler deploy` replaces dashboard plaintext variables unless `keep_vars` is enabled; encrypted secrets persist. The user enters these values privately on iPhone.

| Input | Who sets it | Location/use |
|---|---|---|
| SETUP_CODE | User on iPhone in Cloudflare | Secret; bootstrap registration only, never shared with AI/Mac |
| RECOVERY_EPOCH | User on iPhone in Cloudflare | Secret; user advances stored epoch by exactly one for recovery |
| RUNNER_TOKEN_SHA256 | Coordinator prepares, user merges reviewed change | Public digest in deploy-profile.json → Wrangler vars |
| REQUESTER_TOKEN_SHA256 | Coordinator prepares, user merges reviewed change | Public digest in deploy-profile.json → Wrangler vars |
| RUNNER_TOKEN / REQUESTER_TOKEN | Coordinator provisions private Mac files | Raw tokens only in private Mac files, never deployed; local test harness retains visibly fake raw fixtures |

No value for the user secrets is generated, stored or printed here. No real role token was generated by this task; only the coordinator-provided public hashes were read. The secret table includes the legacy raw-token names read by the local-only compatibility path; hashes are mandatory on the deployed profile.

For later provisioning, the coordinator may run `node scripts/generate-token.mjs /absolute/path/outside/Drives/SYNC/new-role-token` once per role. It uses 256 bits of CSPRNG, exclusive creation and mode 0600, and prints only length and the first eight hash characters. It refuses an existing file and sync/worktree parents. The coordinator computes the full public SHA-256 of the token text **excluding its trailing newline**, through its authorised provisioning workflow; only that digest enters the reviewed profile. Tests inject all-zero bytes for a visibly synthetic throwaway fixture and never exercise real provisioning.

Token rotation: generate a new private Mac token, review and merge its public digest change in deploy-profile.json, then replace the Mac token file after the matching deployment passes verification. Changing a hash is a code change that requires review.

| Role | Allowed | Refused |
|---|---|---|
| requester | Submit/revise/cancel test publication requests | Runner routes, browser session, approval, decline, registration, credential addition, recovery or management |
| runner | Poll approved requests, claim, report, liveness | Requester routes and every browser/management authority above |

A pending/expired/cancelled/superseded request cannot be claimed or reported as executed. Neither token can produce a passkey signature. Fake Mac reports remain possible within the runner role, as in the original CB-6 boundary.

## Post-deploy check ③ and signature-free W7

After the user merges the exact reviewed commit into `aiauthcherltte-gif/mapl`, run from the reviewed local package:

```sh
node scripts/verify-deployed.mjs <full-reviewed-40-char-sha> https://mapl-test.ai-auth-cherltte.workers.dev main
```

The script reads the public GitHub API without authentication: main must have exactly two parents, its second parent must be the reviewed full commit, and the merge tree must equal that reviewed commit's tree. If main is not a two-parent merge, it reports: `main head is not a merge commit; Require linear history or squash/rebase merge must be off`. GitHub Rulesets must permit merge commits; do not enable Require linear history, and use a merge commit rather than squash/rebase. The checks fail on private/unavailable repositories, rate limits, redirects and invalid commits. `/login`, `/register` and JS/CSS bytes and SHA-256 must equal the reviewed local Git blobs. Main is checked again after the public Worker reads to detect a changed head. Tests use local API fixtures and a local HTTP server; no real GitHub request was performed during development.

This binds the current public main merge and deployed public assets to the reviewed commit; it cannot independently attest every deployed server byte or prove which upload produced a matching screen. `/version` supplies read-only state, not commit attestation. User account configuration, branch Rulesets, stale approvals and preview-build settings remain manual W6 checks. No passkey operation is authorised before a successful check.

For W7, `npm run test:tools` writes `evidence/w7-local.json` from the local real Worker/SQLite replay. Preserve that result with the review evidence. Later use `--unsigned <path-to-w7-local.json>` after the merge argument and supply stdin JSON containing only `runner` and `requester` tokens through the coordinator's approved private-file workflow. Never supply SETUP_CODE, RECOVERY_EPOCH, cookies or signatures. Do not put token values in command arguments, shell history or environment. Omitting token fields still checks unauthenticated cases but cannot match a full local baseline.

This explicit option permits test-scoped request submissions, revision/cancellation, refused claims/reports, and registration-without-code refusal calls. It also checks cookie-less HTML/API combinations, forged cookies and spoofed identity/origin, wrong and cross-role tokens, token refusal on login/registration/key-add/approval/management paths, operational request mode and credential-add action refusal, and expired/pending/superseded/cancelled non-reuse. Runner poll may update its heartbeat. It never approves, signs, registers, logs in or reads secrets. Results must match the local rows. The default comparison normalises registration refusal because the bootstrap window can expire. After the user registers the one test passkey, rerun with `--unsigned <path-to-w7-local.json> --registration-closed`: this requires /version.registration=closed and both registration endpoints to return 409 registration_closed; an open window with a wrong code or an expired empty window fails. No signature or setup code is supplied. Test-generated request IDs are random for isolation; they are not secret tokens.

The nine signed W4 scenarios are **not replayed on the deployed Worker**. Tests requiring a valid/expired/revoked signed browser session, assertion/nonce/key mutation, valid signed approval or claim completion remain local W4/W5 evidence. Those states cannot be constructed remotely without a signature; no path to learn the user's setup code is provided. W7 does not claim those signed states passed remotely.

## Mock Mac (W3 reuse)

The launcher `scripts/mock-mac.py` imports the existing W3 MacRunner, HTTPS transport and exact MockKit. It retains independent signature checking, immutable manifests, one-shot intent records and marked OS-temp roots. It has no operational kit or ledger adapter.

Offline preparation (no public connection):

```sh
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B scripts/mock-mac.py prepare --state /Users/rcp/AIFrameworkRuns/MAPLW67P/mock-state.json
```

Review the resulting public request/root ID. The reviewed profile now binds `TEST_ROOT_ID` to `358aa38c4e0ecb6cd913970dea380e12`; reuse its already prepared state rather than running prepare again. Prepare is a one-time action: it mints a new root and requires a new reviewed profile/config commit. Keep the marked root and metadata for the mock run. After check ③ passes and the user registers their single test passkey on iPhone, the coordinator pins only the user-reviewed public `id` and `spki` in a separate public JSON file.

Immediately before the first submission, refresh an expired (or soon-to-expire) seed on that same prepared root:

```sh
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B scripts/mock-mac.py reseed --state /Users/rcp/AIFrameworkRuns/MAPLW67P/mock-state.json
```

This offline action reads no tokens and prints only the new public `request_id` and `expires_at`. It uses the same seed rules with a fresh two-hour window and immutable manifest. It requires the reviewed root binding, the original `gen/0005` pointer, unchanged synthetic bundles and pristine manifests. It saves the exact previous public state beside the state file as `mock-state.json.previous-<random>.json`, then replaces the state atomically. Repeated reseeding before submission is allowed; old manifests remain intact. A missing root is refused, never recreated.

Submission attempts permanently disable offline reseeding for this root, including failed or uncertain submissions: the launcher records an attempt before sending anything, under the same process lock used by reseed and the runner. This conservatively prevents reseeding after remote approval, which cannot be checked offline. Any local approval store, runner record/journal, kit marker/result, changed pointer or running runner also refuses reseeding. Do not bypass the launcher or reuse roots submitted through other tools; approval on a remote Worker leaves no local evidence by itself. This tool does not inspect or cancel remote requests. After submission, use a new reviewed root binding for a new scene rather than deleting the guard. No token or server credential files are read by reseed.

Submit the refreshed public request with the launcher (it reads requester.token internally and sends it only to the Node helper stdin):

```sh
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B scripts/mock-mac.py submit --state /Users/rcp/AIFrameworkRuns/MAPLW67P/mock-state.json --token-dir /Users/rcp/AIFrameworkRuns/MAPL-tokens
```

The helper pins test mode, screen_publication/1, reviewed root ID and the configured mapl-test host. The user separately approves the refreshed request on iPhone within the two-hour window. Then start in the foreground with the separately reviewed public pin:

```sh
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B scripts/mock-mac.py start --state /Users/rcp/AIFrameworkRuns/MAPLW67P/mock-state.json --token-dir /Users/rcp/AIFrameworkRuns/MAPL-tokens --public-pin /private/mac/reviewed-public-pin.json
```

The origin derives from the same SUBDOMAIN and only mapl-test HTTPS is accepted. The configurable --token-dir defaults to /Users/rcp/AIFrameworkRuns/MAPL-tokens. Start reads runner.token and submit reads requester.token from that directory, outside sync with mode 0600. These are expected filenames; the coordinator must match its private provisioning names or supply a directory with those filenames. Token contents never enter argv, environment or output; errors are generic and do not print paths or token values. No private .token file under the real MAPL-tokens directory was opened during this task; tests read only visibly synthetic temporary files. A mismatched root ID or changed public pin fails closed. Stop with Ctrl-C. Prepare new mock state and obtain a new reviewed public root binding if the OS removes the temporary root. No public start was performed for this package.

## Fix-round verification limits

The signature-free replay additionally checks the 131073-byte body refusal (413), malformed and duplicate-key requester JSON (400), query and authenticated percent-path refusal (404), and CSP, X-Frame-Options, Cache-Control and nosniff on HTML and JSON. The generated entrypoint is src/worker.ts; configure and deployment-tool tests validate the single subdomain and distinct public role digests. Sync guards compare path strings case-insensitively.

CPU is **not measured**: this Mac has no Cloudflare login or API token by design, and the user is not asked to inspect dashboards. Proposed judgement: repeated successful user iPhone approvals on the free plan indicate those requests stayed within the CPU limit because Cloudflare fails requests exceeding it [unconfirmed: current official limits/error-1102 documentation could not be fetched under the registry-only network restriction]. Any 1102-type failure is reported as the Q-H trigger; no numerical CPU measurement or headroom is claimed.

For E2E-3, the post-deploy check's /login and /register HTML rows and /static/app.js and /static/app.css rows compare the response bytes with the reviewed Git files (and therefore the same content hashes). A successful check supports “the deployed screens equal the reviewed screens” at the HTML/static-file level. Browser behaviour and passkey scenes remain local-only, including the agent-tab passkey block; real-device human scenes are covered only by the user's iPhone check. Signed deployed CPU verification and claim_response_lost browser/DOM behaviour are not covered by this replay.
