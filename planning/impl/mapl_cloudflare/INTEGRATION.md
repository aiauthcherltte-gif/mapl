# W4 local integration

`integration.py` is the executable integration test harness for the nine frozen
`mapl_test.config.SCENARIOS`. It launches the current Worker (W2 + W5b session gate) in the already
installed Miniflare/workerd with SQLite Durable Objects and runs the unchanged W3
`MacRunner` in separate Python processes, using `TestRoot` and `MockKit` only.
W5b registers the software fixture and performs a distinct UV login before browser API calls;
the test HTTP adapter forwards the resulting server session cookie explicitly, including
the child process observation reads. This exercises cookie issuance and server validation;
Secure-cookie enforcement and TLS are not browser-tested by this HTTP harness.
The harness does not import or substitute the Python server/store.

From the repository root, with the existing Python environment:

```sh
env -u TMPDIR /Users/rcp/AIFrameworkRuns/MAPLI-venv/bin/python3 -I -B -c 'import sys;sys.path.insert(0,".");from planning.impl.mapl_cloudflare.integration import main;main()' --evidence /absolute/path/to/a/new-evidence-directory
```

This runs all nine scenarios exactly once, so run it only when that complete run
is authorized. An existing evidence directory is refused. No installation is
performed. Metrics are disabled before loading Miniflare, its external fetch
service refuses outbound traffic, `cf` downloading is disabled, and the server
binds only to `127.0.0.1:8790`. Python rejects socket connections to any other host.
Resource thresholds are checked before the launcher, before every scenario, and
at completion. Each scenario uses fresh marked temporary files and a fresh DO.
The server is disposed and port closure checked after every scenario.

The assertions cover exact execution and displayed wording against the fixed
r3 §4.5 / test-version §6.5 oracle, view text, expected mock-kit call counts ≤1,
one approval history row, at most one claim, and a successful W3 poll connection.
A second poll of each live runner tests that the same request does not execute
again; it is not a second scenario run. Evidence includes every history row and
the result from each child process. Concurrent double approval submits the same
signed assertion from two HTTP clients and requires exactly one approval.

The local transport intentionally uses the documented W2 profile:
`http://localhost:8790`, RP ID `localhost`, with TCP to `127.0.0.1`. Its test-only
adapter reuses the test-version HTTP method and W3's poll/envelope/protocol
methods. There is no TLS, certificate verification or TLS-origin authentication
on this local hop. Production `HTTPSTransport` is unchanged and is not exercised
by W4. Independent signature verification and credential/public-key pin checks
inside `MacRunner` do run; the public key is pinned directly from the generated
software authenticator, not copied from the Worker envelope.

Fault boundaries are explicit: lost claim replies are accepted over real HTTP
then discarded by the existing runner scenario; `crash_after_start` uses the
runner's fault hook, exits the first child with its durable process lock intact,
and recovers in a new child with explicit takeover and no kit call. Its immutable
intent-record hash must remain equal. It does not wait 15 minutes to exercise
the timeout. `crash_after_marker` and `kit_refuses` use the existing mock-kit
raised-refusal hooks, not an OS kill or a changed live pointer. `runner_offline`
checks the immediate unclaimed state without waiting for expiry; `window_later`
checks before the window opens. Browser rendering and hardware authenticators
are outside this harness.
