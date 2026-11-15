"""Foreground localhost entry point. Use only after coordinator releases runs."""
import argparse
import threading
from datetime import datetime, timezone

from .config import Profile, SCENARIOS
from .errors import Refusal
from .isolation import TestRoot
from .mock_kit import MockKit
from .runner_sim import HTTPTransport, RunnerInstance
from .seed import seed
from .server import Application, LocalServer
from .store import Store, setup_code


def main():
    parser = argparse.ArgumentParser(description='MAPL local test server, simulated runner and mock test target')
    parser.add_argument('--port', type=int, default=8790)
    parser.add_argument('--profile', choices=('local', 'iphone-tailscale'), default='local')
    parser.add_argument('--scenario', choices=SCENARIOS, default='normal')
    args = parser.parse_args()
    profile = Profile(args.profile, args.port)
    root = TestRoot.create()
    stop = threading.Event()
    clock = lambda: datetime.now(timezone.utc)
    code = setup_code()
    store = Store(root, clock, profile, setup_code=code)
    request = seed(root, store, clock(), args.scenario)
    server = LocalServer(Application(store, args.scenario))
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.25),
                                     name='mapl-local-http', daemon=True)
    server_thread.start()
    worker = None
    errors = []
    print('Local test server; simulated runner; mock kit; isolated test target.', flush=True)
    print('Test registration code (10 minutes, one use): ' + code, flush=True)
    del code
    print(profile.origin + '/register', flush=True)
    print(profile.origin + '/r/' + request['request_id'], flush=True)
    print('Cross-process restart is outside this test version.', flush=True)

    def run_runner():
        runner = None
        try:
            transport = HTTPTransport(profile.origin, store.runner_token)
            runner = RunnerInstance(root, transport, MockKit(root, clock), clock, args.scenario)
            while not stop.wait(.5):
                try:
                    runner.step()
                except OSError:
                    # Transient HTTP failure: next step only reports journal facts.
                    continue
        except Refusal as error:
            errors.append(error.code)
        finally:
            if runner:
                try:
                    runner.close()
                except OSError:
                    pass

    if args.scenario != 'runner_offline':
        worker = threading.Thread(target=run_runner, name='mapl-simulated-runner', daemon=True)
        worker.start()
    try:
        while server_thread.is_alive():
            server_thread.join(timeout=.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        # Keep HTTP serving until the runner sends its explicit stopping report.
        if worker:
            worker.join(timeout=12)
        server.shutdown()
        server_thread.join(timeout=2)
        server.server_close()
        if errors:
            print('Simulated runner stopped with a refusal code.', flush=True)
        if worker is None or not worker.is_alive():
            root.cleanup()
        else:
            print('Temporary test root retained while the simulated runner stops.', flush=True)


if __name__ == '__main__':
    main()
