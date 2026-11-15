"""Fixed localhost test profile. No caller-selectable root settings."""
from .errors import Refusal

MODE = 'test'
BIND_HOST = '127.0.0.1'
IPHONE_TAILSCALE_PROFILE = {'name': 'iphone-tailscale', 'scheme': 'https', 'authorized': False}
SCENARIOS = ('normal', 'runner_offline', 'window_later', 'claim_response_lost',
             'crash_after_start', 'crash_after_marker', 'kit_refuses', 'result_unclear', 'double_click')


class Profile:
    def __init__(self, name='local', port=8790):
        if name != 'local':
            raise Refusal('profile_not_authorized')
        if type(port) is not int or port == 8771 or not 1024 <= port <= 65535:
            raise Refusal('port_refused')
        self.name = name
        self.port = port
        self.origin = f'http://localhost:{port}'
        self.host = f'localhost:{port}'
        self.rp_id = 'localhost'
