"""One locked, atomic JSON snapshot per test root. No operational store imports."""
import copy
import hmac
import re
import secrets
import threading

from .canonical import approval_challenge, b64encode, canonical_bytes, digest
from .config import Profile
from .errors import Refusal
from .request import validate
from . import state
from .webauthn_verify import verify_assertion, verify_registration

STORE_LOCK = threading.RLock()


def setup_code():
    return ''.join(secrets.choice('23456789ABCDEFGHJKLMNPQRSTUVWXYZ') for _ in range(10))


class Store:
    def __init__(self, root, clock, profile=None, *, setup_code):
        self.root, self.clock = root, clock
        self.profile = profile or Profile()
        self.lock = STORE_LOCK
        self._failed = False
        self._setup_hash = digest(setup_code.encode())
        self._setup_until = clock().timestamp() + 600
        self.runner_token = secrets.token_hex(32)
        self.requester_token = secrets.token_hex(32)
        self._data = {'requests': {}, 'latest': {}, 'nonces': {}, 'credential': None,
                      'registration_challenge': None, 'last_contact': None, 'stopped_at': None,
                      'user_id': b64encode(secrets.token_bytes(16))}
        self.root.write_atomic('server/runner.token', self.runner_token.encode(), exclusive=True)
        self.root.write_atomic('server/requester.token', self.requester_token.encode(), exclusive=True)
        self._save()

    def _save(self):
        if self._failed:
            raise Refusal('store_unavailable', 503)
        try:
            self.root.write_json('server/state.json', self._data)
        except (OSError, Refusal):
            # A failed durable transaction must not leave an in-memory approval
            # claimable. Freeze the store for the life of this temporary root.
            self._failed = True
            raise

    def _key(self, rid, revision):
        if not isinstance(rid, str) or not re.fullmatch(r'[0-9a-f]{32}', rid) or type(revision) is not int or revision < 1:
            raise Refusal('request_not_found', 404)
        return f'{rid}:{revision}'

    def _entry(self, rid, revision=None):
        if self._failed:
            raise Refusal('store_unavailable', 503)
        revision = revision if revision is not None else self._data['latest'].get(rid)
        key = self._key(rid, revision)
        if key not in self._data['requests']:
            raise Refusal('request_not_found', 404)
        return self._data['requests'][key]

    def _history(self, entry, event, **extra):
        entry['history'].append({'at': state.stamp(self.clock()), 'event': event, **extra})

    def _tick(self, entry):
        before = entry['state']
        after = state.transition(before, 'tick', {}, self.clock(), entry['request'])
        if before != after:
            entry['state'] = after
            self._history(entry, 'tick', execution=after['execution'])
            self._save()

    def create_request(self, request):
        with self.lock:
            request = validate(request, self.root)
            if request['format'] == 'mapl-request/2' and not -300 <= (state.utc(request['created_at']) - self.clock()).total_seconds() <= 60:
                raise Refusal('request_invalid', 400)
            rid, revision = request['request_id'], request['revision']
            latest = self._data['latest'].get(rid)
            if latest is not None:
                old = self._entry(rid)
                if old['state']['claim_id']:
                    raise Refusal('claimed_revision_in_progress')
                if revision != latest + 1:
                    raise Refusal('revision_refused')
                old['state'] = state.transition(old['state'], 'revise', {}, self.clock(), old['request'])
                self._history(old, 'revise')
            elif revision != 1:
                raise Refusal('revision_refused')
            entry = {'request': request, 'state': state.initial(), 'history': [], 'assertion': None,
                     'nonce': None, 'approval_facts': None, 'claim_response': None, 'last_evidence': None}
            self._history(entry, 'create')
            self._data['requests'][self._key(rid, revision)] = entry
            self._data['latest'][rid] = revision
            self.root.write_json('runner/manifests/' + rid + '/' + str(revision) + '.json', request, exclusive=True)
            self._save()
            return self.get(rid)

    def get(self, rid, revision=None):
        with self.lock:
            entry = self._entry(rid, revision)
            self._tick(entry)
            return {'request': copy.deepcopy(entry['request']), **copy.deepcopy(entry['state']),
                    'content_hash': digest(canonical_bytes(entry['request'])),
                    'history': copy.deepcopy(entry['history']),
                    'display_state': state.display(entry['state'], entry['request'], self.clock()),
                    'server_now': state.stamp(self.clock()), 'runner_status': self.runner_status(),
                    'credential_count': self.credential_count(),
                    'credential_registered_at': (self._data['credential'] or {}).get('registered_at')}

    def credential_count(self):
        with self.lock:
            return int(self._data['credential'] is not None)

    def _registration_gate(self, code):
        if self._failed:
            raise Refusal('store_unavailable', 503)
        if self._data['credential'] is not None:
            raise Refusal('registration_closed')
        if self.clock().timestamp() >= self._setup_until:
            raise Refusal('setup_code_expired')
        if not isinstance(code, str) or not hmac.compare_digest(digest(code.encode()), self._setup_hash):
            raise Refusal('setup_code_invalid', 403)

    def registration_options(self, code):
        with self.lock:
            self._registration_gate(code)
            challenge = secrets.token_bytes(32)
            self._data['registration_challenge'] = {'value': b64encode(challenge), 'issued_at': state.stamp(self.clock())}
            self._save()
            return {'challenge': b64encode(challenge), 'rp': {'id': self.profile.rp_id, 'name': 'MAPL 시험판'},
                    'user': {'id': self._data['user_id'], 'name': 'mapl-test', 'displayName': 'MAPL 시험판'},
                    'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}], 'attestation': 'none',
                    'authenticatorSelection': {'residentKey': 'preferred', 'userVerification': 'required'},
                    'timeout': 180000}

    def register(self, code, registration):
        from .canonical import b64decode
        with self.lock:
            self._registration_gate(code)
            issued = self._data['registration_challenge']
            if issued is None or (self.clock() - state.utc(issued['issued_at'])).total_seconds() > 180:
                raise Refusal('registration_challenge_expired')
            credential = verify_registration(registration, b64decode(issued['value']), self.profile.origin, self.profile.rp_id)
            credential['registered_at'] = state.stamp(self.clock())
            self._data['credential'] = credential
            self._data['registration_challenge'] = None
            self._save()
            # Test version only: a pinned copy written at registration; operational
            # enrollment must pin independently. It is not changed by later reports.
            self.root.write_json('server/credentials.json', credential)
            self.root.write_json('runner/pinned-credential.json', credential, exclusive=True)
            self._setup_hash = ''
            return {'credential_count': 1, 'registered_at': credential['registered_at']}

    def approval_options(self, rid, revision=None, content_hash=None):
        with self.lock:
            entry = self._entry(rid)
            # Browser callers supply the exact pair displayed on entering
            # confirmation. Check it under the same lock that issues the nonce.
            if ((revision is not None or content_hash is not None)
                and (type(revision) is not int or revision != entry['request']['revision']
                     or content_hash != digest(canonical_bytes(entry['request'])))):
                raise Refusal('revision_changed')
            self._tick(entry)
            if entry['state']['approval'] == 'approved':
                raise Refusal('already_approved')
            if state.expired(entry['request'], self.clock()):
                raise Refusal('expired')
            if entry['state']['approval'] != 'pending':
                raise Refusal(entry['state']['approval'])
            credential = self._data['credential']
            if credential is None:
                raise Refusal('registration_required')
            key = self._key(rid, entry['request']['revision'])
            previous = self._data['nonces'].get(key)
            if previous and (self.clock() - state.utc(previous['issued_at'])).total_seconds() < 2:
                # Same unconsumed options within the short rate limit, no nonce flood.
                nonce = previous
            else:
                nonce = {'value': secrets.token_hex(32), 'issued_at': state.stamp(self.clock()), 'used': False}
                self._data['nonces'][key] = nonce
                self._save()
            return {'challenge': b64encode(approval_challenge(entry['request'], nonce['value'])),
                    'rpId': self.profile.rp_id, 'userVerification': 'required', 'timeout': 180000,
                    'allowCredentials': [{'type': 'public-key', 'id': credential['id']}]}

    def approve(self, rid, assertion, revision=None):
        with self.lock:
            entry = self._entry(rid, revision)
            request = entry['request']
            if self._data['latest'][rid] != request['revision']:
                raise Refusal('superseded')
            key = self._key(rid, request['revision'])
            nonce = self._data['nonces'].get(key)
            if nonce and nonce['used']:
                raise Refusal('nonce_used')
            if entry['state']['approval'] == 'approved':
                raise Refusal('already_approved')
            if state.expired(request, self.clock()):
                raise Refusal('expired')
            if entry['state']['approval'] != 'pending':
                raise Refusal(entry['state']['approval'])
            if nonce is None:
                raise Refusal('challenge_mismatch', 400)
            if (self.clock() - state.utc(nonce['issued_at'])).total_seconds() >= 180:
                raise Refusal('nonce_expired')
            credential = self._data['credential']
            if credential is None:
                raise Refusal('registration_required')
            validate(request, self.root)
            facts = verify_assertion(assertion, credential, approval_challenge(request, nonce['value']),
                                     self.profile.origin, self.profile.rp_id)
            # All verification, nonce consumption and approval changes share this
            # process-wide lock and the same atomic persisted snapshot.
            entry['state'] = state.transition(entry['state'], 'approve', {}, self.clock(), request)
            entry.update(assertion=copy.deepcopy(assertion), nonce=nonce['value'], approval_facts=facts)
            nonce['used'] = True
            credential.update(sign_count=facts['sign_count'], be=facts['be'], bs=facts['bs'])
            self._history(entry, 'approve', assertion_sha256=digest(canonical_bytes(assertion)), facts=facts)
            self._save()
            return self.get(rid)

    def withdraw(self, rid):
        with self.lock:
            entry = self._entry(rid)
            self._tick(entry)
            entry['state'] = state.transition(entry['state'], 'withdraw', {}, self.clock(), entry['request'])
            self._history(entry, 'withdraw')
            self._save()
            return self.get(rid)

    def decline(self, rid):
        with self.lock:
            entry = self._entry(rid)
            self._tick(entry)
            entry['state'] = state.transition(entry['state'], 'decline', {}, self.clock(), entry['request'])
            self._history(entry, 'decline')
            self._save()
            return self.get(rid)

    def cancel(self, rid):
        with self.lock:
            entry = self._entry(rid)
            entry['state'] = state.transition(entry['state'], 'cancel', {}, self.clock(), entry['request'])
            self._history(entry, 'cancel')
            self._save()
            return self.get(rid)

    def approved(self):
        with self.lock:
            entries = []
            for rid in self._data['latest']:
                entry = self._entry(rid)
                self._tick(entry)
                if entry['state']['approval'] == 'approved' and entry['state']['execution'] == 'not_started':
                    entries.append(self._envelope(entry))
            return entries

    def _envelope(self, entry):
        return copy.deepcopy({'request': entry['request'], 'assertion': entry['assertion'],
            'nonce': entry['nonce'], 'credential': self._data['credential'],
            'content_hash': digest(canonical_bytes(entry['request']))})

    def claim(self, rid, revision, claim_id):
        with self.lock:
            if not isinstance(claim_id, str) or not re.fullmatch(r'[0-9a-f]{32}', claim_id):
                raise Refusal('claim_id_invalid', 400)
            entry = self._entry(rid, revision)
            self._tick(entry)
            current = entry['state']
            if current['claim_id'] is not None:
                if current['claim_id'] != claim_id:
                    raise Refusal('already_claimed')
                if current['execution'] != 'claimed':
                    raise Refusal('claim_closed:' + current['execution'])
                return copy.deepcopy(entry['claim_response'])
            if self._data['latest'][rid] != revision:
                raise Refusal('not_claimable:superseded')
            # §A H1: latest + approved + not_started + time guards under one lock.
            current = state.transition(current, 'claim', {'claim_id': claim_id}, self.clock(), entry['request'])
            response = {'granted': True, 'request_id': rid, 'revision': revision, 'claim_id': claim_id}
            entry.update(state=current, claim_response=response)
            self._history(entry, 'claim', claim_id=claim_id)
            self._save()
            return copy.deepcopy(response)

    def runner_report(self, rid, revision, claim_id, event, evidence):
        with self.lock:
            entry = self._entry(rid, revision)
            if not isinstance(evidence, dict):
                raise Refusal('evidence_malformed', 400)
            if event == 'refused_before_claim':
                if entry['state']['claim_id'] is not None:
                    raise Refusal('already_claimed')
                code = evidence.get('code')
                if code not in ('EXPIRED', 'CONTENT_MISMATCH', 'pinned_key_mismatch', 'ASSERTION_REFUSED', 'CLOCK_SKEW'):
                    raise Refusal('refusal_code_invalid', 400)
                self._history(entry, event, code=code,
                    text='Mac 실행기(모의)가 만료로 맡지 않음 (EXPIRED)' if code == 'EXPIRED' else 'Mac 실행기(모의)가 내용 불일치로 맡지 않음 (CONTENT_MISMATCH)' if code == 'CONTENT_MISMATCH'
                    else 'Mac 실행기(모의)가 검증 불일치로 맡지 않음 (' + code + ')')
                self._save()
                return self.get(rid, revision)
            if event not in ('start', 'result', 'not_run') + state.flow.EVENTS:
                raise Refusal('event_refused', 400)
            if evidence.get('code') and (not isinstance(evidence['code'], str) or not re.fullmatch(r'[A-Z_]{1,80}', evidence['code'])):
                raise Refusal('refusal_code_invalid', 400)
            self._tick(entry)
            # Reports may be resent, execution is never resent. Identical reports
            # on a final axis get the persisted answer, no extra history event.
            report_key = {'claim_id': claim_id, 'event': event, 'evidence': evidence}
            if entry.get('last_report') == report_key:
                return self.get(rid, revision)
            facts = {**copy.deepcopy(evidence), 'claim_id': claim_id}
            entry['state'] = state.transition(entry['state'], event, facts, self.clock(), entry['request'])
            if event == 'result' and evidence.get('code'):
                entry['state']['result_code'] = evidence['code']
            entry['last_evidence'] = copy.deepcopy(evidence)
            entry['last_report'] = copy.deepcopy(report_key)
            self._history(entry, event, claim_id=claim_id, evidence=copy.deepcopy(evidence), source='simulated_runner_report')
            self._save()
            return self.get(rid, revision)

    def heartbeat(self):
        with self.lock:
            self._data['last_contact'] = state.stamp(self.clock())
            self._data['stopped_at'] = None
            self._save()
            return {'recorded': True}

    def stopping(self):
        with self.lock:
            self._data['last_contact'] = self._data['stopped_at'] = state.stamp(self.clock())
            self._save()
            return {'recorded': True}

    def runner_status(self):
        with self.lock:
            if self._data['stopped_at']:
                return '실행기가 꺼진다고 알림 ' + state.utc(self._data['stopped_at']).astimezone().strftime('%H:%M:%S')
            contact = self._data['last_contact']
            suffix = '켜짐·꺼짐은 이 정보만으로 알 수 없습니다'
            if not contact:
                return 'Mac 실행기(모의) 연결 기록 없음 · ' + suffix
            at = state.utc(contact)
            minutes = max(0, int((self.clock() - at).total_seconds()) // 60)
            return f'Mac 실행기(모의) 마지막 연결 {at.astimezone():%H:%M:%S} ({minutes}분 전) · {suffix}'

    # Test fixtures edit only this private test store, under the normal store lock.
    # These methods have no HTTP routes and cannot choose a filesystem path.
    def inject_request_for_tests(self, rid, revision, change):
        with self.lock:
            change(self._entry(rid, revision)['request'])
            self._save()

    def inject_approval_for_tests(self, rid, assertion):
        with self.lock:
            entry = self._entry(rid)
            key = self._key(rid, entry['request']['revision'])
            entry['state']['approval'] = 'approved'
            entry['assertion'] = copy.deepcopy(assertion)
            entry['nonce'] = self._data['nonces'][key]['value']
            self._save()
