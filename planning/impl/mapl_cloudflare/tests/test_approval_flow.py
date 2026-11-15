"""AF1 short, varied protocol, mock execution and restart witnesses."""
import ast
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import timedelta
from ..generate_v2_reference import DEST, request, clause
from ...mapl_test import state, check_contract
from ...mapl_test.request import validate, local_request
from ...mapl_test.canonical import canonical_bytes, digest, approval_challenge
from ...mapl_test.errors import Refusal
from ...mapl_test.runner_sim import DirectTransport
from ..runner import MacRunner
from ...mapl_test.tests.support import World


class FlowTests(unittest.TestCase):
    def test_reference_requests_and_canonical(self):
        root = type('Root', (), {'root_id': request()['target']['test_root_id']})()
        for row in json.loads((DEST/'request-v2.json').read_bytes()):
            with self.subTest(row=row['id']):
                if row['accepted']: self.assertEqual(validate(row['request'], root), row['request'])
                else:
                    with self.assertRaises(Refusal): validate(row['request'], root)
        for row in json.loads((DEST/'canonical-v2.json').read_bytes()):
            self.assertEqual(canonical_bytes(row['request']).decode(),row['utf8'])
            self.assertEqual(digest(canonical_bytes(row['request'])), row['content_hash'])
            self.assertEqual(approval_challenge(row['request'],row['nonce']).hex(), row['challenge_hex'])
        for name, sha in json.loads((DEST/'manifest-v2.json').read_bytes()).items():
            self.assertEqual(digest((DEST/name).read_bytes()),sha)

    def test_reference_states(self):
        for row in json.loads((DEST/'state-v2.json').read_bytes()):
            if 'steps' in row:
                c = row['previous']
                for step in row['steps']:
                    with self.subTest(sequence=row['id'], step=step):
                        if 'error' in step['expected']:
                            with self.assertRaises(Refusal) as caught:
                                state.transition(c, step['event'], step['evidence'], state.utc(step['now']), row['request'])
                            self.assertEqual(caught.exception.code, step['expected']['error'])
                        else:
                            c = state.transition(c, step['event'], step['evidence'], state.utc(step['now']), row['request'])
                            self.assertEqual(c['execution'], step['expected']['execution'])
                continue
            with self.subTest(event=row['event'], evidence=row['evidence']):
                if 'error' in row['expected']:
                    with self.assertRaises(Refusal) as caught: state.transition(row['previous'],row['event'],row['evidence'],state.utc(row['now']),row['request'])
                    self.assertEqual(caught.exception.code,row['expected']['error'])
                else:
                    result=state.transition(row['previous'],row['event'],row['evidence'],state.utc(row['now']),row['request'])
                    self.assertEqual(result,row['expected']['state'])
                    self.assertEqual(state.display(result,row['request'],state.utc(row['now'])), row['expected']['display'])

    def make_v2(self, recovery=False):
        w=World(); self.addCleanup(w.close)
        r=copy.deepcopy(w.request); r['format']='mapl-request/2'; r['revision']=2
        r['check']=check_contract.descriptor(check_contract.MOCK_K7); r['kit']['sha256']=check_contract.kit_hash()
        if recovery: clause(r)
        w.store.create_request(r); w.request=r
        return w

    def test_real_mock_v2_checks_once_after_swap(self):
        w=self.make_v2(); w.approve(); runner=w.runner(); runner.step()
        self.assertEqual(w.record()['execution'],'done')
        self.assertEqual(w.record()['display_state'],'완료 · 포인터·읽기 확인됨 · 수집기·화면 확인 대기')
        self.assertEqual(w.kit.swaps[w.rid],1)
        with patch.object(check_contract,'check',side_effect=AssertionError('second check')): runner.step()

    def test_descriptor_mismatches_before_claim(self):
        for field, value in [('scope',['pointer_bytes','pinned_reader','collector']),('recovery_eligible_codes',[]),('recovery_eligible_codes',['INPUT_CHANGED'])]:
            w=self.make_v2(); r=copy.deepcopy(w.request);r['revision']=3;r['check'][field]=value;w.store.create_request(r);w.request=r;w.approve()
            runner=w.runner();runner.step();self.assertIsNone(w.record()['claim_id']);self.assertNotIn(w.rid,w.kit.calls)
            self.assertEqual(w.record()['history'][-1]['code'],'CONTENT_MISMATCH')

    def test_changed_scope_cannot_reuse_assertion(self):
        w=self.make_v2(); signed=w.sign();r=copy.deepcopy(w.request);r['revision']=3;r['check']['scope']=['pointer_bytes'];w.store.create_request(r)
        w.options()
        with self.assertRaises(Refusal):w.store.approve(w.rid,signed)

    def test_expired_is_not_content_mismatch(self):
        w=self.make_v2();w.approve(); envelope=w.store.approved()[0];w.clock.advance(7200);runner=w.runner()
        with self.assertRaises(Refusal) as caught:runner._verify(envelope)
        self.assertEqual(caught.exception.code,'EXPIRED');runner._refuse(w.request,'EXPIRED')
        self.assertEqual(next(x for x in w.record()['history'] if x['event']=='refused_before_claim')['text'],'Mac 실행기(모의)가 만료로 맡지 않음 (EXPIRED)')

    def test_withdraw(self):
        w=self.make_v2();w.approve();w.store.withdraw(w.rid);self.assertEqual(w.store.approved(),[])
        self.assertEqual(w.record()['display_state'],'승인 철회 · 실행하지 않습니다')

    def test_exact_recovery_once_and_restart_never_retries(self):
        w=self.make_v2(True);w.approve();runner=w.runner()
        with patch.object(check_contract,'check',return_value=(3,'STOP READER_INDEX_MISMATCH')): runner.step()
        self.assertEqual(w.record()['execution'],'recovered')
        self.assertEqual(digest(w.root.read_bytes(w.root.pointer())),w.request['target']['before_sha256'])
        runner.step();self.assertEqual(w.kit.swaps[w.rid],1)
        with self.assertRaises(Refusal): check_contract.recover(w.root,w.request,runner.journal[w.rid]['claim_id'],w.clock,'checking')

    def test_failed_recovery_start_delivery_does_not_repeat_restore(self):
        w=self.make_v2(True);w.approve();runner=w.runner();original=runner._report
        def report(rid, revision, claim, event, evidence):
            if event=='recovery_start': raise ConnectionError('report_delivery_unconfirmed')
            return original(rid,revision,claim,event,evidence)
        runner._report=report
        with patch.object(check_contract,'check',return_value=(3,'STOP READER_INDEX_MISMATCH')):runner.step()
        self.assertIn('recovery_start_unconfirmed',[x['state'] for x in runner.journal[w.rid]['rows']])
        self.assertEqual(w.record()['execution'],'recovered')

    def test_restart_after_swap_only_reports(self):
        w=self.make_v2();w.approve();runner=w.runner()
        with patch.object(runner,'_check_v2',side_effect=ConnectionError('crash')):
            with self.assertRaises(ConnectionError):runner.step()
        runner.crash(); again=w.runner(takeover=True)
        with patch.object(check_contract,'check',side_effect=AssertionError('restart check')):again.step()
        self.assertEqual(w.record()['execution'],'check_unknown')

    def test_crash_before_result_journal(self):
        for runner_type in ('sim', 'mac'):
            for recovery in (False, True):
                with self.subTest(runner=runner_type, recovery=recovery):
                    w=self.make_v2(recovery); w.approve()
                    def create(takeover=False):
                        if runner_type == 'sim': return w.runner(takeover=takeover)
                        transport=DirectTransport(w.store)
                        transport.poll=lambda: {'requests':transport.approved(),'server_now':state.stamp(w.clock()),'has_pending':True}
                        r=MacRunner(w.root, transport, w.kit, w.clock, takeover_after_crash=takeover)
                        w.runners.append(r); return r
                    runner=create(); original=runner._journal
                    def journal(rid, rev, claim, status, evidence=None):
                        if status == 'result': raise ConnectionError('crash before result journal')
                        return original(rid,rev,claim,status,evidence)
                    with patch.object(runner,'_journal',side_effect=journal):
                        if runner_type == 'mac': runner.step()
                        else:
                            with self.assertRaises(ConnectionError): runner.step()
                    self.assertEqual(w.kit.swaps[w.rid],1)
                    self.assertFalse(any(x['state']=='result' for x in runner.journal[w.rid].get('rows',[])))
                    # Same-process restart fixture releases only the process lock;
                    # production takeover still requires proof of a dead PID.
                    if runner_type == 'mac': w.root.release_process_runner_lock(runner.instance_id)
                    runner.crash(); again=create(True); sent=[]; report=again._report
                    def record(rid,rev,claim,event,evidence):
                        sent.append(event); return report(rid,rev,claim,event,evidence)
                    with patch.object(again,'_report',side_effect=record), patch.object(check_contract,'check',side_effect=AssertionError('restart check')), patch.object(check_contract,'recover',side_effect=AssertionError('restart restore')):
                        again.step()
                    self.assertEqual(sent,['check_unknown'])
                    self.assertEqual(w.record()['execution'],'check_unknown')
                    self.assertEqual(w.kit.calls[w.rid],1)

    def test_crash_before_journal_ambiguous_kit_stays_unknown(self):
        w=self.make_v2(); w.approve(); runner=w.runner(scenario='result_unclear'); original=runner._journal
        def journal(rid,rev,claim,status,evidence=None):
            if status=='result': raise ConnectionError('before journal')
            return original(rid,rev,claim,status,evidence)
        with patch.object(runner,'_journal',side_effect=journal):
            with self.assertRaises(ConnectionError): runner.step()
        runner.crash(); again=w.runner(takeover=True)
        with patch.object(check_contract,'check',side_effect=AssertionError('recheck')): again.step()
        self.assertEqual(w.record()['execution'],'unknown')

    def test_current_mismatch_never_restores(self):
        for mismatch_at in ('check','reread'):
            w=self.make_v2(True);w.approve();runner=w.runner()
            def check(root,r):
                root.write_atomic(root.pointer(),b'third-party-test')
                return 3, 'STOP '+('CURRENT_IS_NOT_APPROVED_AFTER_BYTES' if mismatch_at=='check' else 'READER_INDEX_MISMATCH')
            with patch.object(check_contract,'check',side_effect=check):runner.step()
            self.assertEqual(w.record()['execution'],'check_failed')
            self.assertFalse(w.root.exists('kit/recovery/'+w.rid+'.json'))

    def test_check_read_only_and_recovery_entry_allowlist(self):
        source=Path(check_contract.__file__).read_text(); tree=ast.parse(source)
        check=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='check')
        self.assertFalse(any(isinstance(n,ast.Attribute) and n.attr.startswith(('write','remove')) for n in ast.walk(check)))
        w=self.make_v2(True)
        for phase in ('running','checking','result','','recovery_intent'):
            with self.assertRaises(Refusal):check_contract.recover(w.root,w.request,'a'*32,w.clock,phase)

    def test_strict_stop_codes(self):
        for exit_code, stderr in [(0,'STOP READER_INDEX_MISMATCH'),(3,'STOP OTHER'),(3,'noise\nSTOP READER_INDEX_MISMATCH'),(3,'STOP READER_INDEX_MISMATCH\nextra'),(4,'STOP READER_INDEX_MISMATCH')]:
            self.assertIsNone(check_contract.parse_check(exit_code,stderr,check_contract.MOCK_K7))
        self.assertEqual(check_contract.parse_check(3,'STOP READER_INDEX_MISMATCH:detail\n',check_contract.MOCK_K7),'READER_INDEX_MISMATCH')

    def test_recovery_start_deadline_anchored_before_report(self):
        w=self.make_v2(True);w.approve();runner=w.runner()
        def check(root,r):
            w.clock.advance(601)
            return 3,'STOP READER_INDEX_MISMATCH'
        with patch.object(check_contract,'check',side_effect=check):runner.step()
        self.assertEqual(w.record()['execution'],'check_failed')
        self.assertFalse(w.root.exists('runner/recovery-intents/'+w.rid+'.json'))

    def test_restart_after_recovery_intent_reports_unknown(self):
        w=self.make_v2(True);w.approve();runner=w.runner();original=runner._report
        def report(rid,revision,claim,event,evidence):
            if event=='recovery_start':raise OSError('stop before recover')
            return original(rid,revision,claim,event,evidence)
        runner._report=report
        with patch.object(check_contract,'check',return_value=(3,'STOP READER_INDEX_MISMATCH')):
            with self.assertRaises(OSError):runner.step()
        runner.crash();again=w.runner(takeover=True)
        with patch.object(check_contract,'recover',side_effect=AssertionError('restart recovery')):again.step()
        self.assertEqual(w.record()['execution'],'unknown')
        self.assertFalse(w.root.exists('kit/recovery/'+w.rid+'.json'))

    def test_restart_resends_same_check_result_without_rerun(self):
        w=self.make_v2();w.approve();runner=w.runner();original=runner._report
        def report(rid,revision,claim,event,evidence):
            if event=='check_ok':raise OSError('lost result')
            return original(rid,revision,claim,event,evidence)
        runner._report=report
        with self.assertRaises(OSError):runner.step()
        runner.crash();again=w.runner(takeover=True)
        with patch.object(check_contract,'check',side_effect=AssertionError('recheck')):again.step()
        self.assertEqual(w.record()['execution'],'done')

    def test_v2_admission_anchor_on_create_and_revision(self):
        w=self.make_v2()
        r=copy.deepcopy(w.request);r['revision']=3;r['created_at']=state.stamp(w.clock()-timedelta(seconds=301))
        with self.assertRaises(Refusal):w.store.create_request(r)
        self.assertEqual(w.record()['request']['revision'],2)

    def test_not_yet_narrows_verified_scope(self):
        r=request();now=state.utc(r['created_at']);c=state.initial();c.update(approval='approved',execution='checking',claim_id='a'*32)
        for pending in (['collector'],[]):
            next_state=state.transition(c,'check_ok',{'claim_id':'a'*32,'pending':pending,'scope':['screen']},now,r)
            self.assertNotIn('동작 확인됨',state.display(next_state,r,now))
        r['check']['scope'].append('screen')
        n=state.transition(c,'check_ok',{'claim_id':'a'*32,'pending':['screen']},now,r)
        self.assertIn('화면 확인 대기',state.display(n,r,now))
