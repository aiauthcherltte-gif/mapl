import hashlib
import json
import unittest

from .. import generate_reference as generator
from ...mapl_test.canonical import canonical_bytes, parse_json
from ...mapl_test.errors import Refusal


class ReferenceTests(unittest.TestCase):
    def read(self, name):
        return json.loads((generator.DESTINATION / name).read_bytes())

    def test_hashes_and_minimum_counts(self):
        manifest = self.read('manifest.json')
        for name, expected in manifest['sha256'].items():
            self.assertEqual(hashlib.sha256((generator.DESTINATION / name).read_bytes()).hexdigest(), expected)
        self.assertGreaterEqual(manifest['canonical_cases'], 30)
        self.assertEqual(manifest['challenge_cases'], 10)
        self.assertGreaterEqual(manifest['request_cases'], 40)
        cases = self.read('request.json')
        self.assertTrue(any(case['expected']['accepted'] for case in cases))
        self.assertTrue(any(not case['expected']['accepted'] for case in cases))
        self.assertTrue(all('reason' in case['expected'] for case in cases if not case['expected']['accepted']))

    def test_every_sequence_and_oracle_result(self):
        table = self.read('state.json')
        self.assertEqual(table, generator.transitions(generator.fixture()))
        actual = {tuple(row['sequence']) for row in table['sequences']}
        self.assertEqual(len(actual), sum(17**depth for depth in range(5)))
        self.assertEqual(len(table['events']), 17)
        self.assertTrue(all(len(sequence) <= 4 for sequence in actual))
        for sequence in actual - {()}:
            self.assertIn(sequence[:-1], actual)

    def test_fixed_safe_integers_and_code_point_keys(self):
        for case in self.read('canonical-fixed.json'):
            with self.subTest(case=case['id']):
                expected = case['expected']
                if expected['accepted']:
                    self.assertEqual(canonical_bytes(case['input']), expected['utf8'].encode('utf-8'))
                    self.assertEqual(parse_json(json.dumps(case['input'])), case['input'])
                else:
                    for function, value in ((canonical_bytes, case['input']), (parse_json, json.dumps(case['input']))):
                        with self.assertRaises(Refusal) as caught:
                            function(value)
                        self.assertEqual((caught.exception.code, caught.exception.status),
                                         (expected['reason'], expected['status']))

    def test_fixed_duplicate_reject_and_function_oracles(self):
        self.assertEqual(self.read('canonical.json'), generator.canonical_cases())
        self.assertEqual(self.read('request.json'), generator.request_cases(generator.fixture()))
        for case in self.read('challenge.json'):
            self.assertEqual(generator.canonical.approval_challenge(case['request'], case['nonce']).hex(), case['expected_hex'])
        for case in self.read('strict-json-fixed.json'):
            with self.assertRaises(Refusal) as caught:
                parse_json(case['raw'])
            self.assertEqual(caught.exception.code, case['expected']['reason'])
