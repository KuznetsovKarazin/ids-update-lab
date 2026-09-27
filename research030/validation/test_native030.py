#!/usr/bin/env python3
"""Host-only native/reference parity, malformed payloads and rounding boundaries.

Requires g++, OpenSSL development headers. Does not access an MCU.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / 'hardware_codec'))
sys.path.insert(0, str(KIT / 'training'))
import codec030 as codec
import model030 as ref


class NativeParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # LeakSanitizer cannot run under this execution environment's ptrace.
        # Address/undefined checks remain enabled; no leak-check claim is made.
        os.environ['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
        os.environ['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        cls.tmp = tempfile.TemporaryDirectory(prefix='ids030-native-')
        cls.work = Path(cls.tmp.name)
        cls.exe = cls.work / 'native'
        core = KIT / 'firmware/components/ids_core'
        cls.command = ['g++', '-std=c++17', '-O1', '-g', '-ffp-contract=off',
                       '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie',
                       '-I', str(core / 'include'), str(KIT / 'validation/native030.cpp'),
                       *[str(core / n) for n in ('ids_core.cpp', 'ids_tree.cpp', 'ids_mlp.cpp')],
                       '-lcrypto', '-o', str(cls.exe)]
        subprocess.run(cls.command, check=True, capture_output=True)
        (cls.work / 'public.pem').write_bytes(codec.public_pem())
        rng = np.random.default_rng(30025)
        cls.raw = np.expm1(rng.uniform(0, 16, (1024, 8))).astype('<f4')
        cls.raw = np.vstack([np.zeros((1, 8), '<f4'), cls.raw,
                             np.full((1, 8), np.finfo(np.float32).max, '<f4')])
        cls.models = {}
        for kind in ('lr', 'dt', 'mlp_float'):
            m = codec.bootstrap(kind)
            m['mean'] = rng.uniform(1, 6, 8).astype(np.float32).tolist()
            m['scale'] = rng.uniform(1, 4, 8).astype(np.float32).tolist()
            if kind == 'lr':
                m['weights'] = rng.normal(0, .2, 8).astype(np.float32).tolist()
                m['bias'] = -.1
            elif kind == 'dt':
                m['nodes'] = [dict(feature=0, left=1, right=2, threshold=40., probability=.5),
                              dict(feature=-1, left=-1, right=-1, threshold=0., probability=.2),
                              dict(feature=-1, left=-1, right=-1, threshold=0., probability=.8)]
            else:
                for layer in m['layers']:
                    shape = np.asarray(layer['weights']).shape
                    layer['weights'] = rng.normal(0, .22, shape).astype(np.float32).tolist()
                    layer['bias'] = rng.normal(0, .05, shape[1]).astype(np.float32).tolist()
            cls.models[kind] = m
        cls.models['mlp_int8'] = ref.quantize(cls.models['mlp_float'], cls.raw[:-1])
        cls.report = {'measurement_origin': 'host_native_validation', 'hardware_access_attempted': False,
                      'sanitizers': ['address', 'undefined'], 'leak_sanitizer': 'not run: ptrace environment',
                      'seed': 30025, 'comparisons': []}

    @classmethod
    def tearDownClass(cls):
        target = os.environ.get('IDS030_NATIVE_REPORT')
        if target:
            cls.report['source_sha256'] = {
                p.relative_to(KIT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in [KIT / 'validation/native030.cpp', KIT / 'training/model030.py',
                          KIT / 'hardware_codec/codec030.py',
                          *sorted((KIT / 'firmware/components/ids_core').glob('*.cpp'))]}
            Path(target).write_text(json.dumps(cls.report, indent=2) + '\n')
        cls.tmp.cleanup()

    def native(self, envelope, raw=None):
        p = self.work / 'model.sids'; p.write_bytes(envelope)
        return subprocess.run([str(self.exe), str(p), str(self.work / 'public.pem')],
                              input=b'' if raw is None else np.asarray(raw, '<f4').tobytes(),
                              capture_output=True, timeout=30)

    def parity(self, m, raw):
        result = self.native(codec.sign_envelope(m, 7, 'native030'), raw)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        rows = [json.loads(x) for x in result.stdout.splitlines()]
        p, label = ref.predict(m, raw)
        self.assertEqual(len(rows), len(raw))
        self.assertTrue(all(r['ok'] for r in rows))
        got = np.array([r['p'] for r in rows])
        err = float(np.max(np.abs(got - p)))
        self.assertLessEqual(err, 2e-6)
        np.testing.assert_array_equal([r['label'] for r in rows], label)
        self.report['comparisons'].append(dict(kind=m['kind'], rows=len(raw),
                                              threshold=m['threshold'], q_threshold=m.get('q_threshold'),
                                              label_mismatches=0, max_probability_abs_error=err))

    def test_four_families_random_and_extreme_inputs(self):
        for model in self.models.values():
            with self.subTest(kind=model['kind']): self.parity(model, self.raw)

    def test_float_threshold_endpoints_and_exact_tie(self):
        for kind in ('lr', 'dt', 'mlp_float'):
            for threshold in (0., .5, 1.):
                m = codec.bootstrap(kind); m['threshold'] = threshold
                if kind == 'dt': m['nodes'][0]['probability'] = .5
                self.parity(m, self.raw[:3])
        for bias in (-1000., 1000.):
            m = codec.bootstrap('lr'); m.update(bias=bias, threshold=0.)
            self.parity(m, self.raw[:3])

    def test_integer_threshold_endpoints(self):
        for cut in (-127, 0, 1, 127, 128):
            m = copy.deepcopy(self.models['mlp_int8']); m['q_threshold'] = cut
            self.parity(m, self.raw)

    def test_tree_boundary(self):
        raw = np.zeros((3, 8), '<f4')
        raw[:, 0] = [np.nextafter(np.float32(40), np.float32(-np.inf)), 40,
                     np.nextafter(np.float32(40), np.float32(np.inf))]
        self.parity(self.models['dt'], raw)

    def test_invalid_inputs_rejected(self):
        raw = np.zeros((3, 8), '<f4'); raw[:, 0] = [-1, np.nan, np.inf]
        for model in self.models.values():
            result = self.native(codec.sign_envelope(model, 7, 'native030'), raw)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(x) for x in result.stdout.splitlines()]
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(not r['ok'] for r in rows))

    def test_signed_malformed_mlp_rejected(self):
        base = codec.payload(self.models['mlp_int8'], 7, 'native030')
        variants = [base[:n] for n in (0, 19, 79, 143, 159, 167, len(base)-1)]
        for offset, fmt, val in ((160, '<f', 0.), (164, '<i', 129),
                                 (168, '<I', 0), (172, '<I', 63), (176, '<f', float('nan'))):
            p = bytearray(base); struct.pack_into(fmt, p, offset, val); variants.append(bytes(p))
        for p in variants:
            sig = codec.key().sign(p, padding.PKCS1v15(), hashes.SHA256())
            blob = b'SIDSPK1\0' + struct.pack('<II', len(p), len(sig)) + p + sig
            result = self.native(blob)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertNotIn(b'Sanitizer', result.stderr)

    def test_short_decoder_under_sanitizers(self):
        result = subprocess.run([str(self.exe), 'decode-short'], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_integer_rounding_half_ties_and_bounds(self):
        cases = []
        for shift in (1, 2, 7, 30, 31, 62):
            half = 1 << (shift-1)
            for v in (0, half-1, half, half+1, (2**31-1)**2):
                cases.extend([(v, shift), (-v, shift)])
        text = ''.join(f'{v} {s}\n' for v, s in cases)
        result = subprocess.run([str(self.exe), 'round'], input=text.encode(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = [min(127, (abs(v)+(1 << (s-1))) >> s) * (-1 if v<0 else 1) for v,s in cases]
        self.assertEqual(list(map(int, result.stdout.splitlines())), expected)


if __name__ == '__main__': unittest.main(verbosity=2)
