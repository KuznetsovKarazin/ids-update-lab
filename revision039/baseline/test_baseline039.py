#!/usr/bin/env python3
"""Author: Oleksandr Kuznetsov. Offline provenance/plan gates; no serial access."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('baseline039_test',Path(__file__).with_name('run_baseline039.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.training=self.root/'training';(self.training/'models').mkdir(parents=True)
        for role in ('A','B'):
            shutil.copyfile(REPO/f'paper037/evidence_inputs/training/models/{role}_lr.json',self.training/f'models/{role}_lr.json')
        self.prebuilt=self.root/'prebuilt'
        for policy in ('bundle','whole'):
            original=REPO/f'revision039/build/prebuilt/O2/lr_{policy}'
            if not (original/'metadata.json').is_file():self.skipTest('build LR Og/O2 artifacts first')
            shutil.copytree(original,self.prebuilt/f'lr_{policy}')
        self.args=argparse.Namespace(training=str(self.training),prebuilt_root=str(self.prebuilt),families=('lr',),output=str(self.root/'prepared'))
    def test_frozen_model_tamper_rejected_before_output(self):
        with (self.training/'models/A_lr.json').open('a') as f:f.write('\n')
        with self.assertRaisesRegex(ValueError,'frozen model hash mismatch'):base.prepare(self.args)
        self.assertFalse(Path(self.args.output).exists())
    def test_prebuilt_tamper_rejected_before_output(self):
        p=self.prebuilt/'lr_whole/ids_update_lab.bin';p.write_bytes(p.read_bytes()+b'x')
        with self.assertRaisesRegex(ValueError,'prebuilt file hash mismatch'):base.prepare(self.args)
        self.assertFalse(Path(self.args.output).exists())
    def test_self_consistent_synthetic_manifest_cannot_replace_frozen_models(self):
        path=self.training/'models/A_lr.json'
        path.write_text(path.read_text()+'\n')
        pins={f'models/{role}_lr.json':base.sha(self.training/f'models/{role}_lr.json') for role in ('A','B')}
        (self.training/'result_manifest.json').write_text(json.dumps({'sha256':pins}))
        with self.assertRaisesRegex(ValueError,'frozen model hash mismatch'):base.prepare(self.args)
        self.assertFalse(Path(self.args.output).exists())
    def test_mixed_optimization_is_rejected_before_preparation(self):
        path=self.prebuilt/'lr_bundle/metadata.json';meta=json.loads(path.read_text())
        meta['optimization']='Og';path.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError,'mixed optimization'):base.prepare(self.args)
        self.assertFalse(Path(self.args.output).exists())
    def test_preparation_and_tampered_artifact_stop_before_provision(self):
        art=base.prepare(self.args);base.old.verify_pins(self.args.output)
        self.assertEqual([art['families']['lr']['versions'][str(v)]['reference'] for v in (1,2,3,4)],['A','A','B','B'])
        self.assertEqual(art['measurement_origin'],'offline_preparation')
        item=art['families']['lr']['policies']['whole']['images']['3']['compressed']
        p=Path(self.args.output)/item['path'];p.write_bytes(p.read_bytes()+b'bad')
        args=argparse.Namespace(artifacts=self.args.output,families=('lr',),output=str(self.root/'run'),
            repetitions=1,board_id='esp32s3-001122334455',port='MUST_NOT_OPEN',timeout=.1)
        with patch.object(base.old,'provision',side_effect=AssertionError('must not flash')) as flash:
            with self.assertRaisesRegex(ValueError,'Evidence SHA256 mismatch'):base.run(args)
            flash.assert_not_called()
        self.assertFalse(Path(args.output).exists())
    def test_plan_has_all_policies_and_two_comparable_transitions(self):
        schedule=base.plan(base.FAMILIES,10)
        self.assertEqual(len(schedule),120)
        for family in base.FAMILIES:
            for policy in base.POLICIES:
                self.assertEqual(sum(x['family']==family and x['policy']==policy for x in schedule),10)
        self.assertEqual(len(schedule)*2,240)
        with self.assertRaises(ValueError):base.plan(('lr',),0)
if __name__=='__main__':unittest.main()
