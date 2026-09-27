"""Control-flow tests: predetermined plan and evidence survive an early failure."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
s=load('orchestration_support',ROOT/'tools/campaign_support.py')
r=load('orchestration_runner',ROOT/'tools/run_completion.py')

class SuiteEvidence(unittest.TestCase):
    def args(self,path):return argparse.Namespace(command='costs-suite',model='all',policy='bundle',output=str(path),port='TEST_ONLY',board_id='esp32s3-a0f262ebb558',timeout=1,energy_baseline_seconds=0,rom_recovery=False)
    def contexts(self):return {(a,b):{'kit_manifest_sha256':'a'*64} for a,b in [('lr','bundle'),('lr','compatible'),('lr','whole'),('dt','bundle'),('dt','whole')]}
    def test_plan_precedes_access_and_failure_is_not_retried(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'suite';args=self.args(out)
            calls=[]
            def preflight(*values,**kwargs):
                manifest=json.loads((out/'campaign_manifest.json').read_text());self.assertEqual(len(manifest['tasks']),150)
                self.assertEqual(manifest['tasks'][0]['path'],'task-001-lr-bundle-costs')
            def failing_trial(args,support,c,child,item,reflash=False):
                self.assertTrue(reflash);calls.append(item);child.mkdir();(child/'partial.txt').write_text('raw evidence');raise RuntimeError('deliberate mock interruption')
            with patch.object(r,'session_preflight',preflight),patch.object(r,'trial',failing_trial),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,'deliberate'):r.suite(args,s,self.contexts())
            result=json.loads((out/'summary.json').read_text())
            self.assertEqual(len(calls),1);self.assertEqual(result['status'],'failed');self.assertEqual(result['completed_tasks'],0);self.assertEqual(result['attempted_tasks'],1)
            self.assertTrue((out/result['failed_task_path']/'partial.txt').exists());self.assertEqual(result['aggregate_counters_scope'],'completed_tasks_only')
            self.assertTrue(result['hardware_access_attempted'])
    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'existing';out.mkdir();(out/'keep').write_text('prior evidence')
            with patch.object(r,'session_preflight') as access:
                with self.assertRaises(FileExistsError):r.suite(self.args(out),s,self.contexts())
                access.assert_not_called()
            self.assertEqual((out/'keep').read_text(),'prior evidence')

if __name__=='__main__':unittest.main()
