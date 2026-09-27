"""Offline validation of trial plans and fail-closed evidence gates."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('campaign_support_test',ROOT/'tools/campaign_support.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)

class CampaignGates(unittest.TestCase):
    def test_fixed_fault_matrix_and_seed(self):
        p=s.plan('faults');self.assertEqual(p,s.plan('faults'));self.assertEqual(len(p),120)
        for checkpoint in s.CHECKPOINTS:
            for condition in ('clean','reused'):
                rows=[r for r in p if r['checkpoint']==checkpoint and r['target_condition']==condition]
                self.assertEqual(sorted(r['replicate'] for r in rows),list(range(1,11)))
    def test_cost_plan_is_thirty_before_data(self):
        p=s.plan('costs');self.assertEqual(len(p),30)
        self.assertTrue(all(r['transitions']==['A_to_B_clean','B_to_C_reused'] for r in p))
    def test_security_thirty(self):
        p=s.plan('negatives');self.assertEqual(len(p),30)
        for kind in ('signature','contract','replay'):self.assertEqual(sum(r['negative']==kind for r in p),10)
    def test_balanced_cost_suite_before_hardware(self):
        for model,count in [('lr',3),('dt',2),('all',5)]:
            rows=s.suite_plan(model)
            self.assertEqual(len(rows),30*count)
            configurations={(r['model'],r['policy']) for r in rows}
            for pair in configurations:
                entries=[r for r in rows if (r['model'],r['policy'])==pair]
                self.assertEqual(sorted(r['block'] for r in entries),list(range(1,31)))
                for position in range(1,count+1):self.assertEqual(sum(r['position']==position for r in entries),30//count)
    def test_mac_identity_explicit(self):
        self.assertEqual(s.board_mac('esp32s3-a0f262ebb558'),'a0:f2:62:eb:b5:58')
        for invalid in ('board','esp32s3','esp32s3-a0f262ebb55800'):
            with self.assertRaises(ValueError):s.board_mac(invalid)
    def test_bool_not_a_version(self):
        with self.assertRaises(RuntimeError):s.typed({'version':True},{'version':1},'gate')
    def test_no_flash_work_after_rejection(self):
        reply={'timing_schema':3,'timing_measured':True,'timing_executed_mask':1,'latency_us':5,'timing_us':{**{name:0 for name in s.STAGES},'candidate_verify':3,'total':4}}
        s.bundle_timing(reply,False)
        reply['timing_us']['journal_commit']=1
        with self.assertRaises(RuntimeError):s.bundle_timing(reply,False)
    def test_incomplete_timing_mask_rejected(self):
        reply={'timing_schema':3,'timing_measured':True,'timing_executed_mask':63,'latency_us':100,'timing_us':{**{name:1 for name in s.STAGES},'total':20}}
        with self.assertRaises(RuntimeError):s.bundle_timing(reply)
        reply['timing_executed_mask']=511;s.bundle_timing(reply)
    def test_path_traversal_rejected(self):
        for name in ('../private.pem','/tmp/any','tools\\other.py'):
            with self.assertRaises(ValueError):s.confined(ROOT,name)

if __name__=='__main__':unittest.main()
