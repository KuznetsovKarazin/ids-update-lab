"""Independent recovery regressions plus the unchanged 030 test suite."""
import sys,unittest,json,tempfile,hashlib
from pathlib import Path
import numpy as np
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import recover_energy031 as repair
sys.path.insert(0,str(Path('research030/energy/tests').resolve()))
import test_energy030 as old_tests
old_match=old_tests.energy.match_pattern
old_tests.energy.match_pattern=repair.match_pattern_antialias

class Recovery(unittest.TestCase):
 def test_sampling_derived_filter_not_energy_tuned(self):
  self.assertEqual(repair.antialias_width(.08,.01),9)
  self.assertEqual(repair.antialias_width(.08,.04),3)
  self.assertEqual(repair.antialias_width(.08,.1),1)
  self.assertEqual(repair.antialias_width(.09,.01),9)
 def test_intermittent_load_pulses_recover_original_clock(self):
  t,p,spec=old_tests.fixture()
  host=t-5
  # Known 40ms busy + 10ms idle scheduler duty cycle; realistic deep troughs
  # make point-sampled rectangle matching unnecessarily noisy.
  for pat in spec['marker_patterns']:
   for pulse in pat['pulses']:
    a,b=old_tests.energy.midpoint(pulse['start_host_s']),old_tests.energy.midpoint(pulse['end_host_s'])
    dip=(host>=a)&(host<b)&(((host-a)%0.05)>=.04)
    p[dip]-=.05
  r=old_tests.energy.auto_align(t,p,spec)
  self.assertAlmostEqual(r['cfn_seconds_per_host_second'],1,places=4)
  self.assertAlmostEqual(r['cfn_offset_s'],5,delta=.02)
  self.assertTrue(r['clock_mapping_verified_by_holdout_markers'])
 def test_match_does_not_modify_input_power(self):
  t,p,spec=old_tests.fixture();prior=p.copy()
  repair.match_pattern_antialias(t,p,spec['marker_patterns'][0])
  np.testing.assert_array_equal(p,prior)
 def test_hash_mismatch_fails_closed(self):
  import tempfile
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'energy').mkdir();(root/'energy/analyze_continuous.py').write_text('# changed')
   with self.assertRaisesRegex(ValueError,'Frozen analyzer dependency differs'):
    repair.load_frozen(root)
 def hardware_fixture(self,root,updates=1,accepted=True,status='complete'):
  hardware=root/'hardware';hardware.mkdir()
  block=dict(id='one',family='lr',policy='bundle',block=1,accepted_updates=1)
  files={'summary.json':json.dumps(dict(status=status,measurement_origin='actual_mcu',label_mismatches=0,board_id='test')),
         'energy/energy_windows.json':json.dumps(dict(blocks=[block])),
         'energy/timeline.jsonl':'not parsed by binding helper\n',
         'campaign_before_hardware.json':json.dumps(dict(cost_plan=[dict(id='one',family='lr',policy='bundle',block=1,updates=updates)])),
         'costs/one/events.jsonl':json.dumps(dict(event='cost',phase='one',family='lr',policy='bundle',version=3,response=dict(accepted=accepted)))+'\n'}
  manifest={}
  for name,text in files.items():
   path=hardware/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
   manifest[name]=repair.sha256(path)
  (hardware/'evidence_manifest.json').write_text(json.dumps(dict(sha256=manifest)))
  return hardware
 def test_verified_receipts_bind_energy_divisor(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);self.hardware_fixture(root)
   report=repair.verify_hardware_binding(root)
   self.assertEqual(report['measured_accepted_update_receipts'],1)
 def test_hardware_hash_change_refused(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);hardware=self.hardware_fixture(root)
   (hardware/'energy/energy_windows.json').write_text('{}')
   with self.assertRaisesRegex(ValueError,'Hardware evidence hash mismatch'):
    repair.verify_hardware_binding(root)
 def test_planned_divisor_mismatch_refused(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);self.hardware_fixture(root,updates=2)
   with self.assertRaisesRegex(ValueError,'differs from planned'):
    repair.verify_hardware_binding(root)
 def test_rejected_update_receipt_refused(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);self.hardware_fixture(root,accepted=False)
   with self.assertRaisesRegex(ValueError,'Unaccepted bundle'):
    repair.verify_hardware_binding(root)

if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(old_tests),unittest.defaultTestLoader.loadTestsFromTestCase(Recovery)])
 r=unittest.TextTestRunner(verbosity=2).run(suite)
 raise SystemExit(not r.wasSuccessful())
