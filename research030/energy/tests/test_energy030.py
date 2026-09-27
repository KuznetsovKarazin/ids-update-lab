import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import analyze_continuous as energy
from timeline import PATTERNS, EnergyTimeline

def fixture(scale=1.,offset=5.,noise=.0001):
    patterns=[]
    for (name,durations),start in zip(PATTERNS.items(),(20.,60.,240.,280.)):
        pulses=[]
        for duration in durations:
            pulses.append(dict(start_host_s=[start-.01,start+.01],
                               end_host_s=[start+duration-.01,start+duration+.01],
                               duration_device_s=duration))
            start+=duration+2
        patterns.append(dict(event='marker_pattern',marker_id=name,
                             role='calibration' if name.startswith('calibration') else 'validation',
                             pulses=pulses))
    tc=np.arange(offset,offset+320*scale,.01)
    host=(tc-offset)/scale
    power=.2+noise*np.sin(host*7.333)
    for pattern in patterns:
        for pulse in pattern['pulses']:
            a,b=energy.midpoint(pulse['start_host_s']),energy.midpoint(pulse['end_host_s'])
            power[(host>=a)&(host<b)]+=.05
    power[(host>=120)&(host<170)]+=.03
    baselines=[dict(event='baseline',id='pre',start_host_s=100.,end_host_s=110.),
               dict(event='baseline',id='post',start_host_s=180.,end_host_s=190.)]
    blocks=[dict(event='update_block',id='block',policy='bundle',accepted_updates=100,
                 baseline_ids=['pre','post'],start_host_s=120.,end_host_s=170.)]
    spec=dict(status='host_capture_complete',marker_patterns=patterns,
              baselines=baselines,blocks=blocks)
    return tc,power,spec

def write_cfn(path,t,p):
    descriptors=[0,1,4,6]
    header=struct.pack('<diiih',100.,0,0,5,len(descriptors))
    header+=b''.join(struct.pack('<hIB',x,0,0) for x in descriptors)
    header+=struct.pack('<i',len(t))
    rows=np.column_stack([t,np.full(len(t),5.),p/5,p,np.zeros(len(t))])
    path.write_bytes(header+rows.astype('<f8').tobytes())

def write_windows(root,spec):
    records=[*spec['marker_patterns'],*spec['baselines'],*spec['blocks'],dict(event='complete')]
    raw=('\n'.join(json.dumps(r) for r in records)+'\n').encode()
    (root/'timeline.jsonl').write_bytes(raw)
    spec=dict(spec,source_sha256=hashlib.sha256(raw).hexdigest())
    p=root/'energy_windows.json';p.write_text(json.dumps(spec));return p

class ClockAndEnergy(unittest.TestCase):
    def test_affine_clock_recovered_and_holdout_used_only_for_check(self):
        t,p,spec=fixture(scale=.251,offset=7.2)
        fit=energy.auto_align(t,p,spec)
        self.assertAlmostEqual(fit['cfn_seconds_per_host_second'],.251,places=4)
        self.assertAlmostEqual(fit['cfn_offset_s'],7.2,delta=.02)
        self.assertFalse(fit['pattern_quality']['validation_before']['used_to_fit_alignment'])
        self.assertTrue(fit['clock_mapping_verified_by_holdout_markers'])

    def test_missing_current_marker_refuses_alignment(self):
        t,p,spec=fixture();p[:]=.2
        with self.assertRaises(ValueError):energy.auto_align(t,p,spec)

    def test_shifted_holdout_refuses_even_good_calibration(self):
        t,p,spec=fixture()
        for edge in energy.edges(spec['marker_patterns'][1]):
            edge[0]+=1;edge[1]+=1
        with self.assertRaises(ValueError):energy.auto_align(t,p,spec)

    def test_duplicate_calibration_pattern_ambiguous(self):
        t,p,spec=fixture()
        for pulse in spec['marker_patterns'][0]['pulses']:
            a,b=energy.midpoint(pulse['start_host_s']),energy.midpoint(pulse['end_host_s'])
            p[(t>=a+5+70)&(t<b+5+70)]+=.05
        with self.assertRaises(ValueError):energy.auto_align(t,p,spec)

    def test_end_to_end_affine_integral_in_host_seconds(self):
        t,p,spec=fixture(scale=.251,offset=2.)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfn=root/'meter.cfn';write_cfn(cfn,t,p)
            windows=write_windows(root,spec)
            report=energy.analyze(cfn,windows,root/'analysis')
            block=report['blocks'][0]
            self.assertAlmostEqual(block['gross_UI_energy_J']['mid_offset_J'],11.5,delta=.02)
            self.assertAlmostEqual(block['net_UI_energy_J']['mid_offset_J'],1.5,delta=.02)
            self.assertTrue(block['additional_energy_resolved'])
            self.assertFalse(report['energy_NRG_factor_corrected'])
            # Deliberately constant NRG isn't repaired by empirical factor.
            self.assertFalse(report['decoder_diagnostics']['energy_counter_consistent_with_UI'])

    def test_original_timeline_binding_rejects_edited_windows(self):
        t,p,spec=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfn=root/'meter.cfn';write_cfn(cfn,t,p)
            windows=write_windows(root,spec)
            edited=json.loads(windows.read_text());edited['blocks'][0]['accepted_updates']=101
            windows.write_text(json.dumps(edited))
            with self.assertRaisesRegex(ValueError,'differ from original timeline'):
                energy.analyze(cfn,windows,root/'analysis')
            self.assertFalse(json.loads((root/'analysis/summary.json').read_text())['energy_measured'])

    def test_short_single_update_is_not_a_long_block(self):
        _,_,spec=fixture();spec['blocks'][0]['end_host_s']=120.04
        with self.assertRaisesRegex(ValueError,'shorter than 20'):
            energy.validate_windows(spec)

    def test_baselines_must_surround_not_overlap_event(self):
        _,_,spec=fixture();spec['baselines'][1]['start_host_s']=130
        with self.assertRaises(ValueError):energy.validate_windows(spec)

    def test_replay_zero_count_not_energy_update(self):
        _,_,spec=fixture();spec['blocks'][0]['accepted_updates']=0
        with self.assertRaises(ValueError):energy.validate_windows(spec)

    def test_interior_extremum_of_timing_uncertainty(self):
        curve=energy.Curve([0,1,2],[0,2,0])
        result=energy.shifted_bounds(curve,[(0,1,1)],0,1)
        self.assertAlmostEqual(result['max_J'],1.5)
        self.assertAlmostEqual(result['at_offset_max_s'],.5)

    def test_manual_placeholder_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'manual.json'
            p.write_text(json.dumps(dict(cfn_seconds_per_host_second=1,cfn_offset_s=0,
                host_boundary_uncertainty_s=.1,allowed_host_interval_s=[0,100],
                observed_evidence='FILL observed marker evidence here',
                independent_check_evidence='FILL independent marker check here')))
            with self.assertRaises(ValueError):energy.manual_align(p)

class CaptureContract(unittest.TestCase):
    def test_capture_four_markers_and_verified_block(self):
        class Clock:
            now=0.
            def sleep(self, seconds):self.now+=seconds
            def monotonic_ns(self):return round(self.now*1e9)
        clock=Clock()
        class Link:
            def command(self,line,expected):
                self_test.assertEqual(expected,{'energy_marker'})
                verb,ms=line.split();self_test.assertEqual(verb,'ENERGY_MARKER')
                clock.sleep(int(ms)/1000+.04)
                return dict(event='energy_marker',duration_us=int(ms)*1000)
        self_test=self
        with tempfile.TemporaryDirectory() as tmp, patch('timeline.time.sleep',clock.sleep),patch('timeline.time.monotonic_ns',clock.monotonic_ns):
            capture=EnergyTimeline(Path(tmp)/'energy');link=Link()
            capture.marker(link,'calibration_before');capture.marker(link,'validation_before')
            capture.baseline(label='pre')
            with capture.update_block('one','bundle',100,['pre','post']) as receipt:
                clock.sleep(31);receipt['accepted_updates']=100
            capture.baseline(label='post')
            capture.marker(link,'validation_after');capture.marker(link,'calibration_after')
            spec=capture.finish();energy.validate_windows(spec)
            self.assertEqual(len(spec['blocks']),1)
            self.assertFalse(spec['energy_measured'])
            for group in spec['marker_patterns']:
                for pulse in group['pulses']:
                    self.assertAlmostEqual(pulse['start_host_s'][1]-pulse['start_host_s'][0],.04,places=6)

    def test_wrong_accepted_count_marks_failure_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture=EnergyTimeline(Path(tmp)/'energy')
            with self.assertRaises(ValueError):
                with capture.update_block('one','bundle',100,['pre','post']) as receipt:
                    receipt['accepted_updates']=99
            self.assertEqual(capture.records[-1]['event'],'update_failed')
            with self.assertRaises(ValueError):capture.finish()

    def test_marker_duration_unverified_rejected(self):
        class Link:
            def command(self,line,expected):return dict(event='energy_marker',duration_us=10)
        with tempfile.TemporaryDirectory() as tmp,patch('timeline.time.sleep'):
            capture=EnergyTimeline(Path(tmp)/'energy')
            with self.assertRaisesRegex(ValueError,'Unverified MCU energy marker'):
                capture.marker(Link(),'calibration_before')

if __name__=='__main__':unittest.main()
