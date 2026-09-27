import importlib.util,csv,json,math,struct,sys,tempfile,unittest
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import evaluate_external as ex
import energy_analysis as en
import powercut_runner as pc
import generate_energy_windows as gw
from cfn_parser import decode
class External(unittest.TestCase):
    def test_signed_zero_same_fingerprint(self):
        self.assertEqual(ex.fingerprints([[0.,1.]])[0],ex.fingerprints([[-0.,1.]])[0])
    def test_representable_float_difference(self):
        self.assertNotEqual(ex.fingerprints([[1.,2.]])[0],ex.fingerprints([[1.,2.000001]])[0])
    def test_overlap_full_known_source(self):
        path=ROOT/'artifacts/known_input_fingerprints.npz'
        with np.load(path,allow_pickle=False) as k:self.assertEqual(int(k['source_rows']),211043);self.assertEqual(len(k['fingerprints']),92330)
    def test_strict_labels(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.csv';p.write_text('x,label\n1,attack\n')
            with self.assertRaises(ValueError):ex.read_csv(p,['x'])
    def test_reject_negative(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.csv';p.write_text('x,label\n-1,0\n')
            with self.assertRaises(ValueError):ex.read_csv(p,['x'])
    def test_bootstrap_pairing(self):
        pred=np.array([[0,0],[1,1],[0,0],[1,1]]);y=np.array([0,1,0,1]);groups=np.array([0,0,1,1])
        count,p,ci,dci,bad=ex.bootstrap(pred,y,groups,0,20,7)
        self.assertEqual(bad,0);self.assertTrue((dci==0).all());self.assertTrue((p[:,0]==1).all())
    def test_full_frozen_evaluation_declared_groups_and_uppercase_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'synthetic_only.csv';p=json.loads((ROOT/'external_protocol.json').read_text())
            with source.open('w') as f:
                writer=csv.writer(f);writer.writerow(p['feature_names']+['label','session'])
                for i in range(100):writer.writerow([500001.25+i,600001+i,700001+i,800001+i,900001+i,1000001+i,1100001+i,1200001+i]+[i%2,'session_'+str(i//10)])
            prov=json.loads((ROOT/'docs/external_provenance_TEMPLATE.json').read_text())
            for key in ('source_name','source_url_or_accession','collection_session','acquisition_date','feature_extraction_description'):prov[key]='Synthetic software test fixture only'
            for key in ('used_to_fit_any_model','used_to_select_threshold_or_protocol','same_collection_session_as_development'):prov[key]=False
            prov.update(feature_semantics_verified=True,source_sha256=ex.sha(source).upper(),bootstrap_group_column='session',bootstrap_group_description='Synthetic ten independent fixture groups only')
            (root/'p.json').write_text(json.dumps(prov));report=ex.evaluate(source,root/'p.json',root/'out')
            self.assertEqual(report['status'],'complete');self.assertEqual(len(report['models']),10);self.assertEqual(report['bootstrap_clusters'],10);self.assertEqual(report['bootstrap_grouping'],'declared_session');self.assertEqual(report['undefined_bootstrap_draws'],0)
    def test_degenerate_draws_not_resampled(self):
        pred=np.array([[0],[1]]);y=np.array([0,1]);groups=np.array([0,1]);result=ex.bootstrap(pred,y,groups,0,100,7)
        self.assertIsNone(result[2]);self.assertGreater(result[-1],0)
class Energy(unittest.TestCase):
    def test_constant_power(self):
        c=en.Curve([0,1,2,3],[2,2,2,2]);b=en.shifted_bounds(c,[(.5,1.5,1)],0,1)
        self.assertEqual(b['min_J'],2);self.assertEqual(b['max_J'],2)
    def test_interior_extremum(self):
        c=en.Curve([0,1,2],[0,2,0]);b=en.shifted_bounds(c,[(0,1,1)],0,1)
        self.assertAlmostEqual(b['min_J'],1);self.assertAlmostEqual(b['max_J'],1.5);self.assertAlmostEqual(b['at_offset_max_s'],.5)
    def test_net_exact_baseline(self):
        c=en.Curve([0,1,2,3,4],[2,2,2,2,2]);b=en.shifted_bounds(c,[(2,3,1),(0,1,-1)],0,.5)
        self.assertEqual(b['max_J'],0);self.assertEqual(b['min_J'],0)
    def test_out_of_range_fails(self):
        with self.assertRaises(ValueError):en.shifted_bounds(en.Curve([0,1],[1,1]),[(0,1,1)],-.1,0)
    def test_overlap_windows_rejected(self):
        s={'baseline_windows_host_s':[[0,2]],'events':[{'id':'a','host_start_s':1,'host_end_s':3}],'cfn_time_minus_host_relative_time_s':[0,1],'alignment_method':'manual_record_start_interval','alignment_evidence':'manual measured bracket'}
        with self.assertRaises(ValueError):en.validate_windows(s)
    def test_cfn_units_are_unmodified(self):
        channels=[(0,5),(1,.04),(6,.001)]
        h=struct.pack('<diiih',10.,0,0,5,3)+b''.join(struct.pack('<hIB',k,0,0) for k,v in channels)+struct.pack('<i',2)
        payload=h+struct.pack('<dddd',0,5,.04,0)+struct.pack('<dddd',.1,5,.04,.001)
        meta,rows=decode(payload);self.assertEqual(rows[-1]['reported_energy_Wh'],.001)
class PhysicalGate(unittest.TestCase):
    def test_unconfirmed_wiring_rejected(self):
        with self.assertRaises(ValueError):pc.validate_wiring({'protocol':'ids-power-wiring-v1'})
    def test_complete_wiring_declaration(self):
        names=('external_switch_accepts_3v3_enable','load_voltage_5V','active_high_enable','common_ground','no_USB_VBUS_bypass','no_other_power_path','esp_not_powered_by_gpio','data_path_available_when_powered')
        w=dict.fromkeys(names,True);w.update(protocol='ids-power-wiring-v1',controller_pin=15,switch_model='documented_external_load_switch',verification_notes='Verified physically before applying power')
        pc.validate_wiring(w)

class EnergyWindows(unittest.TestCase):
    def test_generator_freezes_host_windows_and_excludes_restore(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);trial=r/'run/trial-001';trial.mkdir(parents=True)
            (trial/'summary.json').write_text(json.dumps({'command':'costs','status':'complete'}))
            rows=[{'event':'energy_baseline','related_update_key':'B','monotonic_start_ns':10_000_000_000,'monotonic_end_ns':20_000_000_000,'utc_start_ns':100_000_000_000}, {'event':'update_interval','model_key':'B','policy':'whole_firmware','accepted_updates':1,'monotonic_start_ns':21_000_000_000,'monotonic_end_ns':51_000_000_000}]
            (trial/'events.jsonl').write_text('\n'.join(map(json.dumps,rows)))
            gw.generate(r/'run',r/'w.json');spec=json.loads((r/'w.json').read_text())
            self.assertEqual(spec['events'][0]['host_start_s'],11);self.assertEqual(spec['events'][0]['host_end_s'],41)
            with self.assertRaises(ValueError):en.validate_windows(spec)
            spec['cfn_time_minus_host_relative_time_s']=[0,1];spec['alignment_evidence']='observed marker with one second bracket';en.validate_windows(spec)
            spec['events'][0]['host_end_s']=40
            with self.assertRaises(ValueError):en.validate_windows(spec)
    def test_placeholder_rejected(self):
        spec=json.loads((ROOT/'docs/energy_windows_TEMPLATE.json').read_text())
        with self.assertRaises(ValueError):en.validate_windows(spec)

if __name__=='__main__':unittest.main()
