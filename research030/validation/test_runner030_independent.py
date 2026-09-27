"""Host mock tests of stage030 evidence gates. No serial device is accessed."""
import copy
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('runner030_audit',ROOT/'research030/tools/hardware030.py')
h=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(h)

class Evidence:
    def __init__(self):self.records=[];self.phase='test'
    def event(self,event,**kwargs):self.records.append(dict(event=event,**kwargs))
    def record(self,record,stream=None):self.records.append(dict(record,stream=stream))

class Link:
    def __init__(self,replies):self.replies=list(replies);self.commands=[];self.allow_reconnect=False
    def command(self,line,expected):
        self.commands.append(line)
        if not self.replies:raise AssertionError('Unexpected extra command '+line)
        r=self.replies.pop(0)
        if r['event'] not in expected:raise RuntimeError('Wrong mock protocol event')
        return r
    def receive(self,expected):
        r=self.replies.pop(0)
        if r['event'] not in expected:raise RuntimeError('Wrong mock boot event')
        return r

class RunnerAudit(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def session(self,policy='bundle'):
        s=h.Session.__new__(h.Session);s.family='lr';s.policy=policy;s.version=1;s.summary=h.empty_summary();s.evidence=Evidence()
        versions={}
        for v in (1,2,3):
            p=self.root/f'v{v}.sids';p.write_bytes(bytes([v])*300)
            versions[str(v)]=dict(version=v,release=f'release{v}',path=p.name,payload_sha256=f'payload{v}',reference='A' if v==1 else 'B',identity={'runtime_abi':2,'schema':'schema030','pretransform':'log1p'})
        images={}
        for v in (1,2,3):
            p=self.root/f'v{v}.bin';p.write_bytes(bytes([v])*2200)
            images[str(v)]=dict(path=p.name,expected_build=f'build-{v}',ota={'metadata_hex':'11'*84,'signature_hex':'22'*256})
        s.f=dict(versions=versions,policies={'bundle':{'images':{'1':images['1']}},'whole':{'images':images}},bad_contract='v3.sids')
        s.artifacts={'root':self.root};s.gold={'raw':[[0]*8],'expected':{'A':[{'probability':.25,'label':0}],'B':[{'probability':.75,'label':1}]}}
        return s
    def test_each_family_has_five_policy_orders(self):
        plan=h.cost_plan()
        self.assertEqual(len(plan),80)
        for f in h.FAMILIES:
            starts=[x['policy'] for x in plan if x['family']==f][::2]
            self.assertEqual(starts.count('bundle'),5,f)
            self.assertEqual(starts.count('whole'),5,f)
        self.assertEqual(len({x['id'] for x in plan}),80)
        for x in plan:self.assertEqual(x['updates'],h.BUNDLE_UPDATES if x['policy']=='bundle' else h.WHOLE_UPDATES)
    def test_typed_does_not_accept_bool_as_integer(self):
        with self.assertRaises(RuntimeError):h.typed({'version':True},{'version':1},'test')
    def test_prepared_evidence_modification_rejected(self):
        p=self.root/'image.bin';p.write_bytes(b'original image');h.pins(self.root)
        h.verify_pins(self.root)
        p.write_bytes(b'changed image')
        with self.assertRaises(ValueError):h.verify_pins(self.root)
    def test_manifest_path_escape_rejected(self):
        d=self.root/'evidence';d.mkdir();outside=self.root/'outside.bin';outside.write_bytes(b'x')
        (d/'evidence_manifest.json').write_text(json.dumps({'sha256':{'../outside.bin':h.sha(outside)}}))
        with self.assertRaises(ValueError):h.verify_pins(d)
    def test_cost_analyzer_rejects_mock_origin(self):
        directory=self.root/'hardware';directory.mkdir()
        (directory/'summary.json').write_text(json.dumps({'status':'complete','measurement_origin':'host_mock','label_mismatches':0}))
        h.pins(directory)
        with self.assertRaises(RuntimeError):h.analyze_costs(directory,self.root/'costs.json')
        self.assertFalse((self.root/'costs.json').exists())
    def test_status_rejects_other_policy_and_payload(self):
        for key,value in [('policy','whole_firmware'),('bundle_sha256','wrong'),('version',2),('build','wrong')]:
            s=self.session();r=s.identity(1);r[key]=value;s.link=Link([r])
            with self.assertRaises(RuntimeError):s.status()
            self.assertEqual(s.summary['accepted_updates'],0)
    def test_inference_mismatch_is_recorded_and_stops(self):
        s=self.session();s.link=Link([dict(event='inference',version=1,policy='bundle',bundle_sha256='payload1',probability=.9,label=1)])
        with self.assertRaises(RuntimeError):s.infer(1)
        self.assertEqual(s.summary['inferred_records'],1);self.assertEqual(s.summary['label_mismatches'],1)
        self.assertEqual(s.evidence.records[-1]['stream'],'observations')
    def bundle_reply(self):
        t={k:1 for k in h.TIMING_STAGES};t['total']=10
        return dict(event='update',accepted=True,reason='ok',ready=True,version=2,policy='bundle',timing_schema=3,timing_measured=True,storage_metrics_schema=1,storage_metrics_kind='successful_flash_request_bytes',timing_us=t,latency_us=12,model_erase_bytes=4096,model_write_bytes=308,journal_erase_bytes=0,journal_write_bytes=128)
    def test_accepted_reply_alone_not_counted_without_status(self):
        s=self.session();bad=s.identity(2);bad['bundle_sha256']='wrong';s.link=Link([self.bundle_reply(),bad])
        with self.assertRaises(RuntimeError):s.bundle(2)
        self.assertEqual(s.summary['accepted_updates'],0)
        self.assertFalse(any(x.get('event')=='cost' for x in s.evidence.records))
    def test_inconsistent_timing_rejected_before_state_advance(self):
        s=self.session();r=self.bundle_reply();r['timing_us']['total']=1;s.link=Link([r])
        with self.assertRaises(RuntimeError):s.bundle(2)
        self.assertEqual(s.version,1);self.assertEqual(s.summary['accepted_updates'],0)
    def test_negative_needs_explicit_right_reason(self):
        s=self.session();s.link=Link([dict(event='update',accepted=False,ready=True,version=1,reason='storage_error')])
        with self.assertRaises(RuntimeError):s.reject('replay')
        self.assertEqual(s.summary['negative_controls_passed'],0)
    def ota_replies(self,s,wrong_boot=False):
        begin=dict(event='fw_begin',ok=True,version=2,size=2200,timing_schema=2,crypto_context='shared_warm',signature_verify_us=2,partition_prepare_us=3,begin_us=6)
        chunks=[dict(event='fw_chunk',ok=True,offset=o,timing_schema=2,write_us=2,hash_us=1,chunk_us=4,write_sum_us=2*i,hash_sum_us=i,chunk_sum_us=4*i,chunk_count=i) for i,o in enumerate([1024,2048,2200],1)]
        ready=dict(event='fw_ready',ok=True,version=2,bytes=2200,reboot_required=True,timing_schema=2,begin_us=6,write_sum_us=6,hash_sum_us=3,chunk_sum_us=12,chunk_count=3,finalize_us=5,device_active_us=23)
        boot=s.identity(2,'boot')
        if wrong_boot:boot['bundle_sha256']='different_pipeline'
        return [begin,*chunks,ready,s.identity(1),dict(event='reboot',fault_kind='software_restart'),boot,s.identity(2)]
    def test_whole_counts_only_after_matching_boot(self):
        s=self.session('whole');s.link=Link(self.ota_replies(s));s.whole(2)
        self.assertEqual(s.summary['accepted_updates'],1);self.assertEqual(s.summary['verified_reboots'],1)
        self.assertEqual(s.version,2);self.assertEqual(len([x for x in s.evidence.records if x['event']=='cost']),1)
        self.assertFalse(s.link.allow_reconnect)
    def test_selected_wrong_image_not_counted(self):
        s=self.session('whole');s.link=Link(self.ota_replies(s,True))
        with self.assertRaises(RuntimeError):s.whole(2)
        self.assertEqual(s.summary['accepted_updates'],0);self.assertEqual(s.summary['verified_reboots'],0)
        self.assertFalse(s.link.allow_reconnect)
    def test_provision_failure_stops_and_preserves_failed_summary(self):
        artifacts=self.root/'art';artifacts.mkdir()
        (artifacts/'golden.json').write_text(json.dumps({'raw':[[0]*8]*20}))
        (artifacts/'artifacts.json').write_text(json.dumps({'validation_only_synthetic':False,'families':{f:{'variants':[],'golden':'golden.json'} for f in h.FAMILIES}}));h.pins(artifacts)
        args=SimpleNamespace(board_id='esp32s3-a0f262ebb558',no_energy=True,port='MOCK',timeout=1)
        # No real provision or serial call can escape this guard.
        with patch.object(h,'provision',side_effect=RuntimeError('forced first provisioning failure')) as provision:
            with self.assertRaises(RuntimeError):h.hardware(args,artifacts,self.root/'out')
            self.assertEqual(provision.call_count,1)
        got=json.loads((self.root/'out/summary.json').read_text())
        self.assertEqual(got['status'],'failed');self.assertEqual(got['measurement_origin'],'not_measured')
        self.assertEqual(got['completed_trials'],0);self.assertEqual(got['accepted_updates'],0)
        with self.assertRaises(FileExistsError):h.hardware(args,artifacts,self.root/'out')
    def test_complete_mock_queue_has_distinct_warmed_versions_and_exact_counts(self):
        artifacts=self.root/'art';artifacts.mkdir();families={}
        for i,family in enumerate(h.FAMILIES):
            p=artifacts/(family+'.json');p.write_text(json.dumps({'raw':[[0]*8]*(1+8*i)}))
            families[family]={'variants':[{'model':family+'_variant','version':201}] if i%2 else [],'golden':p.name}
        (artifacts/'artifacts.json').write_text(json.dumps({'validation_only_synthetic':False,'families':families}));h.pins(artifacts)
        receipts=[]
        class MockSession:
            def __init__(self,args,out,art,family,policy,summary):
                self.f=art['families'][family];self.g=len(h.read(art['root']/self.f['golden'])['raw']);self.summary=summary;self.version=1;self.policy=policy;self.phase_name='correctness'
            def open(self):self.summary['measurement_origin']='host_mock'
            def close(self):pass
            def phase(self,p):self.phase_name=p
            def status(self):return None
            def infer(self,v,count=None):
                if v!=self.version:raise AssertionError('Inference of wrong active version')
                self.summary['inferred_records']+=self.g if count is None else min(self.g,count)
            def reboot(self,v):
                if v!=self.version:raise AssertionError('Reboot of wrong version')
                self.summary['verified_reboots']+=1
            def reject(self,kind):self.summary['negative_controls_passed']+=1
            def bundle(self,v,checkpoint=None):
                if v<=self.version:raise AssertionError('Mutation repeats old version')
                if checkpoint:
                    if checkpoint=='after_commit':self.version=v
                    self.summary['faults_verified']+=1;self.summary['verified_reboots']+=1
                else:
                    self.version=v;self.summary['accepted_updates']+=1;receipts.append((self.phase_name,v))
            def whole(self,v,negative=None):
                if negative:
                    if negative=='replay' and v!=self.version:raise AssertionError('Replay test of wrong version')
                    self.summary['negative_controls_passed']+=1;return
                if v<=self.version:raise AssertionError('OTA repeats old version')
                self.version=v;self.summary['accepted_updates']+=1;self.summary['verified_reboots']+=1;receipts.append((self.phase_name,v))
        args=SimpleNamespace(board_id='esp32s3-a0f262ebb558',no_energy=True,port='MOCK',timeout=1)
        with patch.object(h,'provision'),patch.object(h,'Session',MockSession),patch.object(h.time,'sleep'),contextlib.redirect_stdout(io.StringIO()):
            got=h.hardware(args,artifacts,self.root/'out')
        self.assertEqual(got['status'],'complete');self.assertEqual(got['measurement_origin'],'host_mock')
        self.assertEqual(got['completed_trials'],112)
        for cell in h.cost_plan():
            self.assertEqual([v for phase,v in receipts if phase==cell['id']+'-warmup'],[2])
            self.assertEqual([v for phase,v in receipts if phase==cell['id']],list(range(3,cell['updates']+3)))

if __name__=='__main__':unittest.main(verbosity=2)
