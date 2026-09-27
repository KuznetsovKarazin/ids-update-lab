"""Actual C++ process protocol checks; native timings NEVER count as MCU data.

Native tests adapt chip/build/crypto capability checks explicitly. They do not
alter returned data or substitute MCU identity. Production strict gates are
covered by the separately pinned inspection and gate tests.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'))
from ids_update_lab import package, tree_package, serial_runner

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
s=load(ROOT/'tools/campaign_support.py','support_test_native')
r=load(ROOT/'tools/run_completion.py','runner_test_native')

class NativeLinkTransport:
    executable=None;store=None;model_only=False
    def __init__(self,port,on_read=None):
        self.native=serial_runner.NativeTransport(self.executable,self.store,self.model_only);self.received_bytes=0
    def write(self,line):self.native.write(line)
    def readline(self,timeout):
        old=self.native.process
        line=self.native.readline(timeout)
        if old is not self.native.process:
            for stream in (old.stdin,old.stdout):
                if stream:stream.close()
        if line is not None:self.received_bytes+=len(line)+1
        return line
    def take_pending_fragment(self):return b''
    def close(self):
        self.native.close()
        for stream in (self.native.process.stdin,self.native.process.stdout):
            if stream:stream.close()

def native_status(reply,c,key,event='status'):
    m=c['models'][key]
    s.typed(reply,{'event':event,'ready':True,'reason':'ok','version':m.version,'release':m.release,'policy':c['policy'],'schema':c['schema'],'feature_count':8,'bundle_sha256':c['digests'][key],'chip':'native_host_NOT_MCU','build':'native-shared-core-v1','data_origin':'TON_IoT_development','runtime_abi':c['experiment']['runtime_abi'],'pretransform':c['experiment']['pretransform'],'storage_layout':2,'storage_scheme':'journal_dualrail_v1','timing_schema':3,'crypto_context':'unavailable','active_slot':0 if m.version in (1,3) else 1},'native_status')
    s.integer(reply,'selector_sequence')

class NativeCampaign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=ROOT/'validation/campaign';cls.build.mkdir(parents=True,exist_ok=True)
        cls.executables={};cls.results=[]
        for family in ('lr','dt'):
            inc=cls.build/family;inc.mkdir(exist_ok=True)
            (inc/'model_contract.h').write_bytes((ROOT/f'artifacts/{family}/headers/A.h').read_bytes())
            exe=inc/'native'
            command=['g++','-std=c++17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-ffp-contract=off','-I'+str(ROOT/'firmware/components/ids_core/include'),'-I'+str(inc),str(ROOT/'firmware/components/ids_core/ids_core.cpp'),str(ROOT/'firmware/components/ids_core/ids_protocol.cpp'),str(ROOT/'firmware/components/ids_core/ids_tree.cpp'),str(ROOT/'firmware/native/main.cpp'),'-lcrypto','-o',str(exe)]
            subprocess.run(command,check=True,capture_output=True,text=True);cls.executables[family]=exe
    @classmethod
    def tearDownClass(cls):
        s.save(ROOT/'validation/campaign_native_result.json',{'measurement_origin':'native_host_NOT_MCU','hardware_access_attempted':False,'cases':cls.results,'inferred_records':sum(x['inferred_records'] for x in cls.results),'label_mismatches':sum(x['label_mismatches'] for x in cls.results),'max_probability_abs_error':max((x['max_probability_abs_error'] for x in cls.results),default=0)})
    def context(self,family,compatible=False):
        directory=ROOT/'artifacts'/family;ex=s.read_json(directory/'experiment.json');api=package if family=='lr' else tree_package
        key=package.load_public(directory/'public.pem');blobs={k:(directory/m['package']).read_bytes() for k,m in ex['models'].items()}
        models={k:api.verify(v,key,bytes.fromhex(ex['schema_sha256']),8,expected_abi=ex['runtime_abi']) for k,v in blobs.items()}
        class Adapter(NativeLinkTransport):pass
        Adapter.executable=self.executables[family];Adapter.store=self.temp/'store';Adapter.model_only=compatible
        serial=types.SimpleNamespace(SerialTransport=Adapter,synchronize_serial=lambda transport,record,timeout:serial_runner.synchronize_serial(transport,record,timeout,startup_wait=.01,quiet_period=.001))
        return {'measurement_origin':'native_host_NOT_MCU','root':ROOT,'family':directory,'model_family':family,'policy_name':'compatible' if compatible else 'bundle','policy':s.POLICIES['compatible' if compatible else 'bundle'],'models':models,'envelopes':blobs,'digests':{k:m['payload_sha256'] for k,m in ex['models'].items()},'experiment':ex,'schema':ex['schema_sha256'],'serial':serial,'golden':[json.loads(l) for l in (directory/'golden.jsonl').read_text().splitlines()]}
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.temp=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def run_case(self,family,compatible=False,checkpoint=None,reused=False):
        c=self.context(family,compatible);out=self.temp/'run';out.mkdir()
        summary={'inferred_records':0,'label_mismatches':0,'max_probability_abs_error':0.,'accepted_updates':0,'verified_reboots':0,'faults_verified':0,'negative_controls_passed':0,'measurement_origin':'native_host_NOT_MCU'}
        native_support=types.SimpleNamespace(**{name:getattr(s,name) for name in dir(s) if not name.startswith('__')});native_support.check_status=native_status
        args=types.SimpleNamespace(port='native',timeout=5)
        t=r.Trial(args,native_support,c,out,summary)
        try:
            t.open('A')
            if checkpoint:
                if reused:t.update('B')
                recovered=t.update('C' if reused else 'B',checkpoint)
                t.infer(recovered,c['golden'][:8]);t.reject(c['envelopes']['A'],'replay_or_downgrade',recovered)
            else:
                t.infer('A',c['golden'])
                for letter in 'BC':
                    key=s.key_for(c,letter);t.update(key);t.infer(key,c['golden'])
                t.reboot(s.key_for(c,'C'));t.infer(s.key_for(c,'C'),c['golden'][:1])
                self.assertEqual(summary['inferred_records'],775)
                for kind,reason in [('signature','signature'),('contract','feature_contract')]:t.reject((c['family']/('bad-'+kind+'.sids')).read_bytes(),reason,s.key_for(c,'C'))
                t.reject(c['envelopes']['C'],'replay_or_downgrade',s.key_for(c,'C'))
            self.assertEqual(summary['label_mismatches'],0)
            self.assertLessEqual(summary['max_probability_abs_error'],2e-6)
            # Trial.open labels live transport MCU; rewrite explicitly for this
            # native-only test report before any persisted aggregate or return.
            summary['measurement_origin']='native_host_NOT_MCU'
            self.results.append({'family':family,'compatible':compatible,'checkpoint':checkpoint,'reused':reused,**summary})
            return summary
        finally:t.close()
    def test_lr_smoke_and_security_real_core(self):self.run_case('lr')
    def test_lr_compatible_smoke_and_security_real_core(self):self.run_case('lr',True)
    def test_dt_smoke_and_security_real_core(self):self.run_case('dt')
    def test_all_fault_checkpoints_and_conditions_real_core(self):
        for family in ('lr','dt'):
            for checkpoint in s.CHECKPOINTS:
                for reused in (False,True):
                    with self.subTest(family=family,checkpoint=checkpoint,reused=reused):
                        with tempfile.TemporaryDirectory() as d:
                            self.temp=Path(d);self.run_case(family,checkpoint=checkpoint,reused=reused)

if __name__=='__main__':unittest.main()
