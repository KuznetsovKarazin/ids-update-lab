"""Stage025 storage validation. Host simulations/processes, never MCU evidence.

Run: python3 stage025/tests/test_storage025.py
Requires g++17 and OpenSSL development headers/library. Frozen LR/DT envelopes
are verified by the production OpenSSL backend; the separate adversarial model
uses an explicit authentication stub and real SHA-256 to isolate storage faults.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'validation/storage025'
CORE = ROOT / 'firmware/components/ids_core'
MODES = ('full_slot', 'necessary_sectors')
CHECKPOINTS = ('after_erase','after_write','after_verify','after_slot_commit','after_journal_body','after_commit')

class Storage025Tests(unittest.TestCase):
    report = {'measurement_origin':'native_host_NOT_MCU','physical_power_loss_tested':False,
              'hardware_access_attempted':False,'cases':[],'compile_commands':[]}
    @classmethod
    def compile(cls, output, sources, include):
        cmd=['g++','-std=c++17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-ffp-contract=off',
             '-I'+str(CORE/'include'),'-I'+str(include),*[str(x) for x in sources],'-lcrypto','-o',str(output)]
        result=subprocess.run(cmd,capture_output=True,text=True)
        cls.report['compile_commands'].append({'argv':cmd,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode: raise RuntimeError(result.stderr)
    @classmethod
    def setUpClass(cls):
        if not shutil.which('g++'): raise unittest.SkipTest('g++ with OpenSSL headers required')
        OUT.mkdir(parents=True,exist_ok=True)
        cls.tmp=tempfile.TemporaryDirectory();cls.build=Path(cls.tmp.name)
        cls.report['compiler']=subprocess.run(['g++','--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
        cls.bins={}
        for family in ('lr','dt'):
            inc=cls.build/family;inc.mkdir();(inc/'model_contract.h').write_bytes((ROOT/f'artifacts/{family}/headers/A.h').read_bytes())
            exe=inc/'native';cls.bins[family]=exe
            cls.compile(exe,[CORE/'ids_core.cpp',CORE/'ids_tree.cpp',CORE/'ids_protocol.cpp',ROOT/'firmware/native/main.cpp'],inc)
        cls.adversarial=cls.build/'adversarial'
        cls.compile(cls.adversarial,[CORE/'ids_core.cpp',CORE/'ids_tree.cpp',OUT/'adversarial_storage.cpp'],cls.build/'lr')
        cls.driver=cls.build/'driver'
        cls.compile(cls.driver,[CORE/'ids_core.cpp',CORE/'ids_tree.cpp',CORE/'ids_protocol.cpp',OUT/'file_driver.cpp'],cls.build/'lr')
        files=list(CORE.rglob('*.h'))+list(CORE.glob('*.cpp'))+[ROOT/'firmware/native/main.cpp',Path(__file__),OUT/'adversarial_storage.cpp',OUT/'file_driver.cpp']
        for family in ('lr','dt'):
            files.extend((ROOT/'artifacts'/family).glob('*.sids'));files.extend([ROOT/f'artifacts/{family}/golden.jsonl',ROOT/f'artifacts/{family}/headers/A.h'])
        cls.report['input_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}
    @classmethod
    def tearDownClass(cls):
        cls.report['case_count']=len(cls.report['cases'])
        (OUT/'result.json').write_text(json.dumps(cls.report,indent=2)+'\n')
        cls.tmp.cleanup()
    def process(self,family,mode,store,*commands):
        r=subprocess.run([str(self.bins[family]),'--store',str(store),'--erase-policy',mode],input='\n'.join(commands)+'\n',capture_output=True,text=True)
        self.assertIn(r.returncode,(0,75),r.stderr)
        return [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]
    def update(self,family,name):return 'UPDATE '+(ROOT/'artifacts'/family/name).read_bytes().hex()
    def check_status(self,status,version,mode):
        self.assertTrue(status['ready'],status);self.assertEqual(status['version'],version)
        self.assertEqual(status['erase_policy'],mode);self.assertEqual(status['chip'],'native_host_NOT_MCU')
    def test_adversarial_nor_both_policies(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                r=subprocess.run([str(self.adversarial),mode],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
                result=json.loads(r.stdout);self.assertEqual(result['status'],'pass');self.assertTrue(result['authentication_stubbed'])
                self.report['cases'].append({'test':'adversarial_nor',**result})
    def test_production_native_file_range_driver(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([str(self.driver),d],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.report['cases'].append({'test':'file_driver',**json.loads(r.stdout)})
    def test_frozen_signed_abc_golden_and_rejections(self):
        for family in ('lr','dt'):
            gold=[json.loads(s) for s in (ROOT/f'artifacts/{family}/golden.jsonl').read_text().splitlines()]
            for mode in MODES:
                with self.subTest(family=family,mode=mode),tempfile.TemporaryDirectory() as d:
                    commands=['STATUS'];expected=[]
                    for release in 'ABC':
                        if release!='A':commands.append(self.update(family,'release-'+release+'.sids'))
                        for row in gold:
                            commands.append('INFER '+','.join(format(float(x),'.9g') for x in row['raw']))
                            expected.append(row['expected'][release])
                    for name in ('bad-signature.sids','bad-contract.sids','release-C.sids'):
                        commands.append(self.update(family,name))
                    commands.append('STATUS');events=self.process(family,mode,Path(d),*commands)
                    self.check_status(events[-1],3,mode)
                    inferred=[e for e in events if e['event']=='inference'];self.assertEqual(len(inferred),len(expected))
                    errors=[]
                    for got,want in zip(inferred,expected):
                        self.assertEqual(got['label'],want['label']);errors.append(abs(got['probability']-want['probability']))
                    self.assertLessEqual(max(errors),2e-6)
                    updates=[e for e in events if e['event']=='update'];self.assertEqual(len(updates),5)
                    for idx,e in enumerate(updates[:2]):
                        n=len((ROOT/f'artifacts/{family}/release-{chr(66+idx)}.sids').read_bytes())
                        self.assertTrue(e['accepted'],e);self.assertEqual(e['storage_metrics_kind'],'successful_flash_request_bytes')
                        self.assertEqual(e['model_erase_bytes'],65536 if mode=='full_slot' else 4096)
                        self.assertEqual(e['model_write_bytes'],n+8);self.assertEqual(e['journal_erase_bytes'],0);self.assertEqual(e['journal_write_bytes'],128)
                    for e,reason in zip(updates[2:],('signature','feature_contract','replay_or_downgrade')):
                        self.assertFalse(e['accepted']);self.assertEqual(e['reason'],reason)
                        self.assertTrue(all(e[k]==0 for k in ('model_erase_bytes','model_write_bytes','journal_erase_bytes','journal_write_bytes')))
                    status=self.process(family,mode,Path(d),'STATUS')[-1];self.check_status(status,3,mode)
                    self.report['cases'].append({'test':'frozen_signed_abc','family':family,'erase_policy':mode,'inferred_records':len(inferred),'label_mismatches':0,'max_probability_abs_error':max(errors),'negative_controls':3})
    def test_six_checkpoints_clean_and_reused_real_signatures(self):
        for family in ('lr','dt'):
            for mode in MODES:
                for reused in (False,True):
                    for checkpoint in CHECKPOINTS:
                        with self.subTest(family=family,mode=mode,reused=reused,checkpoint=checkpoint),tempfile.TemporaryDirectory() as d:
                            store=Path(d);commands=[]
                            if reused:commands.append(self.update(family,'release-B.sids'))
                            commands.extend(['ARM_FAIL '+checkpoint,self.update(family,'release-C.sids' if reused else 'release-B.sids')])
                            events=self.process(family,mode,store,*commands)
                            self.assertTrue(any(e.get('event')=='fault_checkpoint' and e.get('checkpoint')==checkpoint and e.get('fault_kind')=='software_restart' for e in events),events)
                            status=self.process(family,mode,store,'STATUS')[-1]
                            old=2 if reused else 1;new=old+1;self.check_status(status,new if checkpoint=='after_commit' else old,mode)
                            if checkpoint!='after_commit':
                                status=self.process(family,mode,store,self.update(family,'release-C.sids' if reused else 'release-B.sids'),'STATUS')[-1]
                                self.check_status(status,new,mode)
                            self.report['cases'].append({'test':'signed_checkpoint','family':family,'erase_policy':mode,'target_state':'reused' if reused else 'clean','checkpoint':checkpoint,'recovery_version':new if checkpoint=='after_commit' else old})
    def test_corrupt_selected_fails_closed_and_inactive_partial_erase_recovers(self):
        for family in ('lr','dt'):
            for mode in MODES:
                with self.subTest(family=family,mode=mode),tempfile.TemporaryDirectory() as d:
                    store=Path(d);self.process(family,mode,store,self.update(family,'release-B.sids'))
                    old=store/'ids_a.bin';raw=old.read_bytes();torn=raw[:80]+b'\xff'*96+raw[176:];old.write_bytes(torn)
                    self.assertEqual(raw[:8],torn[:8]);self.check_status(self.process(family,mode,store,'STATUS')[-1],2,mode)
                    selected=store/'ids_b.bin';raw=bytearray(selected.read_bytes());raw[90]^=1;selected.write_bytes(raw)
                    status=self.process(family,mode,store)[0];self.assertFalse(status['ready']);self.assertEqual(status['reason'],'selected_slot_invalid')
                    self.report['cases'].append({'test':'signed_selected_binding','family':family,'erase_policy':mode,'inactive_partial_erase_recovers':True,'selected_corruption_fails_closed':True})

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Storage025Tests))
    Storage025Tests.report['status']='pass' if result.wasSuccessful() else 'failed'
    Storage025Tests.report['unittest_methods_run']=result.testsRun
    Storage025Tests.report['failures']=[str(x[0]) for x in result.failures+result.errors]
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'result.json').write_text(json.dumps(Storage025Tests.report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
