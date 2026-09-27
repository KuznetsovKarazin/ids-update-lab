"""Host gate/regression tests. Native subprocess evidence is explicitly not MCU."""
from __future__ import annotations
from collections import Counter
import copy
import importlib.util
import json
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

s=module('support025_tests',ROOT/'tools/erase_support025.py');s.load_base(ROOT)
r=module('runner025_tests',ROOT/'tools/run_erase025.py')
z=module('summarizer025_tests',ROOT/'tools/summarize_erase025.py')
old=module('immutable025_tests',ROOT/'tools/run_completion.py')


def context(mode='necessary_sectors',n=448):
    return {'erase_policy':mode,'configuration':'lr_'+mode,'envelopes':{'B':bytes(n),'C':bytes(n)},'models':{'B':SimpleNamespace(version=2),'C':SimpleNamespace(version=3)},'policy':'bundle'}


def reply(mode='necessary_sectors',accepted=True):
    row={'event':'update','accepted':accepted,'reason':'ok' if accepted else 'signature','ready':True,'version':2 if accepted else 3,'policy':'bundle','timing_schema':3,'timing_measured':True,'timing_executed_mask':511 if accepted else 1,'timing_us':{**{k:1 if accepted or k=='candidate_verify' else 0 for k in s.STAGES},'total':9 if accepted else 1},'latency_us':10 if accepted else 2,'erase_policy':mode,'model_slot_capacity_bytes':65536,'erase_sector_bytes':4096,'storage_metrics_schema':1,'storage_metrics_kind':'successful_flash_request_bytes'}
    row.update(s.expected_storage(448,mode) if accepted else {k:0 for k in s.STORAGE_FIELDS});return row

class PlanTests(unittest.TestCase):
    def test_balanced_series_every_pair_each_position(self):
        rows=s.plan('series');self.assertEqual(len(rows),120)
        byblock={b:[r['configuration'] for r in rows if r['block']==b] for b in range(1,31)}
        for c in s.CONFIGURATIONS:
            self.assertEqual(sum(row['configuration']==c for row in rows),30)
            positions=Counter(row['position'] for row in rows if row['configuration']==c)
            self.assertEqual(sorted(positions.values()),[7,7,8,8])
        for i,a in enumerate(s.CONFIGURATIONS):
            for b in s.CONFIGURATIONS[i+1:]:self.assertEqual(sum(order.index(a)<order.index(b) for order in byblock.values()),15)
        self.assertEqual(len({row['path'] for row in rows}),120)
    def test_pilot_all_reused_checkpoints_once(self):
        rows=s.plan('pilot');self.assertEqual(len(rows),28)
        for config in s.CONFIGURATIONS:
            part=[row for row in rows if row['configuration']==config]
            self.assertEqual(sum(row['kind']=='smoke' for row in part),1)
            self.assertEqual([row['checkpoint'] for row in part if row['kind']=='fault'],list(s.CHECKPOINTS))
            self.assertTrue(all(row['target_condition']=='reused' for row in part if row['kind']=='fault'))
    def test_erase_boundary_includes_eight_byte_header(self):
        self.assertEqual(s.expected_storage(4088,'necessary_sectors')['model_erase_bytes'],4096)
        self.assertEqual(s.expected_storage(4089,'necessary_sectors')['model_erase_bytes'],8192)
        self.assertEqual(s.expected_storage(4096,'necessary_sectors')['model_erase_bytes'],8192)
        self.assertEqual(s.expected_storage(1168,'full_slot')['model_write_bytes'],1176)
        for n in (True,0,15,4097,65528):
            with self.assertRaises(ValueError):s.expected_storage(n,'necessary_sectors')
    def test_preflight_accepts_recognized020_high_version(self):
        entry=next(iter(s.read_json(ROOT/'reference020/BUILD_METADATA.json')['configurations'].values()))
        status={'event':'status','ready':True,'chip':'esp32s3','build':entry['images']['A']['expected_build'],'version':10070}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'reference020').mkdir();(root/'reference020/BUILD_METADATA.json').write_bytes((ROOT/'reference020/BUILD_METADATA.json').read_bytes());s.save(root/'BUILD_METADATA.json',{'configurations':{}})
            self.assertEqual(s.known_status(status,root)['version'],10070)
            for change in ({'chip':'native_host_NOT_MCU'},{'build':'unknown'},{'ready':False},{'version':True}):
                with self.assertRaises(RuntimeError):s.known_status({**status,**change},root)
    def test_evidence_hash_and_unlisted_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'data.json').write_text('{}');s.save(root/'proof.json',{'sha256':{'data.json':s.sha(root/'data.json')}})
            s.verify_evidence(root,'proof.json');(root/'extra.txt').write_text('unlisted')
            with self.assertRaises(ValueError):s.verify_evidence(root,'proof.json')
            (root/'extra.txt').unlink();(root/'data.json').write_text('{"tampered":true}')
            with self.assertRaises(ValueError):s.verify_evidence(root,'proof.json')

class TelemetryTests(unittest.TestCase):
    def test_accepted_request_counts_and_stage_sum(self):
        row=reply();self.assertEqual(s.storage(row,context(),'B')['model_erase_bytes'],4096);s.bundle_timing(row)
        for field,value in (('model_erase_bytes',65536),('model_write_bytes',448),('journal_erase_bytes',4096),('journal_write_bytes',124),('model_slot_capacity_bytes',4096),('erase_sector_bytes',65536),('storage_metrics_schema',True)):
            with self.subTest(field=field),self.assertRaises(RuntimeError):s.storage({**row,field:value},context(),'B')
        wrong=copy.deepcopy(row);wrong['timing_us']['total']=8
        with self.assertRaises(RuntimeError):s.bundle_timing(wrong)
    def test_negative_has_no_flash_operations(self):
        row=reply(accepted=False);s.storage(row,context(),accepted=False);s.bundle_timing(row,accepted=False)
        for field in s.STORAGE_FIELDS:
            with self.subTest(field=field),self.assertRaises(RuntimeError):s.storage({**row,field:1},context(),accepted=False)
    def make_trial(self,row):
        Trial=r.trial_class(old);t=Trial.__new__(Trial);t.s=s;t.c=context();t.summary=r.empty_summary('series');t.phase='B'
        t.link=SimpleNamespace(command=lambda line,expected:row)
        t.events=[];t.evidence=SimpleNamespace(event=lambda event,**kw:t.events.append({'event':event,**kw}))
        t.status=lambda key:{'checked':key};return t
    def test_fake_link_update_links_raw_reply_and_counters(self):
        row=reply();t=self.make_trial(row);self.assertEqual(t.update('B'),'B');self.assertEqual(t.summary['accepted_updates'],1)
        costs=[e for e in t.events if e['event']=='cost'];self.assertEqual(len(costs),1);self.assertEqual(costs[0]['response'],row);self.assertEqual(costs[0]['model_write_bytes'],456)
    def test_invalid_telemetry_stops_without_count_or_retry(self):
        row=reply();row['model_erase_bytes']=65536;t=self.make_trial(row);commands=[]
        t.link.command=lambda line,expected:(commands.append(line) or row)
        with self.assertRaises(RuntimeError):t.update('B')
        self.assertEqual(len(commands),1);self.assertEqual(t.summary['accepted_updates'],0);self.assertFalse(any(e['event']=='cost' for e in t.events))
    def test_unmeasured_timing_cannot_be_claimed_measured(self):
        row=reply();row['timing_measured']=False
        with self.assertRaises(RuntimeError):s.bundle_timing(row)
    def test_native_identity_cannot_pass_mcu_status_gate(self):
        row={'event':'status','ready':True,'chip':'native_host_NOT_MCU'}
        with self.assertRaises((RuntimeError,KeyError)):s.check_status(row,context(),'B')

class SummaryTests(unittest.TestCase):
    def test_quantile_and_paired_bootstrap(self):
        self.assertEqual(z.percentile([0,10],.05),.5);self.assertEqual(z.describe([1,2,3])['median'],2)
        rng=random.Random(25092026);draws=[[rng.randrange(30) for _ in range(30)] for _ in range(100)]
        interval=z.paired_interval([-20]*30,draws)
        self.assertEqual((interval['estimate'],interval['lower'],interval['upper']),(-20,-20,-20))
        # Pairing must be by block, not each configuration's serial position.
        full={1:100,2:1000,3:10};necessary={3:8,1:80,2:800}
        self.assertEqual([necessary[b]-full[b] for b in sorted(full)],[-20,-200,-2])
    def test_failed_run_cannot_yield_complete_tables(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);s.save(root/'summary.json',{'status':'failed'})
            s.save(root/'run_evidence_manifest.json',{'sha256':{'summary.json':s.sha(root/'summary.json')}})
            with self.assertRaises(ValueError):z.summarize(root,ROOT,s,{})

class EndToEndSummaryTests(unittest.TestCase):
    def test_full_fixture_and_swapped_condition_gate(self):
        # Temporary, prominently marked synthetic fixture; never delivered as MCU evidence.
        from unittest.mock import patch
        fixture=module('fake_series025',ROOT/'tests/fake_series025.py')
        with tempfile.TemporaryDirectory() as d:
            kit,run,contexts,pins,proof=fixture.write_fixture(Path(d),s)
            with patch.object(s,'pins',return_value=pins):
                result=z.summarize(run,kit,s,contexts)
                self.assertEqual(result['timed_updates'],240)
                self.assertEqual(result['paired_comparisons']['lr/B_to_C_reused']['median_difference_ci95']['estimate'],-90)
                self.assertEqual(result['paired_comparisons']['dt/B_to_C_reused']['median_difference_ci95']['lower'],-90)
                # Rehash a semantic mutation: must fail independently of checksum guards.
                first=s.plan('series')[0];folder=run/first['path'];events=z.jsonlines(folder/'events.jsonl')
                for event in events:
                    if event.get('event')=='cost' and event['model_key']=='B':event['transition']='B_to_C_reused'
                (folder/'events.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in events))
                proof(folder,'evidence_manifest.json');proof(run,'run_evidence_manifest.json')
                with self.assertRaises(RuntimeError):z.summarize(run,kit,s,contexts)

@unittest.skipUnless(shutil.which('g++'),'Native semantic check requires g++ and OpenSSL headers; host-only gates above still run')
class NativeSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name);inc=cls.root/'include';inc.mkdir()
        (inc/'model_contract.h').write_bytes((ROOT/'artifacts/lr/headers/A.h').read_bytes());cls.exe=cls.root/'native';core=ROOT/'firmware/components/ids_core'
        command=['g++','-std=c++17','-O2','-ffp-contract=off','-I'+str(core/'include'),'-I'+str(inc),str(core/'ids_core.cpp'),str(core/'ids_tree.cpp'),str(core/'ids_protocol.cpp'),str(ROOT/'firmware/native/main.cpp'),'-lcrypto','-o',str(cls.exe)]
        completed=subprocess.run(command,capture_output=True,text=True)
        if completed.returncode:raise RuntimeError(completed.stderr)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_real_engine_abc_sequences_and_storage_gate(self):
        for mode in ('full_slot','necessary_sectors'):
            with self.subTest(mode=mode):
                store=self.root/mode;commands=['STATUS','UPDATE '+(ROOT/'artifacts/lr/release-B.sids').read_bytes().hex(),'STATUS','UPDATE '+(ROOT/'artifacts/lr/release-C.sids').read_bytes().hex(),'STATUS']
                result=subprocess.run([str(self.exe),'--store',str(store),'--erase-policy',mode],input='\n'.join(commands)+'\n',capture_output=True,text=True,check=True)
                events=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')];statuses=[row for row in events if row['event']=='status']
                self.assertEqual([row['selector_sequence'] for row in statuses],[1,2,3])
                c=context(mode)
                for key,status in zip('ABC',statuses):
                    self.assertEqual(status['chip'],'native_host_NOT_MCU');s.check_storage_status(status,c,key)
                for key,row in zip('BC',[row for row in events if row['event']=='update']):
                    s.storage(row,c,key)
                    # Native uses a real host timer with the same timing schema.
                    # Provenance is gated on STATUS identity, not numerical timings.
                    s.bundle_timing(row)
                reboot=subprocess.run([str(self.exe),'--store',str(store),'--erase-policy',mode],input='STATUS\n',capture_output=True,text=True,check=True)
                status=json.loads(reboot.stdout.splitlines()[-1]);s.check_storage_status(status,c,'C')

if __name__=='__main__':unittest.main(verbosity=2)
