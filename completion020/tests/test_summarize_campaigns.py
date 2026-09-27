"""Synthetic temporary fixtures only. These tests are NOT hardware evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('analysis020',Path(__file__).resolve().parents[1]/'tools/summarize_campaigns.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value),encoding='utf-8')


def events(policy='bundle',base=100,schema=3):
    out=[]
    for i,(phase,letter) in enumerate([('B_clean','B'),('C_reused','C')]):
        value=base+i;timing={k:1 for k in a.STAGES};timing['total']=value
        key=('compatible_'+letter) if policy=='compatible' else letter
        reply={'event':'update','accepted':True,'timing_schema':schema,'timing_measured':True,'timing_executed_mask':511,'latency_us':value+3,'timing_us':timing}
        out.append({'event':'command_response','phase':phase,'command_kind':'UPDATE','host_roundtrip_ns':25000000,'tx_wire_bytes':904,'response':reply})
        out.append({'event':'update_interval','phase':phase,'model_key':key,'accepted_updates':1,'monotonic_start_ns':100,'monotonic_end_ns':27000100})
        out.append({'event':'cost','phase':phase,'kind':'component','model_key':key,'envelope_bytes':448,'payload_bytes':176,'tx_wire_bytes':904,'timing_us':timing,'source_erase_bytes':65536,'source_model_write_bytes':456,'journal_record_bytes':128})
    return out


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'runs';self.root.mkdir();self.output=Path(self.temp.name)/'analysis'
    def manifest(self,directory,items,**extra):
        manifest={'stage':'020','created_before_hardware':True,'command':'costs','model_family':'lr','policy':'bundle','board_id':'esp32s3-a0f262ebb558','kit_manifest_sha256':'1'*64,'trial_plan':items,'test_data_description':'SYNTHETIC UNIT TEST FIXTURE, NOT HARDWARE EVIDENCE',**extra}
        save(directory/'campaign_manifest.json',manifest)
    def trial(self,directory,item,status='complete',policy='bundle',base=100,schema=3,origin='actual_mcu'):
        summary={'stage':'020','command':'costs','model_family':'lr','policy':a.POLICIES[policy],'trial':item,'status':status,'measurement_origin':origin}
        save(directory/'summary.json',summary)
        (directory/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events(policy,base,schema)),encoding='utf-8')
    def test_all_planned_failure_missing_incomplete_and_success_count(self):
        directory=self.root/'cost';items=[{'trial':i,'replicate':i} for i in range(1,5)];self.manifest(directory,items)
        self.trial(directory/'trial-001',items[0]);self.trial(directory/'trial-002',items[1],status='failed');(directory/'trial-004').mkdir()
        result=a.analyze(self.root,self.output)
        self.assertEqual(result['planned_trials'],4)
        self.assertEqual(result['trial_states'],{'completed':1,'failed':1,'missing':1,'incomplete':1})
        self.assertEqual(len(result['cost_groups']),2)
        self.assertEqual(result['cost_groups'][0]['n_trials'],1)
        self.assertEqual(result['cost_groups'][0]['metrics']['host_update_exchange_ns']['median'],25000000)
        self.assertNotIn('inference_latency_us',result['cost_groups'][0]['metrics'])
    def test_historical_schema_and_native_never_pool(self):
        directory=self.root/'cost';items=[{'trial':i} for i in range(1,4)];self.manifest(directory,items)
        self.trial(directory/'trial-001',items[0],schema=2)
        self.trial(directory/'trial-002',items[1],origin='native_host_NOT_MCU')
        self.trial(directory/'trial-003',items[2])
        self.manifest(self.root/'old',[{'trial':1}],stage='019')
        result=a.analyze(self.root,self.output)
        self.assertEqual(result['trial_states'],{'invalid':2,'completed':1})
        self.assertEqual(len(result['excluded_campaigns']),1)
        self.assertTrue(all(g['n_trials']==1 for g in result['cost_groups']))
    def test_duplicate_cost_event_invalidates_entire_trial(self):
        directory=self.root/'cost';item={'trial':1};self.manifest(directory,[item]);self.trial(directory/'trial-001',item)
        p=directory/'trial-001/events.jsonl';p.write_text(p.read_text()+json.dumps(events()[-1])+'\n')
        result=a.analyze(self.root,self.output)
        self.assertEqual(result['trial_states'],{'invalid':1});self.assertEqual(result['cost_groups'],[])
    def test_balanced_master_only_pairs_complete_explicit_blocks(self):
        directory=self.root/'suite';tasks=[]
        for block in (1,2,3):
            for policy in ('bundle','compatible'):
                task={'task':len(tasks)+1,'command':'costs','model':'lr','policy':policy,'phase':'cost','block':block,'position':1 if policy=='bundle' else 2,'trial':block,'replicate':block}
                tasks.append(task)
                self.trial(directory/f"task-{task['task']:03d}-lr-{policy}-costs",task,policy=policy,base=100+block+(10 if policy=='compatible' else 0))
        self.manifest(directory,[],command='costs-suite',tasks=tasks)
        result=a.analyze(self.root,self.output)
        selected=[x for x in result['paired_comparisons'] if x['metric']=='mcu_update_work_us']
        self.assertEqual(len(selected),2)
        for r in selected:
            self.assertEqual(r['estimate_second_minus_first'],10);self.assertEqual(r['ci95_percentile'],[10,10]);self.assertEqual(r['n_blocks'],3)
    def test_missing_master_trial_prevents_completecase_pairing(self):
        directory=self.root/'suite';tasks=[]
        for block in (1,2):
            for policy in ('bundle','compatible'):
                task={'task':len(tasks)+1,'command':'costs','model':'lr','policy':policy,'phase':'cost','block':block,'trial':block,'replicate':block};tasks.append(task)
                if not(block==2 and policy=='compatible'):self.trial(directory/f"task-{task['task']:03d}-lr-{policy}-costs",task,policy=policy)
        self.manifest(directory,[],command='costs-suite',tasks=tasks)
        result=a.analyze(self.root,self.output)
        self.assertEqual(result['trial_states']['missing'],1);self.assertEqual(result['paired_comparisons'],[]);self.assertEqual(len(result['pairing_exclusions']),2)
    def test_standalone_rep_numbers_never_make_pairs_or_pool(self):
        for policy in ('bundle','compatible'):
            directory=self.root/policy;items=[{'trial':1},{'trial':2}];self.manifest(directory,items,policy=a.POLICIES[policy])
            for item in items:self.trial(directory/f"trial-{item['trial']:03d}",item,policy=policy)
        result=a.analyze(self.root,self.output)
        self.assertEqual(result['paired_comparisons'],[]);self.assertEqual(len(result['cost_groups']),4)
    def test_no_overwrite_and_no_mutation_of_input(self):
        directory=self.root/'cost';item={'trial':1};self.manifest(directory,[item]);self.trial(directory/'trial-001',item)
        before={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        a.analyze(self.root,self.output)
        self.assertEqual(before,{p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        with self.assertRaises(FileExistsError):a.analyze(self.root,self.output)
    def test_quantiles_and_pair_sign(self):
        self.assertEqual(a.percentile([0,10],.1),1)
        self.assertEqual(a.stats([1,2,3])['median'],2)
        result=a.paired_ci({1:20,2:30},{1:10,2:20})
        self.assertEqual(result['estimate_second_minus_first'],-10)
        with self.assertRaises(ValueError):a.paired_ci({1:1},{2:1})
    def test_whole_accounting_requires_explicit_omitted_metadata(self):
        cost={'begin':{'timing_schema':2,'crypto_context':'shared_warm','signature_verify_us':2,'partition_prepare_us':30,'begin_us':40},'ready':{'timing_schema':2,'begin_us':40,'write_sum_us':100,'hash_sum_us':20,'chunk_sum_us':150,'finalize_us':10,'device_active_us':200},'host_transfer_ns':9999,'image_bytes':320000,'tx_wire_bytes':661000,'image_partition_erase_bytes':323584,'image_partition_write_bytes':320000,'otadata_accounted':False}
        value=a.whole_measurements(cost)
        self.assertEqual(value['mcu_update_work_us'],200);self.assertEqual(value['image_partition_write_bytes'],320000)
        del cost['otadata_accounted']
        with self.assertRaises(ValueError):a.whole_measurements(cost)

if __name__=='__main__':unittest.main()
