"""Extract publication data from preserved reports and verify primary serial receipts.
Run from any directory: python paper033/analysis/build_hardware_evidence.py
The full archived research workspace is needed to rebuild this JSON. Figure generation
itself needs only hardware_evidence.json and plot_hardware.py.
"""
import json, hashlib, statistics
from pathlib import Path
from collections import Counter
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).with_name('hardware_evidence.json')
def read(rel): return json.loads((ROOT/rel).read_text())
def lines(p): return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
SOURCES = ['review030/hardware_audit.json', 'review030/input/ids-completion-030/analysis/costs.json', 'review030/input/ids-completion-030/hardware/summary.json', 'review025/stats_recomputed.json', 'review020/faults/faults_audit.json', 'recovery031/results/summary.json', 'recovery031/results/aggregate_descriptive.json', 'recovery031/results/repair_provenance.json', 'recovery031/review/alignment/alignment_review.json']
audit,cost,summary,erase,fa020,energy,agg,repair,align=[read(p) for p in SOURCES]
assert summary['status']=='complete' and len(cost['primary_rows'])==80
primary=[]; measured=0; raw_sources=[]; all_update_events=[]; reboot=[]
for r in cost['primary_rows']:
 p=ROOT/'review030/input/ids-completion-030/hardware/costs'/r['id']/'events.jsonl'
 ev=lines(p); raw_sources.append(p.relative_to(ROOT).as_posix())
 costs=[e for e in ev if e['event']=='cost' and e['phase']==r['id']]
 assert len(costs)==r['updates']
 prim=[e for e in costs if e['primary']]; assert len(prim)==1
 e=prim[0]
 assert e['transition']=='B_to_C_reused' and e['version']==3
 assert e['host_elapsed_ns']==r['host_elapsed_ns'] and e['tx_wire_bytes']==r['tx_wire_bytes']
 if r['policy']=='bundle':
  assert e['response']['accepted'] and e['timing_us']['total']==r['device_active_us']
  assert e['envelope_bytes']==r['payload_or_image_bytes']
  receipts=[x for x in ev if x['phase']==r['id'] and x.get('command_kind')=='UPDATE' and x.get('response',{}).get('accepted') is True]
 else:
  assert e['ready']['device_active_us']==r['device_active_us'] and e['image_bytes']==r['payload_or_image_bytes']
  assert e['ready']['device_active_us']==e['begin']['begin_us']+e['ready']['chunk_sum_us']+e['ready']['finalize_us']
  receipts=[x for x in ev if x['phase']==r['id'] and x.get('response',{}).get('event')=='fw_ready' and x['response'].get('ok')]
  reboot += [dict(id=r['id'], **{k:v for k,v in x.items() if k in ['version','command_to_boot_ns','command_to_status_ns']}) for x in ev if x['phase']==r['id'] and x['event']=='reboot_verified' and x['version']==3]
 assert len(receipts)==r['updates']; measured+=len(receipts)
 # Independently bind each event receipt to the raw decoded serial transcript.
 tr=p.with_name('transcript.jsonl')
 raw_responses=[]
 for x in lines(tr):
  if x.get('direction')=='rx':
   try: raw_responses.append(json.loads(x['line']))
   except (ValueError,KeyError):pass
 counts=Counter(json.dumps(x,sort_keys=True) for x in raw_responses)
 for x in receipts:
  key=json.dumps(x['response'],sort_keys=True)
  assert counts[key]>0;counts[key]-=1
 primary.append(r)
 for c in costs:
  if c['policy']=='bundle':
   all_update_events.append({'id':r['id'],'version':c['version'],'model_erase_bytes':c['response']['model_erase_bytes'],'journal_erase_bytes':c['response']['journal_erase_bytes'],'model_write_bytes':c['response']['model_write_bytes'],'journal_write_bytes':c['response']['journal_write_bytes']})
assert measured==5280==repair['hardware_binding']['measured_accepted_update_receipts']
assert len(reboot)==40
# Explicit receipts for all four model families and all six checkpoints.
faults030=[]
for p in (ROOT/'review030/input/ids-completion-030/hardware/faults').rglob('events.jsonl'):
 ev=lines(p); f=[e for e in ev if e['event']=='fault_verified'];assert len(f)==1
 f=f[0];assert f['recovered_version']==(3 if f['checkpoint']=='after_commit' else 2)
 statuses=[e['response'] for e in ev if e.get('response',{}).get('event')=='status']
 assert statuses[-1]['version']==f['recovered_version'] and statuses[-1]['ready']
 faults030.append({'family':p.parent.parent.name,'checkpoint':f['checkpoint'],'n':1,'recovered_version':f['recovered_version'],'source':p.relative_to(ROOT).as_posix()})
assert len(faults030)==24
faults025=[]
for p in (ROOT/'review025/input/esp32-erase-025-pilot').glob('*fault/summary.json'):
 s=json.loads(p.read_text());assert s['status']=='complete' and s['faults_verified']==1
 faults025.append({'configuration':s['configuration'],'checkpoint':s['trial']['checkpoint'],'target_condition':s['trial']['target_condition'],'n':1,'source':p.relative_to(ROOT).as_posix()})
assert len(faults025)==24
for f in fa020['fault_trials']:
 assert f['recovered_model']==(('B' if f['target_condition']=='clean' else 'C') if f['checkpoint']=='after_commit' else ('A' if f['target_condition']=='clean' else 'B'))
# Recompute energy aggregates from each of the 80 integrals; keep timing/baseline
# envelopes separate from across-block sampling variability.
energy_points=[]
for b in energy['blocks']:
 n=b['accepted_updates']; assert n==(128 if b['policy']=='bundle' else 4)
 energy_points.append({'id':b['id'],'family':b['family'],'policy':b['policy'],'block':b['block'],'accepted_updates':n,'duration_s':b['elapsed_host_s'],'gross_mJ_per_update':1000*b['gross_UI_energy_J']['mid_offset_J']/n,'net_mJ_per_update':1000*b['net_UI_energy_J']['mid_offset_J']/n,'net_sensitivity_mJ_per_update':[1000*x/n for x in b['net_timing_and_baseline_sensitivity_J']]})
for a in agg['rows']:
 p=[x for x in energy_points if x['family']==a['family'] and x['policy']==a['policy']]
 assert len(p)==10
 for m in ['gross','net']:
  assert abs(statistics.median(x[f'{m}_mJ_per_update'] for x in p)-a[f'median_{m}_mJ_per_update'])<1e-8
assert len(energy_points)==80
result={
 'schema':'paper033_hardware_evidence_v1',
 'provenance': [{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in SOURCES],
 'verification':{'cost_primary_rows_bound_to_events':80,'energy_window_receipts_bound_to_raw_serial':measured,'software_fault030_status_verified':24,'energy_aggregate_cells_recomputed':8,'hardware_access_attempted':False},
 'campaign030':summary,
 'cost030':{'scope':cost['metric_scope'],'host_scope':cost['host_metric_scope'],'primary_rows':primary,'comparisons':cost['comparisons'],'resources_and_inference':cost['resources_and_inference'],'reboot_primary':reboot,'image_bytes_excludes_manifest_and_signature':339504,'whole_signed_artifact_bytes':339844,'whole_metadata_bytes':84,'whole_signature_bytes':256,'raw_event_sources':raw_sources,'long_block_flash_requests':{'bundle_updates':len(all_update_events),'model_erase_bytes':sum(x['model_erase_bytes'] for x in all_update_events),'journal_erase_bytes':sum(x['journal_erase_bytes'] for x in all_update_events),'model_write_bytes':sum(x['model_write_bytes'] for x in all_update_events),'journal_write_bytes':sum(x['journal_write_bytes'] for x in all_update_events)}},
 'erase025':{k:erase[k] for k in ['series_counts','pilot_counts','cells','paired','records','bootstrap','limitations']},
 'software_faults':{'stage020_cells':fa020['checkpoint_cells'],'stage020_trials':240,'stage020_old_recovered':fa020['fault_recovery_old_model'],'stage020_new_recovered':fa020['fault_recovery_new_model'],'stage020_dedicated_negative_controls':150,'stage025_cells':faults025,'stage030_cells':faults030,'physical_power_loss_tested':False,'pooled_reliability_estimate_permitted':False},
 'energy031':{'estimand':agg['estimand'],'aggregates':agg['rows'],'block_points':energy_points,'alignment':align['clock'],'posthoc_repair_kind':repair['analysis_kind'],'measurement_accuracy_calibrated':False,'independent_sampling_rate_verified':False,'nominal_recording_rate_sps':100,'duplicate_UI_fraction':align['duplicate_UI_fraction'],'original_cfn_sha256':repair['original_cfn_sha256'],'energy_NRG_factor_corrected':False,'raw_UI_used_for_energy':True,'limitations':energy['limitations']},
 'cautions':['One physical ESP32-S3; blocks are technical repetitions.','Raw FNB58 U/I integration is exploratory, not calibrated metrology.','Different firmware campaigns 020/025/030 must not be pooled as repetitions of the same setup.','Physical power cuts, secure boot, eFuse anti-rollback and invalid-application rollback were not tested.','No model lifetime prediction from requested flash bytes; no peak RAM claim from response-point free heap.']}
OUT.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'output':str(OUT),'verification':result['verification'],'long_block_flash':result['cost030']['long_block_flash_requests']}))
