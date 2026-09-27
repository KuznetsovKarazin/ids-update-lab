#!/usr/bin/env python3
"""Validate a complete stage025 series and summarize paired MCU erase costs.

Partial/failed runs and mixed kit/board provenance cannot produce final tables.
"""
from __future__ import annotations
import argparse
from collections import Counter
import importlib.util
import json
import math
from pathlib import Path
import random
import re
import statistics
import sys

ROOT=Path(__file__).resolve().parents[1]


def jsonlines(path):
    return [json.loads(row,parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Nonfinite JSON'))) for row in Path(path).read_text(encoding='utf-8').splitlines() if row.strip()]


def percentile(values,q):
    if not values or not 0<=q<=1 or not all(math.isfinite(v) for v in values):raise ValueError('Invalid percentile input')
    ordered=sorted(values);position=(len(ordered)-1)*q;lower=int(position);upper=min(lower+1,len(ordered)-1)
    return ordered[lower]+(ordered[upper]-ordered[lower])*(position-lower)


def describe(values):
    return {'n':len(values),'median':statistics.median(values),'p05':percentile(values,.05),'p95':percentile(values,.95),'min':min(values),'max':max(values)}


def paired_interval(differences,draws):
    medians=[statistics.median([differences[i] for i in indices]) for indices in draws]
    return {'estimate':statistics.median(differences),'lower':percentile(medians,.025),'upper':percentile(medians,.975),'confidence_level':.95,'method':'paired_block_percentile_bootstrap_median','bootstrap_resamples':len(draws),'seed':25092026,'assumption':'exchangeable time blocks on one board; no population-of-boards inference'}


def verify_evidence(directory,name,s):
    directory=Path(directory).resolve(); s.verify_evidence(directory,name);data=s.read_json(directory/name)
    files=data.get('sha256')
    if not isinstance(files,dict) or not files:raise ValueError('Missing evidence hashes')
    for relative,digest in files.items():
        path=(directory/relative).resolve()
        if not path.is_relative_to(directory) or '\\' in relative or '..' in Path(relative).parts or not path.is_file() or s.sha(path)!=digest:raise ValueError('Evidence hash mismatch '+relative)
    return files


def validate_trial(run,item,c,s,board_id,port):
    folder=run/item['path'];proof=verify_evidence(folder,'evidence_manifest.json',s)
    for name in ('summary.json','events.jsonl','observations.jsonl','transcript.jsonl','provisioning/identity.log','provisioning/write_factory-result.json','provisioning/erase_component_state-result.json'):
        if name not in proof:raise ValueError('Incomplete trial evidence '+name)
    summary=s.read_json(folder/'summary.json')
    s.typed(summary,{'stage':'025','command':'series','status':'complete','measurement_origin':'actual_mcu','trial':item,'configuration':c['configuration'],'board_id':board_id,'kit_manifest_sha256':c['kit_manifest_sha256'],'erase_policy':c['erase_policy'],'inferred_records':49,'label_mismatches':0,'accepted_updates':2,'verified_reboots':1,'faults_verified':0,'negative_controls_passed':0,'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False},'cost trial summary')
    rom=(folder/'provisioning/identity.log').read_text(encoding='utf-8')
    if {v.lower() for v in re.findall(r'MAC:\s*([0-9a-fA-F:]{17})',rom)}!={s.board_mac(board_id)} or 'ESP32-S3' not in rom:raise ValueError('Trial ROM board identity mismatch')
    for name in ('identity','write_factory','erase_component_state'):
        result=s.read_json(folder/'provisioning'/f'{name}-result.json');intent=s.read_json(folder/'provisioning'/f'{name}-intent.json')
        s.typed(result,{'returncode':0,'log_sha256':s.sha(folder/'provisioning'/f'{name}.log')},'provisioning result')
        argv=intent['argv']
        if argv[1:6]!=['-m','esptool','--chip','esp32s3','--port'] or len(argv)<8 or argv[6]!=port:raise ValueError('Wrong provisioning command')
        expected_tail={'identity':['--after','hard_reset','flash_id'],'write_factory':['-b','460800','--after','no_reset','write_flash','@flash_args'],'erase_component_state':['--after','hard_reset','erase_region','0x3b0000','0x22000']}[name]
        if argv[7:]!=expected_tail:raise ValueError('Wrong provisioning extent/action '+name)
    events=jsonlines(folder/'events.jsonl');observations=jsonlines(folder/'observations.jsonl');transcript=jsonlines(folder/'transcript.jsonl')
    received=[]
    for row in transcript:
        if row.get('direction')=='rx' and isinstance(row.get('line'),str):
            try:received.append(json.loads(row['line']))
            except ValueError:pass # Plain ESP boot text retained; Link's acceptance gate is authoritative.
    cost=[row for row in events if row.get('event')=='cost']
    if [row.get('model_key') for row in cost]!=['B','C']:raise ValueError('ExactlyB,C costs required')
    for row,key in zip(cost,'BC'):
        response=row['response'];s.typed(response,{'event':'update','accepted':True,'reason':'ok','ready':True,'version':c['models'][key].version,'policy':'bundle'},'raw update')
        timing=s.bundle_timing(response);counter=s.storage(response,c,key)
        s.typed(row,{'transition':'A_to_B_clean' if key=='B' else 'B_to_C_reused','configuration':c['configuration'],'erase_policy':c['erase_policy'],'timing_us':timing,'latency_us':response['latency_us'],'envelope_bytes':len(c['envelopes'][key]),'tx_wire_bytes':len(c['envelopes'][key])*2+8,**counter},'cost event')
        s.check_status(row['status_response'],c,key)
        if response not in received or row['status_response'] not in received:raise ValueError('Cost not linked to raw received transcript')
    boots=[row for row in events if row.get('event')=='reboot_verified']
    if len(boots)!=1:raise ValueError('One verified postC reboot required')
    s.check_status(boots[0]['boot_response'],c,'C','boot');s.check_status(boots[0]['response'],c,'C')
    if boots[0]['boot_response'] not in received:raise ValueError('Boot absent from transcript')
    starts=[row for row in events if row.get('event')=='verified_status']
    if len(starts)!=1:raise ValueError('Exactlyone factory status required')
    s.check_status(starts[0]['response'],c,'A')
    if len(observations)!=49:raise ValueError('49 inference observations required')
    expected_order=[(key,row['id']) for key in 'ABC' for row in c['golden'][:16]]+[('C',c['golden'][0]['id'])]
    if [(row['model_key'],row['record_id']) for row in observations]!=expected_order:raise ValueError('Wrong inference sequence or subset')
    golden={row['id']:row for row in c['golden']};max_error=0.
    for row in observations:
        ref=golden[row['record_id']];key=row['model_key'];response=row['response'];expected=ref['expected'][key]
        if row['raw']!=ref['raw'] or row['expected']!=expected:raise ValueError('Observation changes frozen input/reference')
        error,match=s.check_inference(response,c,key,expected)
        if not match or error>s.TOLERANCE or row.get('label_match') is not True or row.get('probability_abs_error')!=error:raise ValueError('Numerical mismatch')
        if response not in received:raise ValueError('Inference absent from raw transcript')
        max_error=max(error,max_error)
    if summary['max_probability_abs_error']!=max_error:raise ValueError('Trial maximum probability error mismatch')
    return summary,cost


def summarize(run,root,s,contexts):
    run=Path(run).resolve();evidence=verify_evidence(run,'run_evidence_manifest.json',s)
    if not {'campaign_manifest.json','summary.json','completed_trials.jsonl','preflight/status.json'}.issubset(evidence):raise ValueError('Incomplete root evidence')
    manifest=s.read_json(run/'campaign_manifest.json');summary=s.read_json(run/'summary.json')
    s.typed(manifest,{'stage':'025','command':'series','created_before_hardware':True,'kit_manifest_sha256':s.sha(root/'KIT_MANIFEST.json'),'protocol_sha256':s.sha(root/'protocol.json'),'source_pins':s.pins(root)},'campaign manifest')
    rows=s.plan('series')
    if manifest['trial_plan']!=rows:raise ValueError('Series plan differs from frozen120-chain plan')
    board=manifest['board_id'];s.board_mac(board)
    s.typed(summary,{'stage':'025','command':'series','status':'complete','measurement_origin':'actual_mcu','board_id':board,'kit_manifest_sha256':s.sha(root/'KIT_MANIFEST.json'),'planned_trials':120,'completed_trials':120,'attempted_trials':120,'inferred_records':5880,'label_mismatches':0,'accepted_updates':240,'verified_reboots':120,'faults_verified':0,'negative_controls_passed':0},'series summary')
    pilot=manifest.get('pilot_gate')
    if not isinstance(pilot,dict) or not re.fullmatch('[a-f0-9]{64}',str(pilot.get('manifest_sha256'))) or not re.fullmatch('[a-f0-9]{64}',str(pilot.get('summary_sha256'))):raise ValueError('Pilot gate was not recorded')
    # Pilot path can be a Windows path when archived elsewhere: hash-bound copies
    # of its manifest/summary are kept in series and checked below.
    for name,key in (('pilot_manifest.json','manifest_sha256'),('pilot_summary.json','summary_sha256')):
        if name not in evidence or s.sha(run/name)!=pilot[key]:raise ValueError('Pilot gate copy mismatch')
    s.typed(s.read_json(run/'pilot_summary.json'),{'status':'complete','measurement_origin':'actual_mcu','completed_trials':28,'faults_verified':24,'negative_controls_passed':32,'label_mismatches':0},'pilot copied summary')
    s.typed(s.read_json(run/'pilot_manifest.json'),{'board_id':board,'kit_manifest_sha256':s.sha(root/'KIT_MANIFEST.json'),'trial_plan':s.plan('pilot')},'pilot copied manifest')
    completed=jsonlines(run/'completed_trials.jsonl')
    if len(completed)!=120:raise ValueError('Completed trial index missing rows')
    values={};records=[];max_error=0.
    for item,logged in zip(rows,completed):
        c=contexts[item['configuration']];trial_summary,costs=validate_trial(run,item,c,s,board,manifest['port'])
        if logged.get('trial')!=item or logged.get('summary')!=trial_summary:raise ValueError('Trial index differs from trial file')
        max_error=max(max_error,trial_summary['max_probability_abs_error'])
        for cost in costs:
            key=(c['configuration'],cost['transition']);values.setdefault(key,[]).append({'block':item['block'],'position':item['position'],**cost})
            records.append({'configuration':c['configuration'],'block':item['block'],'position':item['position'],'transition':cost['transition'],'trial_path':item['path'],'timing_us':cost['timing_us'],'latency_us':cost['latency_us'],**{k:cost[k] for k in s.STORAGE_FIELDS}})
    if summary['max_probability_abs_error']!=max_error:raise ValueError('Series probability error aggregate mismatch')
    cells={}
    for (configuration,transition),items in sorted(values.items()):
        if len(items)!=30 or {r['block'] for r in items}!=set(range(1,31)):raise ValueError('Eachcell requires30 distinct blocks')
        cells[configuration+'/'+transition]={'n':30,'device_timing_us':{name:describe([row['timing_us'][name] for row in items]) for name in (*s.STAGES,'total')},'device_handler_latency_us':describe([row['latency_us'] for row in items]),'flash_request_bytes':{name:sorted({row[name] for row in items}) for name in s.STORAGE_FIELDS},'envelope_bytes':sorted({row['envelope_bytes'] for row in items})}
    rng=random.Random(25092026);draws=[[rng.randrange(30) for _ in range(30)] for _ in range(10000)];paired={}
    for family in ('lr','dt'):
        for transition in ('A_to_B_clean','B_to_C_reused'):
            full={row['block']:row for row in values[(family+'_full_slot',transition)]};necessary={row['block']:row for row in values[(family+'_necessary_sectors',transition)]}
            differences=[necessary[b]['timing_us']['total']-full[b]['timing_us']['total'] for b in range(1,31)]
            paired[family+'/'+transition]={'contrast':'necessary_sectors minus full_slot','unit':'microseconds','n_paired_blocks':30,'primary':transition=='B_to_C_reused','device_total_difference':describe(differences),'median_difference_ci95':paired_interval(differences,draws),'per_block_differences':differences}
    return {'status':'complete','stage':'025','measurement_origin':'actual_mcu','board_id':board,'source_run_manifest_sha256':s.sha(run/'campaign_manifest.json'),'source_evidence_manifest_sha256':s.sha(run/'run_evidence_manifest.json'),'kit_manifest_sha256':s.sha(root/'KIT_MANIFEST.json'),'cells':cells,'paired_comparisons':paired,'trial_count':120,'timed_updates':240,'inferred_records':5880,'label_mismatches':0,'max_probability_abs_error':max_error,'records':records,'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False,'inference_repeats_are_not_independent_samples':True,'flash_metrics_scope':'successful API request bytes; excludes provisioning, not physical wear','bootstrap_scope':'within this one-board ordered campaign, conditional on exchangeable blocks; primary2comparisons, no multiplicity-adjusted test'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',required=True);parser.add_argument('--output',required=True);args=parser.parse_args(argv)
    try:
        # Validate this script and runner before loading executable helper code.
        raw=json.loads((ROOT/'KIT_MANIFEST.json').read_text(encoding='utf-8'));files=raw.get('sha256',raw.get('files',raw))
        import hashlib
        for name in ('tools/summarize_erase025.py','tools/run_erase025.py'):
            if files.get(name)!=hashlib.sha256((ROOT/name).read_bytes()).hexdigest():raise ValueError('Unpinned summarizer/runner')
        spec=importlib.util.spec_from_file_location('erase025_verified_runner',ROOT/'tools/run_erase025.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        s,_,files=runner.bootstrap(ROOT);contexts={name:s.load_context(ROOT,name,files) for name in s.CONFIGURATIONS}
        output=Path(args.output).resolve()
        if output.exists():raise ValueError('Output directory alreadyexists; choose a fresh path')
        result=summarize(Path(args.run),ROOT,s,contexts);output.mkdir(parents=True,exist_ok=False);s.save(output/'summary.json',result)
        print(json.dumps({'status':'complete','output':str(output),'timed_updates':result['timed_updates'],'paired_comparisons':result['paired_comparisons']},allow_nan=False));return 0
    except Exception as exc:parser.exit(1,f'error: {type(exc).__name__}: {exc}\n')

if __name__=='__main__':raise SystemExit(main())
