#!/usr/bin/env python3
"""Read-only completion020 campaign analysis; fresh output, no serial access.

Requires campaign_manifest.json, uses its complete plan including missing trials.
Historical stages and native simulations never enter MCU cost summaries.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import statistics
import sys

SEED=24092026
BOOTSTRAPS=2000
STAGES=('candidate_verify','erase','body_write','readback','readback_verify','commit','journal_prepare','journal_body','journal_commit')
POLICIES={'bundle':'bundle','compatible':'model_only_factory_preprocess','whole':'whole_firmware'}
TRANSITIONS={'B_clean':('A_to_B','clean'),'C_reused':('B_to_C','reused')}


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'),parse_constant=lambda s: (_ for _ in ()).throw(ValueError('Nonfinite JSON '+s)))


def number(value, name):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0:raise ValueError('Invalid nonnegative measurement '+name)
    return value


def integer(value, name):
    if type(value) is not int or value<0:raise ValueError('Invalid nonnegative integer '+name)
    return value


def percentile(values,q):
    ordered=sorted(values)
    if not ordered:raise ValueError('Empty sample')
    position=(len(ordered)-1)*q;low=math.floor(position);high=math.ceil(position)
    return ordered[low]+(ordered[high]-ordered[low])*(position-low)


def stats(values):
    return {'n':len(values),'median':statistics.median(values),'p10':percentile(values,.1),'p25':percentile(values,.25),'p75':percentile(values,.75),'p90':percentile(values,.9),'min':min(values),'max':max(values)}


def paired_ci(first,second):
    if set(first)!=set(second) or len(first)<2:raise ValueError('Paired bootstrap requires equal explicit block IDs and at least two blocks')
    blocks=sorted(first); differences=[second[b]-first[b] for b in blocks]
    rng=random.Random(SEED)
    boot=[statistics.median(rng.choices(differences,k=len(differences))) for _ in range(BOOTSTRAPS)]
    return {'n_blocks':len(blocks),'estimate_second_minus_first':statistics.median(differences),'ci95_percentile':[percentile(boot,.025),percentile(boot,.975)],'resamples':BOOTSTRAPS,'seed':SEED,'statistic':'median of within-block differences; whole blocks resampled'}


def component_measurements(cost,phase_events):
    commands=[e for e in phase_events if e.get('event')=='command_response' and e.get('command_kind')=='UPDATE' and e.get('response',{}).get('accepted') is True]
    if len(commands)!=1:raise ValueError('Need exactly one accepted UPDATE response per cost phase')
    response=commands[0]['response'];timings=cost['timing_us']
    if response.get('timing_schema')!=3 or response.get('timing_measured') is not True or response.get('timing_executed_mask')!=511:raise ValueError('Require measured component timing schema3, mask511')
    if response.get('timing_us')!=timings or set(timings)!=set(STAGES)|{'total'}:raise ValueError('Cost does not match raw UPDATE timing stages')
    for key,value in timings.items():integer(value,key)
    elapsed=integer(response.get('latency_us'),'latency_us')
    if sum(timings[k] for k in STAGES)>timings['total'] or timings['total']>elapsed:raise ValueError('Inconsistent component intervals')
    out={'mcu_update_work_us':timings['total'],'mcu_component_engine_us':timings['total'],'mcu_update_command_us':elapsed,'host_update_exchange_ns':integer(commands[0].get('host_roundtrip_ns'),'host_roundtrip_ns')}
    out.update({'mcu_stage_'+k+'_us':timings[k] for k in STAGES})
    for key in ('envelope_bytes','payload_bytes','tx_wire_bytes','source_erase_bytes','source_model_write_bytes','journal_record_bytes'):
        out[key]=integer(cost.get(key),key)
    if cost['tx_wire_bytes']!=commands[0].get('tx_wire_bytes'):raise ValueError('Wire bytes do not match UPDATE command record')
    return out


def whole_measurements(cost):
    begin,ready=cost['begin'],cost['ready']
    if begin.get('timing_schema')!=2 or ready.get('timing_schema')!=2:raise ValueError('Require whole OTA timing schema2 inside completion020')
    if begin.get('crypto_context')!='shared_warm':raise ValueError('Whole OTA key context is not the completion020 warm context')
    out={}
    for key in ('signature_verify_us','partition_prepare_us','begin_us'):
        out['mcu_ota_'+key]=integer(begin.get(key),key)
    for key in ('write_sum_us','hash_sum_us','chunk_sum_us','finalize_us','device_active_us'):
        out['mcu_ota_'+key]=integer(ready.get(key),key)
    if begin['signature_verify_us']+begin['partition_prepare_us']>begin['begin_us'] or ready.get('begin_us')!=begin['begin_us']:raise ValueError('Inconsistent OTA begin')
    if ready['write_sum_us']+ready['hash_sum_us']>ready['chunk_sum_us'] or ready['device_active_us']!=begin['begin_us']+ready['chunk_sum_us']+ready['finalize_us']:raise ValueError('Inconsistent OTA stages')
    out['mcu_update_work_us']=ready['device_active_us']
    out['host_update_exchange_ns']=integer(cost.get('host_transfer_ns'),'host_transfer_ns')
    for key in ('image_bytes','tx_wire_bytes'):out[key]=integer(cost.get(key),key)
    # Names explicitly distinguish image partition requests from omitted otadata metadata.
    for key in ('image_partition_erase_bytes','image_partition_write_bytes'):
        if key not in cost:raise ValueError('Missing explicit image-partition byte accounting: '+key)
        out[key]=integer(cost[key],key)
    if cost.get('otadata_accounted') is not False:raise ValueError('Require explicit exclusion of unmeasured otadata writes')
    return out


def extract_costs(directory,meta,summary):
    if summary.get('measurement_origin')!='actual_mcu':raise ValueError('Cost summary is not actual_mcu')
    events=[read_json_line(line) for line in (directory/'events.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    result=[]
    for phase,(transition,condition) in TRANSITIONS.items():
        subset=[e for e in events if e.get('phase')==phase]
        cost=[e for e in subset if e.get('event')=='cost']
        if len(cost)!=1:raise ValueError('Need exactly one cost event for '+phase)
        event=cost[0]
        expected_kind='whole' if meta['policy']=='whole_firmware' else 'component'
        if event.get('kind')!=expected_kind:raise ValueError('Policy/cost kind mismatch')
        letter='B' if phase=='B_clean' else 'C'
        expected_model=('compatible_'+letter) if meta['policy']=='model_only_factory_preprocess' else letter
        if event.get('model_key')!=expected_model:raise ValueError('Wrong candidate for '+phase)
        values=whole_measurements(event) if expected_kind=='whole' else component_measurements(event,subset)
        intervals=[e for e in subset if e.get('event')=='update_interval']
        if len(intervals)!=1:raise ValueError('Need exactly one host update-to-ready interval per transition')
        interval=intervals[0]
        if interval.get('model_key')!=expected_model or interval.get('accepted_updates')!=1:raise ValueError('Wrong update interval binding')
        start=integer(interval.get('monotonic_start_ns'),'monotonic_start_ns');end=integer(interval.get('monotonic_end_ns'),'monotonic_end_ns')
        if end<start:raise ValueError('Host update interval ends before start')
        values['host_update_to_ready_ns']=end-start
        for e in subset:
            if e.get('event')=='reboot_verified':
                for name in ('command_to_boot_ns','command_to_status_ns'):values['host_reboot_'+name]=integer(e.get(name),name)
        result.append({**meta,'transition':transition,'target_condition':condition,'model_key':expected_model,'trial_path':str(directory),'measurements':values})
    if len([e for e in events if e.get('event')=='cost'])!=2:raise ValueError('Unexpected extra cost event in cost trial')
    return result


def read_json_line(line):
    value=json.loads(line,parse_constant=lambda s: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    if not isinstance(value,dict):raise ValueError('Event must be object')
    return value


def discover(root):
    manifests=sorted(p for p in root.rglob('campaign_manifest.json') if not p.is_symlink())
    roots=[]
    for path in manifests:
        if not any(parent.parent in path.parents for parent in roots):roots.append(path)
    return roots


def analyze(root,output):
    root=Path(root).resolve(strict=True);output=Path(output).absolute()
    if not root.is_dir():raise ValueError('Input must be directory')
    if output.exists():raise FileExistsError('Output must be a fresh directory')
    rows=[];costs=[];excluded=[];sources=[];plans={};manifests=[];seen=set()

    def logged_json(path):
        if path.is_symlink() or not path.resolve().is_relative_to(root):raise ValueError('Input symlink/path outside run root')
        data=path.read_bytes();sources.append({'path':str(path.relative_to(root)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        return read_json(path)

    def trial(directory,meta,item):
        row={**meta,'trial_path':str(directory),'planned_item':item,'state':'missing','reason':None}
        path=directory/'summary.json'
        if directory.exists() and not path.exists():row.update(state='incomplete',reason='trial directory exists without summary')
        if path.exists():
            try:
                summary=logged_json(path)
                for name in ('stage','command','model_family','policy'):
                    expected='020' if name=='stage' else meta[name]
                    if summary.get(name)!=expected:raise ValueError('Summary identity mismatch '+name)
                if summary.get('trial')!=item:raise ValueError('Summary trial does not match frozen plan')
                if summary.get('status')=='complete':
                    if summary.get('measurement_origin')!='actual_mcu':raise ValueError('Complete trial is not actual MCU evidence')
                    row['state']='completed'
                    if meta['command']=='costs':
                        eventpath=directory/'events.jsonl'
                        if eventpath.is_symlink() or not eventpath.resolve().is_relative_to(root):raise ValueError('Event path is a symlink or outside run root')
                        extracted=extract_costs(directory,meta,summary)
                        sources.append({'path':str(eventpath.relative_to(root)),'bytes':eventpath.stat().st_size,'sha256':hashlib.sha256(eventpath.read_bytes()).hexdigest()})
                        costs.extend(extracted)
                elif summary.get('status')=='failed':row.update(state='failed',reason=summary.get('error','reported failure'))
                else:row.update(state='incomplete',reason='nonterminal or unknown summary status')
            except (OSError,ValueError,KeyError,TypeError) as e:row.update(state='invalid',reason=str(e))
        rows.append(row)

    def campaign(path,parent=None,expected=None):
        if path in seen:return
        seen.add(path);manifest=logged_json(path)
        if manifest.get('stage')!='020':excluded.append({'path':str(path),'reason':'historical/non020 campaign'});return
        if manifest.get('created_before_hardware') is not True:excluded.append({'path':str(path),'reason':'plan not declared before hardware'});return
        if manifest.get('fixture_origin') or manifest.get('measurement_origin','').startswith('native'):
            excluded.append({'path':str(path),'reason':'synthetic/native input'});return
        command=manifest.get('command'); kit=manifest.get('kit_manifest_sha256');board=manifest.get('board_id')
        if not isinstance(kit,str) or len(kit)!=64:raise ValueError('Missing kit identity in '+str(path))
        if not isinstance(board,str):raise ValueError('Missing board identity in '+str(path))
        if expected:
            if command!=expected['command'] or manifest.get('model_family')!=expected['model'] or manifest.get('policy')!=POLICIES[expected['policy']]:raise ValueError('Nested campaign differs from master task')
        campaign_record={'path':str(path),'command':command,'kit_manifest_sha256':kit,'board_id':board}
        if (path.parent/'summary.json').exists():
            aggregate=logged_json(path.parent/'summary.json')
            campaign_record['reported_summary_status']=aggregate.get('status')
            campaign_record['reported_summary_error']=aggregate.get('error')
        manifests.append(campaign_record)
        directory=path.parent;campaign_id=str(path.relative_to(root))
        common={'campaign':campaign_id,'master_campaign':parent,'kit_manifest_sha256':kit,'board_id':board}
        if 'tasks' in manifest:
            task_ids=set();planned_block_ids=set()
            for task in manifest['tasks']:
                number_id=integer(task['task'],'task'); family=task['model'];short_policy=task['policy']; cmd=task['command']
                if number_id in task_ids:raise ValueError('Duplicate master task ID')
                task_ids.add(number_id)
                if family not in ('lr','dt') or short_policy not in POLICIES or cmd not in ('flash','smoke','faults','negatives','costs'):raise ValueError('Unsupported master task identity')
                child=directory/f"task-{number_id:03d}-{family}-{short_policy}-{cmd}"
                if cmd=='flash':continue
                meta={**common,'master_campaign':campaign_id,'command':cmd,'model_family':family,'policy':POLICIES[short_policy],'block':task.get('block'),'trial':task.get('trial'),'task':number_id}
                if task.get('phase')=='cost':
                    if cmd!='costs' or type(task.get('block')) is not int:raise ValueError('Invalid master cost task')
                    block_key=(family,short_policy,task['block'])
                    if block_key in planned_block_ids:raise ValueError('Duplicate model/policy/block in master plan')
                    planned_block_ids.add(block_key)
                    key=(campaign_id,kit,board,family);plans.setdefault(key,defaultdict(set))[meta['policy']].add(task['block'])
                    trial(child,meta,task)
                elif (child/'campaign_manifest.json').exists():campaign(child/'campaign_manifest.json',campaign_id,task)
                else:
                    if cmd=='faults':items=manifest['software_fault_plan']
                    elif cmd=='negatives':
                        items=[dict(r) for r in manifest['component_negative_plan']]
                        if short_policy=='whole':
                            for r in items:
                                if r.get('negative')=='contract':r['negative']='image_hash'
                    elif cmd=='smoke':items=[{'trial':1,'replicate':1}]
                    else:raise ValueError('Unknown planned task '+cmd)
                    for item in items:trial(child/f"trial-{item['trial']:03d}",{**meta,'trial':item['trial']},item)
        else:
            if command=='flash':return
            if command not in ('smoke','faults','negatives','costs'):raise ValueError('Unknown completion020 campaign '+str(command))
            family=manifest['model_family'];policy=manifest['policy']
            if family not in ('lr','dt') or policy not in POLICIES.values():raise ValueError('Unsupported model/policy in campaign')
            trial_ids=set()
            for item in manifest['trial_plan']:
                tid=integer(item['trial'],'trial')
                if tid in trial_ids:raise ValueError('Duplicate trial ID in plan')
                trial_ids.add(tid)
                meta={**common,'command':command,'model_family':family,'policy':policy,'block':None,'trial':tid,'task':None}
                trial(directory/f'trial-{tid:03d}',meta,item)

    for path in discover(root):campaign(path)
    if not manifests:raise ValueError('No eligible completion020 campaign manifests found')
    grouped=defaultdict(list)
    for record in costs:
        key=(record['campaign'],record['master_campaign'],record['kit_manifest_sha256'],record['board_id'],record['model_family'],record['policy'],record['transition'],record['target_condition'])
        grouped[key].append(record)
    groups=[]
    for key,records in sorted(grouped.items(),key=lambda kv:str(kv[0])):
        fields=('campaign','master_campaign','kit_manifest_sha256','board_id','model_family','policy','transition','target_condition')
        group=dict(zip(fields,key));group['n_trials']=len(records); metrics=defaultdict(list)
        for record in records:
            for name,value in record['measurements'].items():metrics[name].append(value)
        group['metrics']={k:stats(v) for k,v in metrics.items()};groups.append(group)
    pairs=[];pair_exclusions=[]
    for key,policyplans in plans.items():
        master,kit,board,family=key
        for a,b in itertools.combinations(sorted(policyplans),2):
            pa,pb=policyplans[a],policyplans[b]
            if pa!=pb or len(pa)<2:
                pair_exclusions.append({'master_campaign':master,'model_family':family,'policies':[a,b],'reason':'unbalanced explicit block plan'});continue
            for transition,condition in TRANSITIONS.values():
                selected={policy:{r['block']:r for r in costs if r['master_campaign']==master and r['kit_manifest_sha256']==kit and r['board_id']==board and r['model_family']==family and r['policy']==policy and r['transition']==transition} for policy in (a,b)}
                if any(set(selected[p])!=pa for p in (a,b)):
                    pair_exclusions.append({'master_campaign':master,'model_family':family,'policies':[a,b],'transition':transition,'reason':'not all preplanned blocks have valid complete costs; no posthoc complete-case pairing'});continue
                metrics=set.intersection(*(set(r['measurements']) for p in (a,b) for r in selected[p].values()))
                for metric in sorted(metrics):
                    result=paired_ci({block:r['measurements'][metric] for block,r in selected[a].items()},{block:r['measurements'][metric] for block,r in selected[b].items()})
                    pairs.append({'master_campaign':master,'kit_manifest_sha256':kit,'board_id':board,'model_family':family,'first_policy':a,'second_policy':b,'transition':transition,'target_condition':condition,'metric':metric,**result})
    cellcounts=defaultdict(Counter)
    for row in rows:
        item=row['planned_item'];key=(row['campaign'],row['model_family'],row['policy'],row['command'],item.get('target_condition'),item.get('checkpoint'),item.get('negative'))
        cellcounts[key]['planned']+=1;cellcounts[key][row['state']]+=1
    counts=[]
    for key,c in cellcounts.items():
        entry=dict(zip(('campaign','model_family','policy','command','target_condition','checkpoint','negative'),key));entry.update({k:c[k] for k in ('planned','completed','failed','missing','incomplete','invalid')});counts.append(entry)
    total=Counter(r['state'] for r in rows)
    report={'status':'complete','analysis_schema':'completion020-campaign-analysis-v1','hardware_access_attempted':False,'input_modified':False,'independent_security_or_numerical_reaudit':False,'bootstrap':{'seed':SEED,'resamples':BOOTSTRAPS},'planned_trials':len(rows),'trial_states':dict(total),'campaigns':manifests,'cells':counts,'cost_groups':groups,'paired_comparisons':pairs,'pairing_exclusions':pair_exclusions,'excluded_campaigns':excluded,'provisioning_policy':'Flash setup is not an update trial; aggregate campaign failure/error is retained, and all unreached scientific trials remain missing.', 'limitations':['Only accepted costs from completed actual_mcu trials with matching new schemas enter distributions; every planned trial remains in denominator table.','No pooling across campaign/kit/board/model/policy/condition. Standalone campaigns are never paired by row number.','Clean A-to-B and reused B-to-C are confounded with slot and sequence; no isolated erase-state causal claim.','MCU update work sums measured device code intervals; it is not CPU-only compute, host elapsed time, energy or IDS service outage.','Host transfer includes transport; firmware transfer ends before its required reboot. Reboot/status intervals are reported separately.','Requested bytes are not measured endurance/wear; whole-image partition byte accounting excludes SDK otadata metadata.','No detection-quality, energy, physical-power-loss, population-board or generalization claim follows from this report.']}
    output.mkdir(parents=True,exist_ok=False)
    for name,value in [('summary.json',report),('trial_inventory.json',rows),('cost_observations.json',costs),('SOURCE_SHA256.json',sources)]:
        (output/name).write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    with (output/'trial_counts.csv').open('w',newline='',encoding='utf-8-sig') as f:
        if counts:w=csv.DictWriter(f,fieldnames=list(counts[0]));w.writeheader();w.writerows(counts)
    flat=[]
    for group in groups:
        for name,v in group['metrics'].items():flat.append({**{k:v for k,v in group.items() if k not in ('metrics',)},'metric':name,**v})
    with (output/'cost_statistics.csv').open('w',newline='',encoding='utf-8-sig') as f:
        if flat:w=csv.DictWriter(f,fieldnames=list(flat[0]));w.writeheader();w.writerows(flat)
    if pairs:
        paired_rows=[]
        for pair in pairs:
            row={k:v for k,v in pair.items() if k!='ci95_percentile'};row['ci95_low'],row['ci95_high']=pair['ci95_percentile'];paired_rows.append(row)
        with (output/'paired_comparisons.csv').open('w',newline='',encoding='utf-8-sig') as f:
            writer=csv.DictWriter(f,fieldnames=list(paired_rows[0]));writer.writeheader();writer.writerows(paired_rows)
    text='# Анализ кампаний 020\n\n'+f"Плановых испытаний: {len(rows)}. Состояния: {dict(total)}.\n\n"+'\n'.join('- '+s for s in report['limitations'])+'\n\nПодробности: summary.json, trial_inventory.json, cost_observations.json, trial_counts.csv, cost_statistics.csv.\n'
    (output/'README_RU.md').write_text(text,encoding='utf-8')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        result=analyze(a.runs,a.output)
        print(json.dumps({'status':'complete','output':str(a.output),'planned_trials':result['planned_trials'],'trial_states':result['trial_states'],'cost_groups':len(result['cost_groups']),'paired_comparisons':len(result['paired_comparisons'])},ensure_ascii=False));return 0
    except (OSError,ValueError,KeyError,TypeError) as e:p.exit(1,f'error: {e}\n')

if __name__=='__main__':sys.exit(main())
