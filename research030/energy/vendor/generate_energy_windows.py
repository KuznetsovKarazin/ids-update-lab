#!/usr/bin/env python3
"""Freeze energy windows from successful costs logs, excluding provisioning.
Only the CFN time offset and its evidence are filled by the investigator later.
"""
import argparse,hashlib,json,sys
from pathlib import Path

def binding(spec):
    fields={k:spec[k] for k in ('baseline_windows_host_s','events','host_origin_monotonic_ns')}
    return hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def generate(run,output):
    run=Path(run);intervals=[];hashes={}
    for path in sorted(run.rglob('events.jsonl')):
        summary_path=path.parent/'summary.json'
        if not summary_path.exists():continue
        summary=json.loads(summary_path.read_text())
        if summary.get('command')!='costs':continue
        if summary.get('status')!='complete':raise ValueError('Incomplete costs trial must be analyzed before energy: '+str(path.parent))
        data=path.read_bytes();hashes[path.relative_to(run).as_posix()]=hashlib.sha256(data).hexdigest()
        rows=[json.loads(line) for line in data.splitlines() if line.strip()]
        baselines=[x for x in rows if x.get('event')=='energy_baseline']
        updates=[x for x in rows if x.get('event')=='update_interval']
        if not updates:raise ValueError('Cost log lacks explicit update_interval bounds')
        for item in updates:
            if item.get('accepted_updates')!=1:raise ValueError('Only verified accepted updates qualify')
            previous=[x for x in baselines if x['monotonic_end_ns']<=item['monotonic_start_ns'] and x.get('related_update_key')==item.get('model_key')]
            if not previous:raise ValueError('No recorded baseline for update; run dedicated whole costs with --energy-baseline-seconds 10')
            base=max(previous,key=lambda x:x['monotonic_end_ns'])
            if item['monotonic_start_ns']<=base['monotonic_end_ns']-1 or item['monotonic_end_ns']<=item['monotonic_start_ns']:raise ValueError('Invalid measured boundaries')
            intervals.append((path.parent.relative_to(run).as_posix(),item,base))
    if not intervals:raise ValueError('No successful costs intervals found')
    origin=min(base['monotonic_start_ns'] for name,item,base in intervals);base_rows=[];events=[]
    for name,item,base in intervals:
        index=len(base_rows);base_rows.append([(base[k]-origin)/1e9 for k in ('monotonic_start_ns','monotonic_end_ns')])
        events.append({'id':name+'/'+item['model_key'],'host_start_s':(item['monotonic_start_ns']-origin)/1e9,'host_end_s':(item['monotonic_end_ns']-origin)/1e9,'accepted_updates':1,'baseline_indices':[index],'policy':item['policy'],'model_key':item['model_key']})
    spec={'alignment_method':'manual_record_start_interval','alignment_evidence':'FILL actual observed synchronization evidence, not optimization of energy result','cfn_time_minus_host_relative_time_s':None,'host_origin_monotonic_ns':origin,'host_origin_utc_ns':min(intervals,key=lambda row:row[2]['monotonic_start_ns'])[2].get('utc_start_ns'),'baseline_windows_host_s':base_rows,'events':events,'source_events_sha256':hashes,'source_run_name':run.name,'generated_intervals_must_not_be_edited':True,'includes_provisioning':False,'energy_measurement_performed':False}
    spec['host_window_binding_sha256']=binding(spec)
    with Path(output).open('x',encoding='utf-8') as f:json.dump(spec,f,ensure_ascii=False,indent=2);f.write('\n')
    return {'status':'complete','update_windows':len(events),'alignment_still_required':True,'output':str(output)}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:print(json.dumps(generate(a.run,a.output)));return 0
    except (ValueError,TypeError,OSError,KeyError) as e:print('error: '+str(e),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
