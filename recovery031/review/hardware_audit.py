"""Read-only independent audit of the delivered 030 hardware evidence."""
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
RUN=HERE/'input/ids-completion-030'
KIT=HERE.parent/'research030'
CHECKS=collections.Counter()

def check(condition, what):
    if not condition: raise AssertionError(what)
    CHECKS[what.split(':')[0]]+=1
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def read(p):return json.loads(Path(p).read_text())
def lines(p):
    with Path(p).open() as f:
        for line in f:
            if line.strip():yield json.loads(line)
def norm(p):return Path(str(p).replace('\\','/'))
def canonical(o):return json.dumps(o,sort_keys=True,separators=(',',':'))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def main():
    manifest=read(HERE/'input/ARCHIVE_MANIFEST.json')
    for rel,digest in manifest['sha256'].items():check(sha(HERE/'input'/rel)==digest,'archive_sha256:'+rel)
    excluded={x['path'] for x in manifest['excluded']}
    skipped=[]
    for base,name in [(RUN/'hardware','evidence_manifest.json'),(RUN/'artifacts','evidence_manifest.json'),(RUN/'analysis','evidence_manifest.json'),(RUN/'training','result_manifest.json')]:
        for rel,digest in read(base/name)['sha256'].items():
            path=base/norm(rel)
            if not path.exists() and path.relative_to(RUN).as_posix() in excluded:
                skipped.append(path.relative_to(RUN).as_posix());continue
            check(path.exists() and sha(path)==digest,'phase_sha256:'+str(path.relative_to(RUN)))
    for rel,digest in read(RUN/'KIT_MANIFEST_at_start.json')['sha256'].items():check(sha(KIT/norm(rel))==digest,'frozen_kit_sha256:'+rel)
    codec=load('audit030codec',KIT/'hardware_codec/codec030.py')
    ref=load('audit030reference',KIT/'training/model030.py')
    hw=load('audit030hardware',KIT/'tools/hardware030.py')
    art=read(RUN/'artifacts/artifacts.json')
    models={};golds={};unique=set();host_reference_error=0.
    for family,f in art['families'].items():
        gold=read(RUN/'artifacts'/norm(f['golden']));golds[family]=gold
        for reference,expected in gold['expected'].items():
            model_name=reference+'_'+family if reference in ('A','B') else reference
            model=read(RUN/'training/models'/f'{model_name}.json');models[family,reference]=model
            p,y=ref.predict(model,gold['raw'])
            host_reference_error=max(host_reference_error,max(abs(float(a)-b['probability']) for a,b in zip(p,expected)))
            check(all(abs(float(a)-b['probability'])<=2e-6 and int(c)==b['label'] for a,b,c in zip(p,expected,y)),'host_golden_recomputed:'+family+'/'+reference)
        for version,v in f['versions'].items():
            blob=(RUN/'artifacts'/norm(v['path'])).read_bytes()
            check(codec.envelope_metadata(blob)==v['identity'],'signed_bundle_binding:'+family+'/'+version)
            check(codec.payload(models[family,v['reference']],int(version),v['release'])==blob[16:-256],'model_to_payload_binding:'+family+'/'+version)
        for policy,pp in f['policies'].items():
            for version,m in pp['images'].items():
                image=(RUN/'artifacts'/norm(m['path'])).read_bytes()
                metadata=codec.verify_image(image)
                check(all(metadata[k]==m[k] for k in metadata),'firmware_checksum_sha_binding:'+family+'/'+policy+'/'+version)
                blob=(RUN/'artifacts'/norm(f['versions'][version]['path'])).read_bytes()
                check(image.count(blob)==1,'firmware_bundle_embedding:'+family+'/'+policy+'/'+version)

    count=collections.Counter();negative=collections.Counter();by_family={};maxerr=0.;faults=[];whole_primary_reboots=[]
    for eventpath in sorted((RUN/'hardware').rglob('events.jsonl')):
        directory=eventpath.parent
        if not (directory/'observations.jsonl').exists():continue
        events=list(lines(eventpath));initial=[x for x in events if x.get('event')=='initial_status_verified']
        check(len(initial)==1,'initial_status_per_session')
        status=initial[0]['response'];abi=status['runtime_abi'];family={2:'lr',3:'dt',4:'mlp_float',5:'mlp_int8'}[abi]
        policy='whole' if status['policy']=='whole_firmware' else 'bundle';f=art['families'][family]
        count['completed_trials']+=1
        fam=by_family.setdefault(family,collections.Counter())
        # Every emitted response in event evidence must occur in the serial transcript.
        raw_responses=collections.Counter()
        for r in lines(directory/'transcript.jsonl'):
            if r.get('direction')=='rx':
                try:response=json.loads(r['line'])
                except (ValueError,KeyError):continue
                raw_responses[canonical(response)]+=1
        command_responses=collections.Counter(canonical(e['response']) for e in events if e.get('event')=='command_response')
        check(all(raw_responses[k]>=n for k,n in command_responses.items()),'raw_serial_response_binding')
        obs_responses=collections.Counter()
        for ob in lines(directory/'observations.jsonl'):
            response=ob['response'];v=f['versions'][str(response['version'])]
            expected=golds[family]['expected'][v['reference']][ob['index']]
            check(ob['raw']==golds[family]['raw'][ob['index']] and ob['expected']==expected,'observation_golden_binding')
            check(response['bundle_sha256']==v['payload_sha256'],'inference_payload_identity')
            err=abs(response['probability']-expected['probability'])
            match=response['label']==expected['label']
            check(err==ob['probability_abs_error'] and match==ob['label_match'] and match and err<=2e-6,'numerical_observation')
            obs_responses[canonical(response)]+=1;unique.add(tuple(ob['raw']))
            count['inferred_records']+=1;fam['inferred_records']+=1;maxerr=max(maxerr,err)
        check(all(command_responses[k]>=n for k,n in obs_responses.items()),'observation_command_binding')
        for i,e in enumerate(events):
            if e.get('event')=='command_response':
                r=e['response']
                if r.get('event') in ('status','inference'):
                    v=f['versions'][str(r['version'])]
                    check(r['bundle_sha256']==v['payload_sha256'] and r['runtime_abi']==abi,'response_identity')
                    if r['event']=='status':
                        image=f['policies'][policy]['images'][str(r['version']) if policy=='whole' else '1']
                        check(r['build']==image['expected_build'],'running_image_template_identity')
                if r.get('event')=='update' and r.get('accepted') is False:
                    check(r['ready'] is True and all(r[k]==0 for k in ('model_erase_bytes','model_write_bytes','journal_erase_bytes','journal_write_bytes')),'negative_bundle_zero_flash')
                    check(r['reason'] in ('signature','feature_contract','replay_or_downgrade'),'negative_bundle_reason')
                    negative[r['reason']]+=1
                if r.get('event')=='fw_error':
                    check(r['error'] in ('signature','image_sha256','non_monotonic_version'),'negative_ota_reason')
                    negative['ota_'+r['error']]+=1
            elif e.get('event')=='cost':
                count['accepted_updates']+=1;fam['accepted_updates']+=1
                if policy=='bundle':
                    r=e['response'];t=r['timing_us']
                    check(sum(t[k] for k in hw.TIMING_STAGES)<=t['total']<=r['latency_us'],'bundle_stage_time_sum')
                    check(r['model_erase_bytes']==4096 and r['model_write_bytes']==e['envelope_bytes']+8,'bundle_flash_work')
                else:
                    r=e['ready'];b=e['begin']
                    check(r['device_active_us']==b['begin_us']+r['chunk_sum_us']+r['finalize_us'],'ota_stage_time_sum')
                    check(r['chunk_count']==332 and r['bytes']==339504,'ota_transfer_size')
                    if e['version']==3:
                        reboots=[x for x in events[:i] if x.get('event')=='reboot_verified' and x['version']==3]
                        check(len(reboots)==1,'primary_reboot_count');whole_primary_reboots.append(reboots[0]['command_to_status_ns']/1e9)
            elif e.get('event')=='fault_verified':
                expected=3 if e['checkpoint']=='after_commit' else 2
                check(e['recovered_version']==expected and e['physical_power_loss_tested'] is False,'software_fault_recovery')
                count['faults_verified']+=1;count['verified_reboots']+=1;faults.append(dict(family=family,checkpoint=e['checkpoint'],recovered_version=expected))
            elif e.get('event')=='reboot_verified':count['verified_reboots']+=1
        binding=read(directory/'provisioning/factory_image_binding.json')
        check(binding['image_sha256']==f['policies'][policy]['images']['1']['image_sha256'],'provisioning_image_binding')
        rom=(directory/'provisioning/rom_identity.log').read_text()
        check('a0:f2:62:eb:b5:58' in rom and 'ESP32-S3' in rom,'provisioning_rom_identity')
        for p in (directory/'provisioning').glob('*-result.json'):check(read(p)['returncode']==0,'provisioning_result')
    count['negative_controls_passed']=sum(negative.values());count['label_mismatches']=0
    summary=read(RUN/'hardware/summary.json');expected=read(RUN/'hardware/campaign_before_hardware.json')['expected_completed_counters']
    check(dict(count)==expected,'reconstructed_campaign_counters')
    check(all(summary[k]==v for k,v in count.items()) and summary['max_probability_abs_error']==maxerr,'summary_reconstructed_counters')
    costs=hw.analyze_costs(RUN/'hardware',HERE/'hardware_costs_reproduced.json')
    check(costs==read(RUN/'analysis/costs.json'),'cost_analysis_exact_reproduction')
    import numpy as np
    table=[]
    for family in art['families']:
        comparison=costs['comparisons'][family];rows=[r for r in costs['primary_rows'] if r['family']==family]
        bundle=next(r for r in rows if r['policy']=='bundle');whole=next(r for r in rows if r['policy']=='whole')
        table.append(dict(family=family,bundle_bytes=bundle['payload_or_image_bytes'],whole_bytes=whole['payload_or_image_bytes'],bundle_device_ms=comparison['bundle_median_us']/1000,whole_device_ms=comparison['whole_median_us']/1000,bundle_host_s=float(np.median([r['host_elapsed_ns']/1e9 for r in rows if r['policy']=='bundle'])),whole_host_s=float(np.median([r['host_elapsed_ns']/1e9 for r in rows if r['policy']=='whole'])),whole_to_bundle_bytes=whole['payload_or_image_bytes']/bundle['payload_or_image_bytes']))
    result=dict(status='pass',checks=sum(CHECKS.values()),checks_by_kind=dict(CHECKS),read_only_audit=True,physical_hardware_access_by_auditor=False,archive_sha256=sha(HERE.parent/'upload/ids-completion-030-results.zip'),excluded_cache=skipped,hardware_summary=summary,reconstructed_counters=dict(count),negative_controls=dict(negative),family_counters={k:dict(v) for k,v in by_family.items()},unique_raw_input_vectors_across_all_7664_calls=len(unique),cost_table=table,faults=faults,whole_primary_reboot_command_to_status_median_s=float(np.median(whole_primary_reboots)),host_reference_cross_platform_max_error=host_reference_error,energy_original_status=read(RUN/'analysis/energy/summary.json'))
    (HERE/'hardware_audit.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:result[k] for k in ('status','checks','reconstructed_counters','unique_raw_input_vectors_across_all_7664_calls','cost_table')},indent=2))

if __name__=='__main__':main()
