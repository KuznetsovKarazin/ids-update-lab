#!/usr/bin/env python3
"""Completion 020: pinned ESP32-S3 experiments, explicit finite plans, fresh evidence.

No mutation retries or automatic resume. Faults mean software restarts only.
Use inspect before flash. Hardware commands require --port/--board-id/--output.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
# Verify the support module itself before executing it. Full pins gate precedes
# loading all other local modules and every hardware operation.
def bootstrap():
    manifest=ROOT/'KIT_MANIFEST.json'
    data=json.loads(manifest.read_text(encoding='utf-8')); files=data.get('sha256',data.get('files',data))
    for name in ('tools/run_completion.py','tools/campaign_support.py'):
        if files.get(name)!=hashlib.sha256((ROOT/name).read_bytes()).hexdigest(): raise ValueError('Unpinned runner/support '+name)
    spec=importlib.util.spec_from_file_location('campaign_support',ROOT/'tools/campaign_support.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def stamp(): return {'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}

def append(path,value):
    with Path(path).open('a',encoding='utf-8') as f:
        f.write(json.dumps({**stamp(),**value},allow_nan=False)+'\n'); f.flush()


def legacy(root):
    spec=importlib.util.spec_from_file_location('completion_legacy018',root/'tools/legacy_runner018.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def esptool(args,directory,name,tail,s,c,cwd=None):
    directory.mkdir(parents=True,exist_ok=True)
    command=[sys.executable,'-m','esptool','--chip','esp32s3','--port',args.port,*tail]
    intent={'action':name,'argv':command,'cwd':str(cwd or c['root']),**stamp()}
    s.save(directory/(name+'-intent.json'),intent)
    with (directory/(name+'.log')).open('x',encoding='utf-8') as log:
        completed=subprocess.run(command,cwd=cwd or c['root'],stdout=log,stderr=subprocess.STDOUT,text=True,timeout=180,check=False)
    output=(directory/(name+'.log')).read_text(encoding='utf-8',errors='replace')
    s.save(directory/(name+'-result.json'),{'returncode':completed.returncode,'log_sha256':s.sha(directory/(name+'.log')),**stamp()})
    if completed.returncode!=0: raise RuntimeError(f'esptool {name} failed; inspect {directory/name}.log')
    return output


def verify_mac(args,directory,s,c):
    output=esptool(args,directory,'identity',['--after','hard_reset','flash_id'],s,c)
    matches={v.lower() for v in re.findall(r'MAC:\s*([0-9a-fA-F:]{17})',output)}
    if matches!={s.board_mac(args.board_id)} or 'ESP32-S3' not in output: raise RuntimeError('ROM-reported chip/MAC differs before write; no flash/erase issued')
    return {'reported_mac':next(iter(matches)),'rom_query_verified':True,'secure_attestation':False}


def flash_factory(args,directory,s,c,identity=True):
    if identity: verify_mac(args,directory,s,c)
    esptool(args,directory,'write_factory',['-b','460800','--after','no_reset','write_flash','@flash_args'],s,c,c['factory_dir'])
    # Remove stale model selectors and component bodies; leave NVS untouched.
    esptool(args,directory,'erase_component_state',['--after','no_reset' if c['policy_name']=='whole' else 'hard_reset','erase_region','0x3b0000','0x22000'],s,c)
    if c['policy_name']=='whole':
        esptool(args,directory,'erase_inactive_ota',['--after','hard_reset','erase_region','0x1e0000','0x1d0000'],s,c)


def restore(args,directory,s,c):
    verify_mac(args,directory,s,c)
    if c['policy_name']=='whole': flash_factory(args,directory,s,c,identity=False)
    else: esptool(args,directory,'erase_component_state',['--after','hard_reset','erase_region','0x3b0000','0x22000'],s,c)


def known_status(reply,s,c,allow_old=False):
    known=set()
    for entry in s.read_json(c['root']/'BUILD_METADATA.json')['configurations'].values():
        known.update(im['expected_build'] for im in entry['images'].values())
    if allow_old: known.add('esp-idf-v5.3.2;app=1;elf=acaf8dc23')
    if reply.get('event')!='status' or reply.get('ready') is not True or reply.get('chip')!='esp32s3' or reply.get('build') not in known: raise RuntimeError('Preflight requires a recognized ready firmware; preserve transcript before changing state')
    if reply.get('build')=='esp-idf-v5.3.2;app=1;elf=acaf8dc23':
        s.typed(reply,{'version':8,'release':'log1p-B-rest','policy':'bundle','runtime_abi':2},'pre-020 board')
    return reply


class Trial:
    def __init__(self,args,s,c,out,summary):
        self.args,self.s,self.c,self.out,self.summary=args,s,c,out,summary
        self.api=legacy(c['root']); self.evidence=self.api.Evidence(out); self.link=self.api.Link(c['serial'],self.evidence,args.timeout)
        self.phase='startup'
    def setphase(self,value): self.phase=value; self.evidence.phase=value
    def open(self,key='A'):
        reply=self.link.open(self.args.port); self.s.check_status(reply,self.c,key)
        self.evidence.event('verified_status',response=reply,model_key=key)
        self.summary['measurement_origin']=self.c.get('measurement_origin','actual_mcu'); return reply
    def status(self,key):
        reply=self.link.command('STATUS',{'status'}); self.s.check_status(reply,self.c,key); return reply
    def infer(self,key,rows):
        for i,row in enumerate(rows,1):
            reply=self.link.command('INFER '+','.join(format(float(v),'.9g') for v in row['raw']),{'inference'})
            expected=row['expected'][key]; error,match=self.s.check_inference(reply,self.c,key,expected)
            self.evidence.record({'model_key':key,'record_id':row['id'],'raw':row['raw'],'expected':expected,'response':reply,'probability_abs_error':error,'label_match':match},'observations')
            self.summary['inferred_records']+=1; self.summary['label_mismatches']+=not match
            self.summary['max_probability_abs_error']=max(self.summary['max_probability_abs_error'],error)
            if not match or error>self.s.TOLERANCE: raise RuntimeError('Inference differs from frozen model: '+key+'/'+str(row['id']))
            if len(rows)>32 and (i%64==0 or i==len(rows)): print(f'{self.phase}: {i}/{len(rows)}',flush=True)
    def reboot(self,key):
        self.evidence.event('mutation_intent',command='REBOOT',expected_model=key)
        self.link.allow_reconnect=True; start=time.monotonic_ns()
        try:
            reply=self.link.command('REBOOT',{'reboot'}); self.s.typed(reply,{'event':'reboot','fault_kind':'software_restart'},'reboot')
            boot=self.link.receive({'boot'}); self.s.check_status(boot,self.c,key,'boot')
            boot_elapsed=time.monotonic_ns()-start
            after=self.status(key)
            self.evidence.event('reboot_verified',response=after,boot_response=boot,command_to_boot_ns=boot_elapsed,command_to_status_ns=time.monotonic_ns()-start,physical_power_loss_tested=False)
            self.summary['verified_reboots']+=1
        finally: self.link.allow_reconnect=False
    def update(self,key,checkpoint=None):
        interval_start=stamp()
        blob=self.c['envelopes'][key]
        if checkpoint:
            armed=self.link.command('ARM_FAIL '+checkpoint,{'armed'}); self.s.typed(armed,{'event':'armed','checkpoint':checkpoint},'arm')
        self.evidence.event('mutation_intent',command='UPDATE',candidate=key,envelope_sha256=hashlib.sha256(blob).hexdigest(),checkpoint=checkpoint)
        if checkpoint:
            self.link.allow_reconnect=True
            try:
                reply=self.link.command('UPDATE '+blob.hex(),{'fault_checkpoint'})
                self.s.typed(reply,{'event':'fault_checkpoint','checkpoint':checkpoint,'fault_kind':'software_restart'},'fault trigger')
                boot=self.link.receive({'boot'})
                old='A' if self.c['models'][key].version==2 else self.s.key_for(self.c,'B')
                recovered=key if checkpoint=='after_commit' else old
                self.s.check_status(boot,self.c,recovered,'boot'); self.status(recovered)
                self.evidence.event('checkpoint_recovery_verified',checkpoint=checkpoint,recovered_model=recovered,response=boot,physical_power_loss_tested=False)
                self.summary['verified_reboots']+=1; self.summary['faults_verified']+=1
                return recovered
            finally: self.link.allow_reconnect=False
        reply=self.link.command('UPDATE '+blob.hex(),{'update'})
        self.s.typed(reply,{'event':'update','accepted':True,'reason':'ok','ready':True,'version':self.c['models'][key].version,'policy':self.c['policy']},'accepted update')
        timings=self.s.bundle_timing(reply); self.status(key)
        self.evidence.event('cost',kind='component',model_key=key,envelope_bytes=len(blob),payload_bytes=len(blob)-272,tx_wire_bytes=2*len(blob)+8,timing_us=timings,source_erase_bytes=65536,source_model_write_bytes=len(blob)+8,journal_record_bytes=128,journal_rollover_excluded=True)
        end=stamp();self.evidence.event('update_interval',model_key=key,policy=self.c['policy'],accepted_updates=1,monotonic_start_ns=interval_start['monotonic_ns'],monotonic_end_ns=end['monotonic_ns'],utc_start_ns=interval_start['utc_ns'],utc_end_ns=end['utc_ns'],scope='UPDATE through acknowledged status')
        self.summary['accepted_updates']+=1; return key
    def reject(self,blob,reason,current):
        self.evidence.event('mutation_intent',command='UPDATE',negative_expected=reason,envelope_sha256=hashlib.sha256(blob).hexdigest())
        reply=self.link.command('UPDATE '+blob.hex(),{'update'})
        self.s.typed(reply,{'event':'update','accepted':False,'reason':reason,'ready':True,'version':self.c['models'][current].version,'policy':self.c['policy']},'negative rejection')
        self.s.bundle_timing(reply,accepted=False); self.status(current)
        self.summary['negative_controls_passed']+=1
    def fw(self,key,negative=None):
        image,meta,sig=self.s.validate_ota(self.c,key)
        if negative=='signature': sig=sig[:-1]+bytes([sig[-1]^1])
        if negative=='image_hash': image=image[:-1]+bytes([image[-1]^1])
        reason={'signature':'signature','replay':'non_monotonic_version'}.get(negative)
        self.evidence.event('mutation_intent',command='FW_BEGIN',candidate=key,negative=negative,image_sha256=hashlib.sha256(image).hexdigest())
        interval_start=stamp();start=interval_start['monotonic_ns']; wire=0
        def command(line,expected):
            nonlocal wire
            wire+=len(line.encode('ascii'))+1; return self.link.command(line,expected)
        begin=command('FW_BEGIN '+meta.hex()+' '+sig.hex(),{'fw_error'} if reason else {'fw_begin'})
        if reason:
            self.s.typed(begin,{'event':'fw_error','ok':False,'error':reason},'OTA rejection'); self.status('A'); self.summary['negative_controls_passed']+=1; return
        self.s.typed(begin,{'event':'fw_begin','ok':True,'version':self.c['models'][key].version,'size':len(image),'timing_schema':2,'crypto_context':'shared_warm'},'OTA begin')
        for name in ('signature_verify_us','partition_prepare_us','begin_us'): self.s.integer(begin,name)
        if begin['signature_verify_us']+begin['partition_prepare_us']>begin['begin_us']: raise RuntimeError('OTA begin timing inconsistency')
        totals={name:0 for name in ('write_sum_us','hash_sum_us','chunk_sum_us','chunk_count')}
        for offset in range(0,len(image),256):
            chunk=image[offset:offset+256]; reply=command(f'FW_CHUNK {offset} {chunk.hex()}',{'fw_chunk'})
            self.s.typed(reply,{'event':'fw_chunk','ok':True,'offset':offset+len(chunk),'timing_schema':2},'OTA chunk')
            write=self.s.integer(reply,'write_us'); hashing=self.s.integer(reply,'hash_us'); elapsed=self.s.integer(reply,'chunk_us')
            if write+hashing>elapsed: raise RuntimeError('OTA chunk timing inconsistency')
            totals['write_sum_us']+=write; totals['hash_sum_us']+=hashing; totals['chunk_sum_us']+=elapsed; totals['chunk_count']+=1
            self.s.typed(reply,totals,'OTA cumulative timings')
        ready=command('FW_END',{'fw_error'} if negative=='image_hash' else {'fw_ready'})
        if negative=='image_hash':
            self.s.typed(ready,{'event':'fw_error','ok':False,'error':'image_sha256'},'OTA hash rejection'); self.status('A'); self.summary['negative_controls_passed']+=1; return
        self.s.typed(ready,{'event':'fw_ready','ok':True,'version':self.c['models'][key].version,'bytes':len(image),'reboot_required':True,'timing_schema':2,'begin_us':begin['begin_us'],**totals},'OTA ready')
        finalize=self.s.integer(ready,'finalize_us'); device=self.s.integer(ready,'device_active_us')
        if device!=begin['begin_us']+totals['chunk_sum_us']+finalize: raise RuntimeError('OTA total timing inconsistency')
        self.evidence.event('cost',kind='whole',model_key=key,image_bytes=len(image),tx_wire_bytes=wire,host_transfer_ns=time.monotonic_ns()-start,begin=begin,ready=ready,transport='USB serial, hex, stop-and-wait, 256-byte image chunks',image_partition_erase_bytes=math.ceil(len(image)/4096)*4096,image_partition_write_bytes=len(image),otadata_accounted=False,wear_claim='image-partition requested bytes only; extra otadata erase/write on selection and boot excluded, not measured endurance')
        # FW_END selects new image but old one must remain live until reboot.
        old='A' if key=='B' else 'B'; self.status(old)
        self.reboot(key)
        end=stamp();self.evidence.event('update_interval',model_key=key,policy=self.c['policy'],accepted_updates=1,monotonic_start_ns=interval_start['monotonic_ns'],monotonic_end_ns=end['monotonic_ns'],utc_start_ns=interval_start['utc_ns'],utc_end_ns=end['utc_ns'],scope='FW_BEGIN through reboot and verified status')
        self.summary['accepted_updates']+=1
    def baseline(self,current,target):
        seconds=getattr(self.args,'energy_baseline_seconds',0)
        if seconds:
            start=stamp();time.sleep(seconds);end=stamp()
            self.evidence.event('energy_baseline',model_key=current,related_update_key=target,seconds=seconds,monotonic_start_ns=start['monotonic_ns'],monotonic_end_ns=end['monotonic_ns'],utc_start_ns=start['utc_ns'],utc_end_ns=end['utc_ns'],scope='no protocol commands; powered firmware idle')
    def close(self): self.link.close(); self.evidence.close()


def session_preflight(args,s,c,output,allow_old=False):
    output.mkdir(exist_ok=False)
    a=legacy(c['root']); e=a.Evidence(output); link=a.Link(c['serial'],e,args.timeout)
    try:
        reply=link.open(args.port)
        known_status(reply,s,c,allow_old)
        if not allow_old:
            allowed={im['expected_build'] for im in c['build']['images'].values()}
            if reply['build'] not in allowed or reply.get('policy')!=c['policy']: raise RuntimeError('Wrong current policy/build; use explicit flash command first')
        s.save(output/'status.json',reply)
    finally: link.close(); e.close()


def trial(args,s,c,output,item,reflash=False):
    output.mkdir(exist_ok=False)
    summary={'status':'failed','measurement_origin':'not_measured','stage':'020','command':args.command,'model_family':args.model,'policy':c['policy'],'trial':item,'inferred_records':0,'label_mismatches':0,'max_probability_abs_error':0.,'accepted_updates':0,'verified_reboots':0,'faults_verified':0,'negative_controls_passed':0,'physical_power_loss_tested':False,'heldout_detection_quality_measured':False,'energy_measured':False}
    t=None
    try:
        if reflash:flash_factory(args,output/'restore',s,c)
        else:restore(args,output/'restore',s,c)
        t=Trial(args,s,c,output,summary); t.open('A')
        if args.command=='faults':
            target='B'
            if item['target_condition']=='reused': t.setphase('setup_B'); t.update(s.key_for(c,'B')); target='C'
            t.setphase(item['target_condition']+'_'+item['checkpoint'])
            recovered=t.update(s.key_for(c,target),item['checkpoint']); t.infer(recovered,c['golden'][:8])
            # Signed factory A is now equal/older. Rejection must not mutate flash.
            t.reject(c['envelopes']['A'],'replay_or_downgrade',recovered); t.infer(recovered,c['golden'][:1])
        elif args.command=='negatives':
            t.setphase(item['negative'])
            if c['policy_name']=='whole': t.fw('A' if item['negative']=='replay' else 'B',item['negative'])
            else:
                kind=item['negative']; blob=c['envelopes']['A'] if kind=='replay' else (c['family']/('bad-'+kind+'.sids')).read_bytes()
                t.reject(blob,{'signature':'signature','contract':'feature_contract','replay':'replay_or_downgrade'}[kind],'A')
            t.infer('A',c['golden'][:8]); t.reboot('A'); t.infer('A',c['golden'][:1])
        else:
            rows=c['golden'] if args.command=='smoke' else c['golden'][:16]
            for letter in 'ABC':
                key=s.key_for(c,letter); t.setphase(letter+('_clean' if letter=='B' else '_reused' if letter=='C' else ''))
                if letter!='A':
                    if args.command=='costs':t.baseline(s.key_for(c,'A' if letter=='B' else 'B'),key)
                    if c['policy_name']=='whole': t.fw(key)
                    else: t.update(key)
                t.infer(key,rows)
            t.setphase('C_after_reboot'); t.reboot(s.key_for(c,'C')); t.infer(s.key_for(c,'C'),c['golden'][:1])
        summary['status']='complete'
    except BaseException as exc:
        summary['error']=f'{type(exc).__name__}: {exc}'; raise
    finally:
        if t:t.close()
        summary['finished_utc_ns']=time.time_ns(); s.save(output/'summary.json',summary)
    return summary


def campaign(args,s,c):
    output=Path(args.output).resolve(); output.mkdir(parents=True,exist_ok=False)
    summary={'status':'failed','measurement_origin':'not_measured','stage':'020','command':args.command,'model_family':args.model,'policy':c['policy'],'completed_trials':0,'attempted_trials':0,'planned_trials':0,'hardware_access_attempted':False,'aggregate_counters_scope':'completed_trials_only','inferred_records':0,'label_mismatches':0,'max_probability_abs_error':0.,'accepted_updates':0,'verified_reboots':0,'faults_verified':0,'negative_controls_passed':0,'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False}
    rows=s.plan(args.command)
    if args.command=='negatives' and args.policy=='whole':
        for row in rows:
            if row['negative']=='contract':row['negative']='image_hash'
    manifest={'stage':'020','schema':1,'protocol':'completion020_hardware_before_collection','created_before_hardware':True,'created_utc_ns':time.time_ns(),'command':args.command,'model_family':args.model,'policy':c['policy'],'board_id':args.board_id,'expected_rom_mac':s.board_mac(args.board_id),'port':args.port,'kit_manifest_sha256':c['kit_manifest_sha256'],'parameters':vars(args),'trial_plan':rows,'seed':24092026,'fault_trials_per_checkpoint_condition':10,'security_trials_per_case':10,'cost_trials':30,'fixed_probability_abs_tolerance':s.TOLERANCE,'correctness_subset_ids':[r['id'] for r in (c['golden'] if args.command=='smoke' else c['golden'][:8] if args.command in ('faults','negatives') else c['golden'][:16])],'data_origin':'TON_IoT_development','physical_power_loss_tested':False,'heldout_detection_quality_measured':False,'energy_measured':False,'condition_caveat':'A->B is clean slot1; B->C reuses old A in slot0. Order and slot are not randomized; not a causal effect of erase state alone.','flash_write_caveat':'esptool reinitialization is provisioning, excluded from update cost. Model storage reset loses software rollback history intentionally in this laboratory.'}
    s.save(output/'campaign_manifest.json',manifest)
    try:
        summary['hardware_access_attempted']=True
        if getattr(args,'rom_recovery',False):
            if args.command!='flash':raise ValueError('--rom-recovery is only valid with flash')
            s.save(output/'rom_recovery_intent.json',{'runtime_preflight_skipped_explicitly':True,'rom_mac_guard_still_required':True})
        else:session_preflight(args,s,c,output/'preflight',allow_old=args.command=='flash')
        summary['measurement_origin']='actual_mcu' if not getattr(args,'rom_recovery',False) else 'not_measured'
        if args.command=='flash':
            flash_factory(args,output/'flash',s,c)
            verify=output/'verify'; verify.mkdir(); t=Trial(args,s,c,verify,summary)
            try:t.open('A');t.infer('A',c['golden'][:1])
            finally:t.close()
            summary['factory_verified']=True
        else:
            summary['planned_trials']=len(rows)
            for item in rows:
                print(f"{args.command} {args.model}/{args.policy}: {item['trial']}/{len(rows)} {json.dumps(item)}",flush=True)
                summary['attempted_trials']+=1;summary['current_trial_path']=f"trial-{item['trial']:03d}"
                result=trial(args,s,c,output/f"trial-{item['trial']:03d}",item)
                append(output/'completed_trials.jsonl',result); summary['completed_trials']+=1; summary['measurement_origin']='actual_mcu'
                for key in ('inferred_records','label_mismatches','accepted_updates','verified_reboots','faults_verified','negative_controls_passed'):summary[key]+=result[key]
                summary['max_probability_abs_error']=max(summary['max_probability_abs_error'],result['max_probability_abs_error'])
        summary['status']='complete'
    except BaseException as exc:
        summary['error']=f'{type(exc).__name__}: {exc}'
        if 'current_trial_path' in summary:summary['failed_trial_path']=summary['current_trial_path']
        raise
    finally:
        summary['finished_utc_ns']=time.time_ns(); s.save(output/'summary.json',summary)
    print(json.dumps({'run':str(output),**summary},allow_nan=False))
    return summary


def suite(args,s,contexts):
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False)
    tasks=s.suite_plan(args.model,full=args.command=='series')
    for task in tasks:task['path']=f"task-{task['task']:03d}-{task['model']}-{task['policy']}-{task['command']}"
    manifest={'stage':'020','schema':1,'protocol':'completion020_hardware_before_collection','command':args.command,'created_before_hardware':True,'created_utc_ns':time.time_ns(),'kit_manifest_sha256':next(iter(contexts.values()))['kit_manifest_sha256'],'board_id':args.board_id,'expected_rom_mac':s.board_mac(args.board_id),'port':args.port,'tasks':tasks,'order_rule':'30 blocks, all selected configurations once per block; left-rotate configuration list by block_index modulo configuration_count','component_resets':'factory reflash before each cost cell to control policy/image selection; excluded from update timing','costs_trials_each_configuration':30,'software_fault_plan':s.plan('faults'),'component_negative_plan':s.plan('negatives'),'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False,'data_origin':'TON_IoT_development','condition_caveat':'Within each cost trial, A->B clean slot1 precedes B->C reused slot0; this is not causal isolation of slot or erase state.'}
    s.save(output/'campaign_manifest.json',manifest)
    s.save(output/'cost_suite_manifest.json',{'stage':'020','schema':1,'model_family':args.model,'kit_manifest_sha256':manifest['kit_manifest_sha256'],'created_before_hardware':True,'energy_baseline_seconds':args.energy_baseline_seconds,'trial_plan':[{'block':task['block'],'position':task['position'],'model_family':task['model'],'policy':task['policy'],'path':task['path'],'trial':task['trial']} for task in tasks if task['phase']=='cost']})
    summary={'status':'failed','command':args.command,'stage':'020','measurement_origin':'not_measured','planned_tasks':len(tasks),'completed_tasks':0,'attempted_tasks':0,'hardware_access_attempted':False,'aggregate_counters_scope':'completed_tasks_only','inferred_records':0,'label_mismatches':0,'max_probability_abs_error':0.,'accepted_updates':0,'verified_reboots':0,'faults_verified':0,'negative_controls_passed':0,'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False}
    try:
        first=contexts[(tasks[0]['model'],tasks[0]['policy'])]
        summary['hardware_access_attempted']=True
        session_preflight(args,s,first,output/'preflight',allow_old=True)
        summary['measurement_origin']='actual_mcu'
        for task in tasks:
            family,policy=task['model'],task['policy'];c=contexts[(family,policy)]
            child=output/task['path'];summary['attempted_tasks']+=1;summary['current_task_path']=task['path']
            child_args=argparse.Namespace(**{**vars(args),'model':family,'policy':policy,'command':task['command'],'output':str(child)})
            print(f"Suite task {task['task']}/{len(tasks)}: {family}/{policy}/{task['command']}",flush=True)
            if task['phase']=='cost':result=trial(child_args,s,c,child,task,reflash=True)
            else:result=campaign(child_args,s,c)
            append(output/'completed_tasks.jsonl',{'task':task,'summary':result})
            summary['completed_tasks']+=1;summary['measurement_origin']='actual_mcu'
            for key in ('inferred_records','label_mismatches','accepted_updates','verified_reboots','faults_verified','negative_controls_passed'):summary[key]+=result[key]
            summary['max_probability_abs_error']=max(summary['max_probability_abs_error'],result['max_probability_abs_error'])
        summary['status']='complete'
    except BaseException as exc:
        summary['error']=f'{type(exc).__name__}: {exc}'
        if 'current_task_path' in summary:summary['failed_task_path']=summary['current_task_path']
        raise
    finally:
        summary['finished_utc_ns']=time.time_ns();s.save(output/'summary.json',summary)
    print(json.dumps({'run':str(output),**summary},allow_nan=False))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('inspect','flash','smoke','faults','negatives','costs','costs-suite','series'))
    parser.add_argument('--model',choices=('lr','dt','all'),default='lr'); parser.add_argument('--policy',choices=('bundle','compatible','whole'),default='bundle')
    parser.add_argument('--rom-recovery',action='store_true',help='explicit flash-only recovery: bypass runtime STATUS gate, keep mandatory ROM MAC guard')
    parser.add_argument('--energy-baseline-seconds',type=int,choices=(0,10),default=0,help='optional secondary costs measurement: idle baseline before each valid update; default0')
    parser.add_argument('--port'); parser.add_argument('--board-id',default='esp32s3-a0f262ebb558'); parser.add_argument('--output'); parser.add_argument('--timeout',type=float,default=30)
    args=parser.parse_args()
    try:
        s=bootstrap()
        if args.rom_recovery and args.command!='flash':raise ValueError('--rom-recovery requires flash')
        if args.energy_baseline_seconds and args.command not in ('costs','costs-suite'):raise ValueError('Energy baseline only allowed for a separately recorded costs/costs-suite run')
        if args.command in ('costs-suite','series'):
            if not args.port or not args.output or not math.isfinite(args.timeout) or args.timeout<=0:raise ValueError('Suite requires --port, fresh --output and positive --timeout')
            s.board_mac(args.board_id)
            pairs={(task['model'],task['policy']) for task in s.suite_plan(args.model)}
            contexts={(family,policy):s.load_context(ROOT,family,policy) for family,policy in sorted(pairs)}
            for c in contexts.values():
                if c['policy_name']=='whole':
                    for key in 'ABC':s.validate_ota(c,key)
            suite(args,s,contexts);return
        c=s.load_context(ROOT,args.model,args.policy)
        if args.policy=='whole':
            for key in 'ABC':s.validate_ota(c,key)
        if args.command=='inspect':
            print(json.dumps({'status':'complete','stage':'020','model_family':args.model,'policy':c['policy'],'kit_manifest_sha256':c['kit_manifest_sha256'],'golden_count':len(c['golden']),'measurement_origin':'not_measured','hardware_access_attempted':False}));return
        if not args.port or not args.output or not math.isfinite(args.timeout) or args.timeout<=0:raise ValueError('Hardware command requires --port, fresh --output and positive --timeout')
        if args.command=='faults' and args.policy!='bundle':raise ValueError('Predetermined checkpoint fault study uses bundle only')
        s.board_mac(args.board_id); campaign(args,s,c)
    except Exception as exc: parser.exit(1,f'error: {type(exc).__name__}: {exc}\n')

if __name__=='__main__': main()
