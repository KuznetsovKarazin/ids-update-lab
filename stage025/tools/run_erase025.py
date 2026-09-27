#!/usr/bin/env python3
"""Stage025: inspect offline, then pilot, then a frozen120-chain erase comparison.

Each chain provisions factory A after a ROM MAC check. No mutation retry/resume.
Software checkpoint recovery only. Device counters are successful flash requests.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import platform
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def bootstrap(root=ROOT):
    root=Path(root).resolve(); data=json.loads((root/'KIT_MANIFEST.json').read_text(encoding='utf-8')); files=data.get('sha256',data.get('files',data))
    for name in ('tools/run_erase025.py','tools/erase_support025.py'):
        if files.get(name)!=hashlib.sha256((root/name).read_bytes()).hexdigest(): raise ValueError('Unpinned runner/support '+name)
    s=load_module('erase_support025_runtime',root/'tools/erase_support025.py'); files=s.pins(root);s.load_base(root)
    old=load_module('erase025_immutable_runner',root/'tools/run_completion.py')
    return s,old,files


def trial_class(old):
    class EraseTrial(old.Trial):
        def update(self,key,checkpoint=None):
            if checkpoint: return super().update(key,checkpoint)
            blob=self.c['envelopes'][key]; start=old.stamp()
            self.evidence.event('mutation_intent',command='UPDATE',candidate=key,envelope_sha256=hashlib.sha256(blob).hexdigest(),checkpoint=None)
            reply=self.link.command('UPDATE '+blob.hex(),{'update'})
            self.s.typed(reply,{'event':'update','accepted':True,'reason':'ok','ready':True,'version':self.c['models'][key].version,'policy':'bundle'},'accepted025 update')
            timings=self.s.bundle_timing(reply); counters=self.s.storage(reply,self.c,key)
            after=self.status(key)
            self.evidence.event('cost',kind='component',configuration=self.c['configuration'],model_key=key,transition='A_to_B_clean' if key=='B' else 'B_to_C_reused',envelope_bytes=len(blob),payload_bytes=len(blob)-272,tx_wire_bytes=2*len(blob)+8,timing_us=timings,latency_us=reply['latency_us'],storage_metrics_schema=1,storage_metrics_kind='successful_flash_request_bytes',erase_policy=self.c['erase_policy'],**counters,response=reply,status_response=after,journal_rollover_excluded=True)
            end=old.stamp();self.evidence.event('update_interval',model_key=key,accepted_updates=1,monotonic_start_ns=start['monotonic_ns'],monotonic_end_ns=end['monotonic_ns'],utc_start_ns=start['utc_ns'],utc_end_ns=end['utc_ns'],scope='UPDATE through acknowledged STATUS; includes transport; secondary only')
            self.summary['accepted_updates']+=1
            return key
        def reject(self,blob,reason,current):
            self.evidence.event('mutation_intent',command='UPDATE',negative_expected=reason,envelope_sha256=hashlib.sha256(blob).hexdigest())
            reply=self.link.command('UPDATE '+blob.hex(),{'update'})
            self.s.typed(reply,{'event':'update','accepted':False,'reason':reason,'ready':True,'version':self.c['models'][current].version,'policy':'bundle'},'negative025 rejection')
            self.s.bundle_timing(reply,accepted=False);self.s.storage(reply,self.c,accepted=False);self.status(current)
            self.summary['negative_controls_passed']+=1
    return EraseTrial


def preflight(args,s,old,c,out):
    out.mkdir(exist_ok=False);api=old.legacy(c['root']);e=api.Evidence(out);link=api.Link(c['serial'],e,args.timeout)
    try:
        reply=link.open(args.port);s.save(out/'status.json',reply)
        s.known_status(reply,c['root']);e.event('recognized_initial_status',response=reply,model_version_not_constrained=True)
    finally:link.close();e.close()


def empty_summary(command):
    return {'stage':'025','command':command,'status':'failed','measurement_origin':'not_measured','data_origin':'TON_IoT_development','hardware_access_attempted':False,'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False,'max_probability_abs_error':0.,**{k:0 for k in ('inferred_records','label_mismatches','accepted_updates','verified_reboots','faults_verified','negative_controls_passed')}}


def trial(args,s,old,c,out,item,Trial):
    out.mkdir(exist_ok=False);summary={**empty_summary(args.command),'trial':item,'configuration':c['configuration'],'erase_policy':c['erase_policy'],'kit_manifest_sha256':c['kit_manifest_sha256'],'board_id':args.board_id,'measurement_origin':'not_measured'};t=None
    try:
        summary['hardware_access_attempted']=True
        old.flash_factory(args,out/'provisioning',s,c)
        t=Trial(args,s,c,out,summary);t.open('A')
        if item['kind']=='fault':
            t.setphase('setup_B');t.update('B');t.setphase('reused_'+item['checkpoint'])
            recovered=t.update('C',checkpoint=item['checkpoint']);t.infer(recovered,c['golden'][:8])
            t.reject(c['envelopes']['A'],'replay_or_downgrade',recovered);t.infer(recovered,c['golden'][:1])
        else:
            rows=c['golden'] if item['kind']=='smoke' else c['golden'][:16]
            for key in 'ABC':
                t.setphase(key)
                if key!='A':t.update(key)
                t.infer(key,rows)
            t.setphase('C_after_reboot');t.reboot('C');t.infer('C',c['golden'][:1])
            if item['kind']=='smoke':
                # Both controls follow C; signature is evaluated before replay.
                t.setphase('negative_signature');t.reject((c['family']/'bad-signature.sids').read_bytes(),'signature','C')
                t.setphase('negative_replay');t.reject(c['envelopes']['C'],'replay_or_downgrade','C')
        summary['status']='complete'
    except BaseException as exc:
        summary['error']=f'{type(exc).__name__}: {exc}';raise
    finally:
        if t:t.close()
        summary['finished_utc_ns']=time.time_ns();s.save(out/'summary.json',summary)
        s.save(out/'evidence_manifest.json',{'sha256':{p.relative_to(out).as_posix():s.sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='evidence_manifest.json'}})
    return summary


def campaign(args,s,old,contexts,files):
    pilot=s.verify_pilot(args.pilot_run,ROOT,args.board_id) if args.command=='series' else None
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False);items=s.plan(args.command);summary=empty_summary(args.command)
    summary.update({'planned_trials':len(items),'attempted_trials':0,'completed_trials':0,'aggregate_counters_scope':'completed_trials_only','board_id':args.board_id,'kit_manifest_sha256':s.sha(ROOT/'KIT_MANIFEST.json')})
    manifest={'stage':'025','schema':1,'command':args.command,'created_before_hardware':True,'created_utc_ns':time.time_ns(),'kit_manifest_sha256':s.sha(ROOT/'KIT_MANIFEST.json'),'protocol_sha256':s.sha(ROOT/'protocol.json'),'board_id':args.board_id,'expected_rom_mac':s.board_mac(args.board_id),'port':args.port,'parameters':vars(args),'trial_plan':items,'pilot_gate':pilot,'source_pins':files,'runtime':{'python':sys.version,'platform':platform.platform()},'data_origin':'TON_IoT_development','physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False,'order_rule':'left rotate configurations by floor(zero_based_block/2) mod4; reverse odd zero_based blocks','within_chain_caveat':'A->B clean slot1 precedes B->C reused slot0; source version, order, and slot are confounded with erase condition','flash_request_metric':'successful API request bytes, not physical wear or internal flash-controller operations','provisioning':'factory reflash+erase0x3b0000/0x22000 before every chain; excluded cost; NVS retained; software rollback history reset for laboratory'}
    s.save(out/'campaign_manifest.json',manifest)
    if pilot:
        for source,target in (('campaign_manifest.json','pilot_manifest.json'),('summary.json','pilot_summary.json')):
            (out/target).write_bytes((Path(args.pilot_run)/source).read_bytes())
    Trial=trial_class(old)
    try:
        summary['hardware_access_attempted']=True
        preflight(args,s,old,contexts[items[0]['configuration']],out/'preflight')
        for item in items:
            c=contexts[item['configuration']];summary['attempted_trials']+=1;summary['current_trial_path']=item['path']
            print(f"{args.command} {item['trial']}/{len(items)}: {item['configuration']} {item['kind']} "+item.get('checkpoint',''),flush=True)
            result=trial(args,s,old,c,out/item['path'],item,Trial)
            old.append(out/'completed_trials.jsonl',{'trial':item,'summary':result});summary['completed_trials']+=1;summary['measurement_origin']='actual_mcu'
            for key in s.COUNTERS:summary[key]+=result[key]
            summary['max_probability_abs_error']=max(summary['max_probability_abs_error'],result['max_probability_abs_error'])
        summary['status']='complete'
    except BaseException as exc:
        summary['error']=f'{type(exc).__name__}: {exc}';raise
    finally:
        summary['finished_utc_ns']=time.time_ns();s.save(out/'summary.json',summary)
        s.save(out/'run_evidence_manifest.json',{'sha256':{p.relative_to(out).as_posix():s.sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='run_evidence_manifest.json'}})
    print(json.dumps({'run':str(out),**summary},allow_nan=False))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=('inspect','pilot','series'))
    parser.add_argument('--port');parser.add_argument('--board-id',default='esp32s3-a0f262ebb558');parser.add_argument('--output');parser.add_argument('--timeout',type=float,default=20);parser.add_argument('--pilot-run')
    args=parser.parse_args(argv)
    try:
        s,old,files=bootstrap();contexts={name:s.load_context(ROOT,name,files) for name in s.CONFIGURATIONS}
        if args.command=='inspect':
            print(json.dumps({'status':'complete','stage':'025','measurement_origin':'not_measured','hardware_access_attempted':False,'kit_manifest_sha256':s.sha(ROOT/'KIT_MANIFEST.json'),'configurations':{name:{'expected_build':c['build']['images']['A']['expected_build'],'golden_records':len(c['golden']),'update_storage':s.expected_storage(len(c['envelopes']['B']),c['erase_policy'])} for name,c in contexts.items()},'pilot_trials':28,'series_trials':120,'series_updates':240}));return 0
        if not args.port or not args.output or not math.isfinite(args.timeout) or args.timeout<=0:raise ValueError('Need --port, fresh --output, positive --timeout')
        s.board_mac(args.board_id)
        if args.command=='series' and not args.pilot_run: raise ValueError('Series requires --pilot-run from complete same-kit same-board pilot')
        if args.command=='pilot' and args.pilot_run: raise ValueError('--pilot-run applies to series only')
        campaign(args,s,old,contexts,files);return 0
    except (Exception,KeyboardInterrupt) as exc:parser.exit(1,f'error: {type(exc).__name__}: {exc}\n')

if __name__=='__main__':raise SystemExit(main())
