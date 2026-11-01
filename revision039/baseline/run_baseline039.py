#!/usr/bin/env python3
"""Revision039 paired package/raw/compressed MCU experiment. Author: Oleksandr Kuznetsov.

prepare is offline. run is the only command opening/flashing a physical board.
No offline compressed size or native decoder test is reported as MCU evidence.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import shutil
import sys
import time
import zlib

REPO = Path(__file__).resolve().parents[2]
FAMILIES = ('lr','dt','mlp_float','mlp_int8')
POLICIES = ('bundle','whole','compressed')

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); sys.modules[name]=module; spec.loader.exec_module(module)
    return module
old=load('hardware030_baseline039',REPO/'research030/tools/hardware030.py')
codec=load('codec_baseline039',REPO/'research030/hardware_codec/codec030.py')
reference=load('model_baseline039',REPO/'research030/training/model030.py')
read,save,sha,typed,integer=old.read,old.save,old.sha,old.typed,old.integer

def families_arg(text):
    values=tuple(text.split(','))
    if not values or len(set(values))!=len(values) or any(x not in FAMILIES for x in values):
        raise argparse.ArgumentTypeError('choose unique comma-separated families: '+','.join(FAMILIES))
    return values

def verify_sources(training, prebuilt, families):
    """Reject changed frozen inputs/build payloads before creating an artifact."""
    training,prebuilt=Path(training),Path(prebuilt)
    public={row['path']:row['sha256'] for row in read(REPO/'MANIFEST.sha256.json')['files']}
    canonical={f'models/{role}_{family}.json':public.get(f'paper037/evidence_inputs/training/models/{role}_{family}.json')
               for family in families for role in ('A','B')}
    prior_manifest=training/'result_manifest.json'
    if prior_manifest.is_file():
        pins=read(prior_manifest).get('sha256',{})
    else:
        pins=canonical
    build_settings=set()
    for family in families:
        for role in ('A','B'):
            relative=f'models/{role}_{family}.json'
            actual=sha(training/relative)
            if not pins.get(relative) or actual!=pins[relative] or actual!=canonical.get(relative):
                raise ValueError('frozen model hash mismatch: '+relative)
        for policy in ('bundle','whole'):
            base=prebuilt/f'{family}_{policy}';meta=read(base/'metadata.json')
            if meta.get('stage')!='039' or meta.get('family')!=family or meta.get('policy')!=policy:
                raise ValueError('revision039 build identity mismatch: '+str(base))
            if meta.get('optimization') not in ('Og','O2') or meta.get('idf_version')!='v5.3.2':
                raise ValueError('unsupported build optimization or SDK')
            build_settings.add((meta['optimization'],meta['idf_version']))
            required={'ids_update_lab.bin','bootloader/bootloader.bin','partition_table/partition-table.bin',
                      'ota_data_initial.bin','flash_args','sdkconfig'}
            hashes=meta.get('files_sha256',{})
            if not required.issubset(hashes):raise ValueError('incomplete prebuilt file manifest')
            for relative,digest in hashes.items():
                if relative=='metadata.json':continue  # a manifest cannot hash itself
                path=(base/relative).resolve()
                if not path.is_relative_to(base.resolve()) or sha(path)!=digest:
                    raise ValueError('prebuilt file hash mismatch: '+relative)
            if meta.get('image_sha256')!=sha(base/'ids_update_lab.bin'):
                raise ValueError('prebuilt image identity mismatch')
            if meta.get('phase_gpio') is not None or 'CONFIG_IDS_PHASE_GPIO_ENABLED=y' in (base/'sdkconfig').read_text():
                raise ValueError('timing experiment requires phase instrumentation disabled')
            if meta.get('compressed_full_image_protocol')!='FWZ_BEGIN/FWZ_CHUNK/FWZ_END/FWZ_ABORT':
                raise ValueError('prebuilt lacks compressed updater capability provenance')
            if meta.get('compressed_full_image_enabled') is not (policy=='whole'):
                raise ValueError('prebuilt compressed updater policy mismatch')
    if len(build_settings)!=1:raise ValueError('mixed optimization or SDK would confound policy comparison')
    return next(iter(build_settings))[0]

def prepare(args):
    training=Path(args.training); prebuilt=Path(args.prebuilt_root)
    optimization=verify_sources(training,prebuilt,args.families)
    target=Path(args.output); target.mkdir(parents=True,exist_ok=False)
    result={}
    raw=[[0.]*8,[0.,0.,0.,0.,1.,63.,0.,0.],[1.,64.,64.,0.,1.,64.,1.,64.]]
    for family in args.families:
        models={v:read(training/'models'/f'{v}_{family}.json') for v in ('A','B')}
        dest=target/family; dest.mkdir()
        versions={}
        for version in (1,2,3,4):
            role='A' if version<3 else 'B'; release=f'039-{family[:5]}-{version}'
            blob=codec.sign_envelope(models[role],version,release)
            path=dest/f'v{version}.sids'; path.write_bytes(blob)
            versions[str(version)]=dict(version=version,release=release,path=str(path.relative_to(target)),
                envelope_sha256=sha(path),payload_sha256=hashlib.sha256(blob[16:-256]).hexdigest(),
                envelope_bytes=len(blob),reference=role,identity=codec.envelope_metadata(blob))
        (dest/'bad-contract.sids').write_bytes(codec.bad_contract_envelope(models['B'],1000,'039-bad-contract'))
        expected={}
        for role,model in models.items():
            probabilities,labels=reference.predict(model,raw)
            expected[role]=[dict(probability=float(p),label=int(y)) for p,y in zip(probabilities,labels)]
        save(dest/'golden.json',dict(raw=raw,expected=expected,scope='three deterministic identity smoke inputs, not the expanded numerical panel'))
        policies={}
        for policy in ('bundle','whole'):
            base=prebuilt/f'{family}_{policy}'
            config=(base/'sdkconfig').read_text()
            if 'CONFIG_IDS_PHASE_GPIO_ENABLED=y' in config:
                raise ValueError('timing experiment requires phase instrumentation disabled')
            if not (base/'metadata.json').is_file(): raise ValueError('missing revision039 build provenance')
            metadata=read(base/'metadata.json')
            if metadata.get('stage') != '039':
                raise ValueError('use revision039 prebuilts with actual FWZ updater; old images are not supported')
            factory=dest/policy;factory.mkdir()
            for name in ('bootloader/bootloader.bin','partition_table/partition-table.bin','ota_data_initial.bin','flash_args'):
                path=factory/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(base/name,path)
            shutil.copyfile(base/'metadata.json',factory/'build_metadata.json')
            shutil.copyfile(base/'sdkconfig',factory/'sdkconfig')
            images={}
            for version in ((1,) if policy=='bundle' else (1,2,3,4)):
                envelope=(target/versions[str(version)]['path']).read_bytes()
                image=codec.patch_image((base/'ids_update_lab.bin').read_bytes(),envelope)
                name='ids_update_lab.bin' if version==1 else f'ota-v{version}.bin'
                path=factory/name; path.write_bytes(image)
                entry=dict(path=str(path.relative_to(target)),sha256=sha(path),**codec.image_metadata(image))
                if policy=='whole':
                    entry['ota']=codec.whole_manifest(image,envelope)
                    encoded=zlib.compress(image,level=6); compressed_path=path.with_suffix('.zlib');compressed_path.write_bytes(encoded)
                    entry['compressed']=dict(path=str(compressed_path.relative_to(target)),sha256=sha(compressed_path),
                        bytes=len(encoded),format='zlib',compression_level=6,zlib_version=zlib.ZLIB_VERSION,
                        offline_only=True,reconstructed_sha256=hashlib.sha256(zlib.decompress(encoded)).hexdigest())
                images[str(version)]=entry
            policies[policy]=dict(factory_dir=str(factory.relative_to(target)),images=images,
                template_sha256=sha(base/'ids_update_lab.bin'),build_metadata=metadata)
        result[family]=dict(versions=versions,policies=policies,golden=str((dest/'golden.json').relative_to(target)),
            bad_contract=str((dest/'bad-contract.sids').relative_to(target)),variants=[],
            model_sha256={v:sha(training/'models'/f'{v}_{family}.json') for v in models})
    manifest=dict(schema=1,stage='039',prepared_before_hardware=True,families=result,
        optimization=optimization,
        training_path=str(training.resolve()),prebuilt_root=str(prebuilt.resolve()),
        frozen_model_manifest_sha256=sha(REPO/'MANIFEST.sha256.json'),
        transitions={'warmup':'A1 to A2, excluded','3':'A2 to B3, reused target','4':'B3 to C4, same B parameters, reused target'},
        physical_power_loss_tested=False,energy_measured=False,measurement_origin='offline_preparation',
        validation_only_synthetic=False,compression='zlib level 6, miniz_tinfl 3.0.2 on MCU')
    save(target/'artifacts.json',manifest);old.pins(target)
    return manifest

class Session(old.Session):
    def __init__(self,*args,experiment_policy,**kwargs):
        super().__init__(*args,**kwargs);self.experiment_policy=experiment_policy
    def cost_bundle(self,version,measured):
        blob=(self.artifacts['root']/self.f['versions'][str(version)]['path']).read_bytes()
        start=time.monotonic_ns()
        self.evidence.event('mutation_intent',command='UPDATE',version=version,envelope_sha256=hashlib.sha256(blob).hexdigest())
        reply=self.link.command('UPDATE '+blob.hex(),{'update'})
        typed(reply,dict(event='update',accepted=True,reason='ok',ready=True,version=version,
              policy='bundle',timing_schema=3,timing_measured=True),'package update')
        timing=reply.get('timing_us',{})
        if sum(integer(timing,k) for k in old.TIMING_STAGES)>integer(timing,'total'):
            raise RuntimeError('package timing components exceed total')
        typed(reply,dict(model_erase_bytes=math.ceil((len(blob)+8)/4096)*4096,
              model_write_bytes=len(blob)+8),'package flash accounting')
        self.version=version;self.status(version)
        row=dict(policy='bundle',family=self.family,version=version,measured=measured,
            transition='A_to_B_reused' if version==3 else 'B_to_C_same_parameters_reused' if version==4 else 'warmup_A_to_A',
            artifact_bytes=len(blob),tx_wire_bytes=len('UPDATE '+blob.hex()+'\n'),
            tx_wire_bytes_scope='update commands only; STATUS, REBOOT and inference excluded',
            device_active_us=timing['total'],host_elapsed_ns=time.monotonic_ns()-start,
            model_erase_bytes=reply['model_erase_bytes'],model_write_bytes=reply['model_write_bytes'],
            journal_erase_bytes=reply['journal_erase_bytes'],journal_write_bytes=reply['journal_write_bytes'],response=reply)
        self.evidence.event('revision039_cost',**row);self.summary['accepted_updates']+=1
        return row
    def cost_whole(self,version,measured,negative=None):
        image_meta=self.f['policies']['whole']['images'][str(version)]
        raw=(self.artifacts['root']/image_meta['path']).read_bytes()
        compressed=self.experiment_policy=='compressed';prefix='FWZ' if compressed else 'FW'
        encoded=(self.artifacts['root']/image_meta['compressed']['path']).read_bytes() if compressed else raw
        ota=image_meta['ota'];meta,sig=ota['metadata_hex'],ota['signature_hex']
        if negative=='signature':sig=sig[:-2]+format(int(sig[-2:],16)^1,'02x')
        if negative=='image_hash':
            changed=raw[:-1]+bytes([raw[-1]^1]);encoded=zlib.compress(changed,6) if compressed else changed
        if negative=='compressed_corruption':encoded=bytes([encoded[0]^1])+encoded[1:]
        prior=self.version;start=time.monotonic_ns();wire=0
        self.evidence.event('mutation_intent',command=prefix+'_BEGIN',version=version,negative=negative,
            image_sha256=image_meta['sha256'],encoded_sha256=hashlib.sha256(encoded).hexdigest())
        def command(line,events):
            nonlocal wire
            wire+=len(line)+1
            return self.link.command(line,events)
        begin_line=f'{prefix}_BEGIN {meta} {sig}'+(f' {len(encoded)}' if compressed else '')
        rejected=negative in ('signature','replay')
        begin=command(begin_line,{'fw_error'} if rejected else {'fw_begin'})
        if rejected:
            typed(begin,dict(event='fw_error',ok=False,error='signature' if negative=='signature' else 'non_monotonic_version'),'manifest rejection')
            self.status(prior);self.summary['negative_controls_passed']+=1;return None
        typed(begin,dict(event='fw_begin',ok=True,version=version,size=len(raw),
              encoded_size=len(encoded),encoding='zlib' if compressed else 'identity',timing_schema=2,crypto_context='shared_warm'),'OTA begin')
        totals={key:0 for key in ('write_sum_us','hash_sum_us','chunk_sum_us','chunk_count')}
        for offset in range(0,len(encoded),1024):
            chunk=encoded[offset:offset+1024]
            reply=command(f'{prefix}_CHUNK {offset} {chunk.hex()}',{'fw_error','fw_chunk'})
            if negative=='compressed_corruption':
                typed(reply,dict(event='fw_error',ok=False,error='decompression_or_write'),'invalid compressed stream')
                self.status(prior);self.summary['negative_controls_passed']+=1;return None
            typed(reply,dict(event='fw_chunk',ok=True,offset=offset+len(chunk),timing_schema=2),
                  f'OTA chunk ({prefix}, offset={offset}, negative={negative!r}, response={reply!r})')
            w,h,t=integer(reply,'write_us'),integer(reply,'hash_us'),integer(reply,'chunk_us')
            if w+h>t:raise RuntimeError('nested write/hash exceeds chunk interval')
            for key,value in (('write_sum_us',w),('hash_sum_us',h),('chunk_sum_us',t),('chunk_count',1)):totals[key]+=value
            typed(reply,totals,'cumulative timings')
        ready=command(prefix+'_END',{'fw_error'} if negative=='image_hash' else {'fw_ready'})
        if negative=='image_hash':
            typed(ready,dict(event='fw_error',ok=False,error='image_sha256'),'reconstructed hash rejection')
            self.status(prior);self.summary['negative_controls_passed']+=1;return None
        typed(ready,dict(event='fw_ready',ok=True,version=version,bytes=len(raw),encoded_bytes=len(encoded),
            reboot_required=True,timing_schema=2,begin_us=begin['begin_us'],**totals),'OTA completion')
        if integer(ready,'device_active_us')!=integer(begin,'begin_us')+totals['chunk_sum_us']+integer(ready,'finalize_us'):
            raise RuntimeError('active interval double counting or omission')
        self.status(prior);self.reboot(version)
        row=dict(policy=self.experiment_policy,family=self.family,version=version,measured=measured,
            transition='A_to_B_reused' if version==3 else 'B_to_C_same_parameters_reused' if version==4 else 'warmup_A_to_A',
            artifact_bytes=len(encoded)+84+256,raw_image_bytes=len(raw),encoded_bytes=len(encoded),
            tx_wire_bytes=wire,device_active_us=ready['device_active_us'],
            tx_wire_bytes_scope='update commands only; STATUS, REBOOT and inference excluded',
            host_elapsed_ns=time.monotonic_ns()-start,image_sha256=image_meta['sha256'],
            image_partition_erase_bytes=math.ceil(len(raw)/4096)*4096,image_partition_write_bytes=len(raw),
            otadata_flash_work_included=False,begin=begin,ready=ready)
        self.evidence.event('revision039_cost',**row);self.summary['accepted_updates']+=1
        return row

def plan(families,repetitions):
    if repetitions<1:raise ValueError('repetitions must be positive')
    rows=[]
    for block in range(repetitions):
        rotated=families[block%len(families):]+families[:block%len(families)]
        for i,family in enumerate(rotated):
            j=(block+i)%len(POLICIES);policies=POLICIES[j:]+POLICIES[:j]
            for policy in policies:rows.append(dict(block=block+1,family=family,policy=policy))
    return rows

def run(args):
    artpath=Path(args.artifacts);old.verify_pins(artpath)
    art=read(artpath/'artifacts.json');art['root']=artpath
    if art.get('stage')!='039':raise ValueError('not revision039 prepared artifacts')
    if art.get('validation_only_synthetic') is not False:
        raise ValueError('synthetic or unclassified artifacts cannot enter the measured campaign')
    if art.get('optimization') not in ('Og','O2'):
        raise ValueError('prepared artifacts lack a common optimization identity')
    if any(family not in art['families'] for family in args.families):raise ValueError('requested family not prepared')
    output=Path(args.output);output.mkdir(parents=True,exist_ok=False)
    summary=old.empty_summary();summary.update(stage='039',board_id=args.board_id,energy_measured=False,
        optimization=art['optimization'],
        cost_observations=[],expected_measured_observations=args.repetitions*len(args.families)*len(POLICIES)*2)
    schedule=plan(args.families,args.repetitions)
    save(output/'plan.json',dict(stage='039',plan=schedule,board_id=args.board_id,
        optimization=art['optimization'],
        artifact_manifest_sha256=sha(artpath/'evidence_manifest.json'),warmup='A1->A2 excluded',
        measurements=['A2->B3 reused','B3->C4 reused same model parameters'],
        energy_measured=False,physical_power_loss_tested=False))
    session=None
    try:
        for row in schedule:
            base='bundle' if row['policy']=='bundle' else 'whole'
            dest=output/f'b{row["block"]:02d}-{row["family"]}-{row["policy"]}';dest.mkdir()
            summary['hardware_access_attempted']=True
            old.provision(args,dest,art,row['family'],base)
            session=Session(args,dest,art,row['family'],base,summary,experiment_policy=row['policy']);session.open()
            phase=session.link.command('PHASE_STATUS',{'phase_status'})
            typed(phase,dict(event='phase_status',ok=True,enabled=False),'timing firmware instrumentation gate')
            session.infer(1)
            if row['block']==1:
                session.phase('negative_controls')
                if base=='bundle':
                    for kind in ('signature','contract','replay'):session.reject(kind)
                else:
                    session.cost_whole(2,False,'signature');session.cost_whole(2,False,'image_hash')
                    session.cost_whole(1,False,'replay')
                    if row['policy']=='compressed':session.cost_whole(2,False,'compressed_corruption')
            session.phase('warmup_A_to_A')
            (session.cost_bundle if base=='bundle' else session.cost_whole)(2,False)
            for version in (3,4):
                session.phase('measured_'+('A_to_B_reused' if version==3 else 'B_to_C_same_parameters_reused'))
                observation=(session.cost_bundle if base=='bundle' else session.cost_whole)(version,True)
                observation.update(block=row['block'],board_id=args.board_id)
                summary['cost_observations'].append(observation)
                session.infer(version)
            session.phase('post_measurement_replay')
            if base=='bundle':session.reject('replay')
            else:session.cost_whole(4,False,'replay')
            session.close();session=None;summary['completed_trials']+=1
            save(output/'summary.json',summary)
        if len(summary['cost_observations'])!=summary['expected_measured_observations']:
            raise RuntimeError('incomplete measurement matrix')
        summary['status']='complete'
    except Exception as exc:
        summary['error']=f'{type(exc).__name__}: {exc}';raise
    finally:
        if session:session.close()
        save(output/'summary.json',summary);old.pins(output)
    return summary

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare',help='offline artifacts only; no serial access')
    prep.add_argument('--training',default=str(REPO/'paper037/evidence_inputs/training'))
    prep.add_argument('--prebuilt-root',required=True);prep.add_argument('--output',required=True)
    prep.add_argument('--families',type=families_arg,default=FAMILIES)
    acquire=sub.add_parser('run',help='flash and acquire from the explicitly identified ESP32-S3')
    for name in ('artifacts','port','board-id','output'):acquire.add_argument('--'+name,required=True)
    acquire.add_argument('--families',type=families_arg,default=FAMILIES)
    acquire.add_argument('--repetitions',type=int,default=10);acquire.add_argument('--timeout',type=float,default=20.)
    args=parser.parse_args(argv)
    result=prepare(args) if args.command=='prepare' else run(args)
    print(json.dumps(dict(stage='039',command=args.command,status=result.get('status','prepared'),
        measurement_origin=result.get('measurement_origin')),indent=2))
if __name__=='__main__':main()
