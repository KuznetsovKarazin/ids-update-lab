"""One finite MCU campaign; every mutation has an append-only intent/receipt.

Provisioning is laboratory setup, outside cost/energy intervals. No mutation is
retried. The first error terminates the campaign and preserves partial evidence.
"""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

KIT = Path(__file__).resolve().parents[1]
FAMILIES = ('lr', 'dt', 'mlp_float', 'mlp_int8')
CHECKPOINTS = ('after_erase', 'after_write', 'after_verify', 'after_slot_commit', 'after_journal_body', 'after_commit')
BLOCKS = 10
BUNDLE_UPDATES = 128
WHOLE_UPDATES = 4
QUIET_AFTER_UPDATE_SECONDS = .2
TOLERANCE = 2e-6
TIMING_STAGES = ('candidate_verify','erase','body_write','readback','readback_verify','commit','journal_prepare','journal_body','journal_commit')

def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
    return h.hexdigest()

def save(path, data):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(data,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')

def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))

def pins(directory, name='evidence_manifest.json'):
    directory=Path(directory)
    save(directory/name,{'sha256':{p.relative_to(directory).as_posix():sha(p) for p in sorted(directory.rglob('*')) if p.is_file() and p.name!=name and '__pycache__' not in p.parts}})

def verify_pins(directory,name='evidence_manifest.json'):
    directory=Path(directory).resolve();items=read(directory/name).get('sha256')
    if not isinstance(items,dict) or not items:raise ValueError('Missing evidence manifest '+str(directory/name))
    for relative,digest in items.items():
        p=(directory/relative).resolve()
        if not p.is_relative_to(directory) or '\\' in relative or '..' in Path(relative).parts or not p.is_file() or sha(p)!=digest:raise ValueError('Evidence SHA256 mismatch: '+relative)
    return items

def typed(got, expected, context):
    for key,value in expected.items():
        if got.get(key)!=value or type(got.get(key)) is not type(value):
            raise RuntimeError(f'{context}: {key}={got.get(key)!r}, expected {value!r}')

def integer(d,key):
    value=d.get(key)
    if type(value) is not int or value<0:raise RuntimeError('Invalid nonnegative counter '+key)
    return value

def board_mac(board):
    if not re.fullmatch('esp32s3-[0-9a-f]{12}',board):raise ValueError('Expected board id esp32s3-<12 lowercase hexadecimal digits>')
    return ':'.join(board[8:][i:i+2] for i in range(0,12,2))

def cost_plan():
    plan=[]
    for b in range(BLOCKS):
        families=FAMILIES[b%4:]+FAMILIES[:b%4]
        for i,family in enumerate(families):
            policies=('bundle','whole') if (b+FAMILIES.index(family))%2==0 else ('whole','bundle')
            for policy in policies:
                plan.append(dict(block=b+1,family=family,policy=policy,updates=BUNDLE_UPDATES if policy=='bundle' else WHOLE_UPDATES,id=f'b{b+1:02d}-{family}-{policy}'))
    return plan

def prepare(training, output, allow_validation=False):
    """Prepare all artifacts before energy acquisition; no fitting on the MCU."""
    training,output=Path(training),Path(output)
    output.mkdir(parents=True,exist_ok=False)
    codec=module('codec030_runner',KIT/'hardware_codec/codec030.py')
    ref=module('model030_runner',KIT/'training/model030.py')
    training_summary=read(training/'summary.json')
    if training_summary.get('status')!='complete':raise ValueError('Training has not completed')
    synthetic=bool(training_summary.get('validation_only_synthetic') or training_summary.get('scientific_full_result') is False)
    if synthetic and not allow_validation:raise ValueError('Synthetic validation fitting cannot enter the hardware campaign')
    verify_pins(training,'result_manifest.json')
    (output/'public.pem').write_bytes(codec.public_pem())
    families={}
    for family in FAMILIES:
        models={v:read(training/'models'/f'{v}_{family}.json') for v in ('A','B')}
        golden=read(training/'hardware_vectors'/f'B_{family}.json')
        raw=golden['raw']
        if not raw or len(raw)>1024:raise ValueError('Missing or excessive frozen hardware vectors')
        target=output/family;target.mkdir()
        versions={}
        # The same B semantics are republished with monotonic release versions.
        for v in range(1,BUNDLE_UPDATES+3):
            m=models['A' if v==1 else 'B'];release=f'030-{family[:5]}-{v}'
            blob=codec.sign_envelope(m,v,release)
            if not 272<len(blob)<=4096:raise ValueError('Envelope exceeds reviewed MCU line/storage capacity')
            p=target/f'v{v:03d}.sids';p.write_bytes(blob)
            versions[str(v)]=dict(version=v,release=release,path=str(p.relative_to(output)),envelope_sha256=sha(p),payload_sha256=hashlib.sha256(blob[16:-256]).hexdigest(),envelope_bytes=len(blob),reference='A' if v==1 else 'B',identity=codec.envelope_metadata(blob))
        # Re-sign a future candidate with an incompatible contract. The codec
        # helper changes the contract before signing, keeping a valid signature.
        bad_contract=codec.bad_contract_envelope(models['B'],1000,f'030-{family[:5]}-bad')
        (target/'bad-contract.sids').write_bytes(bad_contract)
        refs={}
        for key,m in models.items():
            p,y=ref.predict(m,raw)
            refs[key]=[dict(probability=float(a),label=int(b)) for a,b in zip(p,y)]
        variants=[]
        for i,path in enumerate(sorted((training/'models').glob(family+'_*.json'))):
            m=read(path);key=path.stem
            if m['kind']!=family:raise ValueError('Variant family differs')
            version=201+i;release=f'030-var-{version}'
            blob=codec.sign_envelope(m,version,release);dest=target/f'v{version:03d}.sids';dest.write_bytes(blob)
            versions[str(version)]=dict(version=version,release=release,path=str(dest.relative_to(output)),envelope_sha256=sha(dest),payload_sha256=hashlib.sha256(blob[16:-256]).hexdigest(),envelope_bytes=len(blob),reference=key,identity=codec.envelope_metadata(blob))
            p,y=ref.predict(m,raw);refs[key]=[dict(probability=float(a),label=int(b)) for a,b in zip(p,y)]
            variants.append(dict(model=key,version=version,model_sha256=sha(path)))
        if variants:
            blob=codec.sign_envelope(models['B'],300,'030-restored-B');dest=target/'v300.sids';dest.write_bytes(blob)
            versions['300']=dict(version=300,release='030-restored-B',path=str(dest.relative_to(output)),envelope_sha256=sha(dest),payload_sha256=hashlib.sha256(blob[16:-256]).hexdigest(),envelope_bytes=len(blob),reference='B',identity=codec.envelope_metadata(blob))
        save(target/'golden.json',dict(raw=raw,expected=refs,source=golden,model_sha256={k:sha(training/'models'/f'{k}_{family}.json') for k in models}))
        templates={}
        for policy in ('bundle','whole'):
            base=KIT/'prebuilt'/f'{family}_{policy}'
            factory=target/policy;factory.mkdir()
            for name in ('bootloader/bootloader.bin','partition_table/partition-table.bin','ota_data_initial.bin','flash_args'):
                (factory/name).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(base/name,factory/name)
            images={}
            for v in (1,) if policy=='bundle' else range(1,WHOLE_UPDATES+3):
                envelope=(output/versions[str(v)]['path']).read_bytes()
                image=codec.patch_image((base/'ids_update_lab.bin').read_bytes(),envelope)
                name='ids_update_lab.bin' if v==1 else f'ota-v{v}.bin'
                (factory/name).write_bytes(image)
                meta=codec.image_metadata(image)
                entry=dict(path=str((factory/name).relative_to(output)),sha256=sha(factory/name),**meta)
                if policy=='whole' and v>1:entry['ota']=codec.whole_manifest(image,envelope)
                images[str(v)]=entry
            templates[policy]=dict(factory_dir=str(factory.relative_to(output)),images=images,template_sha256=sha(base/'ids_update_lab.bin'))
        families[family]=dict(versions=versions,policies=templates,golden=str((target/'golden.json').relative_to(output)),bad_contract=str((target/'bad-contract.sids').relative_to(output)),variants=variants)
    manifest=dict(schema=1,stage='030',prepared_before_hardware=True,families=families,training_summary_sha256=sha(training/'summary.json'),cost_plan=cost_plan(),probability_tolerance=TOLERANCE,physical_power_loss_tested=False,validation_only_synthetic=synthetic)
    save(output/'artifacts.json',manifest);pins(output)
    return manifest

def esptool(args,directory,name,tail,cwd):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    argv=[sys.executable,'-m','esptool','--chip','esp32s3','--port',args.port,*tail]
    save(directory/(name+'-intent.json'),dict(argv=argv,cwd=str(cwd),utc_ns=time.time_ns(),monotonic_ns=time.monotonic_ns()))
    with (directory/(name+'.log')).open('x',encoding='utf-8') as f:
        result=subprocess.run(argv,cwd=cwd,stdout=f,stderr=subprocess.STDOUT,timeout=180,check=False)
    save(directory/(name+'-result.json'),dict(returncode=result.returncode,log_sha256=sha(directory/(name+'.log')),utc_ns=time.time_ns()))
    if result.returncode:raise RuntimeError(f'esptool {name} failed: {directory/name}.log')
    return (directory/(name+'.log')).read_text(encoding='utf-8',errors='replace')

def provision(args,out,artifacts,family,policy):
    directory=Path(out)/'provisioning';factory=artifacts['root']/artifacts['families'][family]['policies'][policy]['factory_dir']
    log=esptool(args,directory,'rom_identity',['--after','hard_reset','flash_id'],factory)
    macs={x.lower() for x in re.findall(r'MAC:\s*([0-9a-fA-F:]{17})',log)}
    if macs!={board_mac(args.board_id)} or 'ESP32-S3' not in log:raise RuntimeError('ROM chip/MAC mismatch; write not issued')
    save(directory/'factory_image_binding.json',dict(image_sha256=sha(factory/'ids_update_lab.bin'),family=family,policy=policy,template_patching=True,elf_identifies_template_not_final_image=True))
    esptool(args,directory,'write_factory',['-b','460800','--after','no_reset','write_flash','@flash_args'],factory)
    esptool(args,directory,'erase_model_state',['--after','no_reset' if policy=='whole' else 'hard_reset','erase_region','0x3b0000','0x22000'],factory)
    if policy=='whole':esptool(args,directory,'erase_inactive_ota',['--after','hard_reset','erase_region','0x1e0000','0x1d0000'],factory)

class Session:
    def __init__(self,args,out,artifacts,family,policy,summary):
        self.args,self.out,self.artifacts,self.family,self.policy,self.summary=args,Path(out),artifacts,family,policy,summary
        self.f=artifacts['families'][family];self.gold=read(artifacts['root']/self.f['golden'])
        serial=module('serial030_transport',KIT/'tools/vendor/serial_transport.py')
        api=module('serial030_evidence',KIT/'tools/vendor/evidence_link.py')
        self.evidence=api.Evidence(out);self.link=api.Link(serial,self.evidence,args.timeout)
        self.version=1
    def phase(self,value):self.evidence.phase=value
    def identity(self,version,event='status'):
        v=self.f['versions'][str(version)]
        image=self.f['policies'][self.policy]['images'][str(version if self.policy=='whole' else 1)]
        expected=dict(event=event,ready=True,reason='ok',version=version,release=v['release'],policy='whole_firmware' if self.policy=='whole' else 'bundle',feature_count=8,bundle_sha256=v['payload_sha256'],chip='esp32s3',build=image['expected_build'],runtime_abi=v['identity']['runtime_abi'],schema=v['identity']['schema'],pretransform=v['identity']['pretransform'],data_origin='TON_IoT_temporal_030')
        return expected
    def status(self,version=None):
        version=self.version if version is None else version
        reply=self.link.command('STATUS',{'status'});typed(reply,self.identity(version),'STATUS');return reply
    def open(self):
        reply=self.link.open(self.args.port);typed(reply,self.identity(1),'initial STATUS');self.evidence.event('initial_status_verified',response=reply)
        self.summary['measurement_origin']='actual_mcu';return reply
    def infer(self,version,count=None):
        expected=self.gold['expected'][self.f['versions'][str(version)]['reference']]
        pairs=list(zip(self.gold['raw'],expected))
        if count is not None:pairs=pairs[:count]
        for i,(raw,ref) in enumerate(pairs):
            reply=self.link.command('INFER '+','.join(format(float(x),'.9g') for x in raw),{'inference'})
            typed(reply,dict(event='inference',version=version,policy='whole_firmware' if self.policy=='whole' else 'bundle',bundle_sha256=self.f['versions'][str(version)]['payload_sha256']),'INFER identity')
            p=reply.get('probability');label=reply.get('label')
            if type(p) not in (int,float) or not math.isfinite(p) or not 0<=p<=1 or type(label) is not int:raise RuntimeError('Malformed inference')
            err=abs(p-ref['probability']);matched=label==ref['label']
            self.evidence.record(dict(index=i,raw=raw,expected=ref,response=reply,label_match=matched,probability_abs_error=err),'observations')
            self.summary['inferred_records']+=1;self.summary['label_mismatches']+=int(not matched)
            self.summary['max_probability_abs_error']=max(self.summary['max_probability_abs_error'],err)
            if not matched or err>TOLERANCE:raise RuntimeError(f'{self.family} numerical mismatch on frozen input {i}; no retry')
            if len(pairs)>32 and ((i+1)%64==0 or i+1==len(pairs)):print(f'{self.family}/{self.policy} v{version}: {i+1}/{len(pairs)}',flush=True)
    def reboot(self,version):
        self.evidence.event('mutation_intent',command='REBOOT',expected_version=version)
        self.link.allow_reconnect=True;start=time.monotonic_ns()
        try:
            typed(self.link.command('REBOOT',{'reboot'}),dict(event='reboot',fault_kind='software_restart'),'REBOOT')
            boot=self.link.receive({'boot'});typed(boot,self.identity(version,'boot'),'reboot identity')
            boot_ns=time.monotonic_ns()-start;self.version=version;self.status(version)
            self.evidence.event('reboot_verified',version=version,command_to_boot_ns=boot_ns,command_to_status_ns=time.monotonic_ns()-start,physical_power_loss_tested=False)
            self.summary['verified_reboots']+=1
        finally:self.link.allow_reconnect=False
    def bundle(self,version,checkpoint=None):
        blob=(self.artifacts['root']/self.f['versions'][str(version)]['path']).read_bytes()
        prior=self.version
        if checkpoint:typed(self.link.command('ARM_FAIL '+checkpoint,{'armed'}),dict(event='armed',checkpoint=checkpoint),'ARM_FAIL')
        self.evidence.event('mutation_intent',command='UPDATE',version=version,envelope_sha256=hashlib.sha256(blob).hexdigest(),checkpoint=checkpoint)
        if checkpoint:
            self.link.allow_reconnect=True
            try:
                typed(self.link.command('UPDATE '+blob.hex(),{'fault_checkpoint'}),dict(event='fault_checkpoint',checkpoint=checkpoint,fault_kind='software_restart'),'fault')
                target=version if checkpoint=='after_commit' else prior
                typed(self.link.receive({'boot'}),self.identity(target,'boot'),'fault recovery')
                self.version=target;self.status(target);self.summary['faults_verified']+=1;self.summary['verified_reboots']+=1
                self.evidence.event('fault_verified',checkpoint=checkpoint,recovered_version=target,physical_power_loss_tested=False)
                return
            finally:self.link.allow_reconnect=False
        start=time.monotonic_ns();reply=self.link.command('UPDATE '+blob.hex(),{'update'})
        typed(reply,dict(event='update',accepted=True,reason='ok',ready=True,version=version,policy='bundle',timing_schema=3,timing_measured=True,storage_metrics_schema=1,storage_metrics_kind='successful_flash_request_bytes'),'UPDATE')
        t=reply.get('timing_us',{})
        if sum(integer(t,k) for k in TIMING_STAGES)>integer(t,'total') or t['total']>integer(reply,'latency_us'):raise RuntimeError('Invalid stage timing sum')
        erase=math.ceil((len(blob)+8)/4096)*4096
        if reply.get('model_erase_bytes')!=erase or reply.get('model_write_bytes')!=len(blob)+8:raise RuntimeError('Unexpected model flash request counts')
        for k in ('journal_erase_bytes','journal_write_bytes'):integer(reply,k)
        self.version=version;self.status(version)
        self.evidence.event('cost',policy='bundle',family=self.family,version=version,transition='A_to_B_clean' if version==2 else 'B_to_C_reused' if version==3 else 'repeated_B',primary=version==3,unmeasured_warmup=self.evidence.phase.endswith('-warmup'),timing_us=t,envelope_bytes=len(blob),tx_wire_bytes=2*len(blob)+8,host_elapsed_ns=time.monotonic_ns()-start,response=reply,journal_rotation_included=version>3)
        self.summary['accepted_updates']+=1
    def reject(self,kind):
        current=self.version;blob=(self.artifacts['root']/self.f['versions'][str(current)]['path']).read_bytes()
        if kind=='signature':blob=blob[:-1]+bytes([blob[-1]^1])
        elif kind=='contract':blob=(self.artifacts['root']/self.f['bad_contract']).read_bytes()
        elif kind!='replay':raise ValueError(kind)
        reason={'signature':'signature','contract':'feature_contract','replay':'replay_or_downgrade'}[kind]
        self.evidence.event('negative_intent',kind=kind,envelope_sha256=hashlib.sha256(blob).hexdigest())
        reply=self.link.command('UPDATE '+blob.hex(),{'update'})
        typed(reply,dict(event='update',accepted=False,reason=reason,ready=True,version=current),'negative control')
        for k in ('model_erase_bytes','model_write_bytes','journal_erase_bytes','journal_write_bytes'):typed(reply,{k:0},'rejection does no flash work')
        self.status(current);self.summary['negative_controls_passed']+=1
    def whole(self,version,negative=None):
        image_meta=self.f['policies']['whole']['images'][str(version)];image=(self.artifacts['root']/image_meta['path']).read_bytes();ota=image_meta['ota']
        metadata=ota['metadata_hex'];sig=ota['signature_hex']
        if negative=='signature':sig=sig[:-2]+format(int(sig[-2:],16)^1,'02x')
        if negative=='image_hash':image=image[:-1]+bytes([image[-1]^1])
        prior=self.version;start=time.monotonic_ns();wire=0
        self.evidence.event('mutation_intent',command='FW_BEGIN',version=version,negative=negative,image_sha256=hashlib.sha256(image).hexdigest())
        def command(line,expected):
            nonlocal wire
            wire+=len(line)+1;return self.link.command(line,expected)
        rejected=negative in ('signature','replay')
        begin=command('FW_BEGIN '+metadata+' '+sig,{'fw_error'} if rejected else {'fw_begin'})
        if rejected:
            typed(begin,dict(event='fw_error',ok=False,error='signature' if negative=='signature' else 'non_monotonic_version'),'OTA rejection')
            self.status(prior);self.summary['negative_controls_passed']+=1;return
        typed(begin,dict(event='fw_begin',ok=True,version=version,size=len(image),timing_schema=2,crypto_context='shared_warm'),'OTA begin')
        if integer(begin,'signature_verify_us')+integer(begin,'partition_prepare_us')>integer(begin,'begin_us'):raise RuntimeError('Invalid OTA begin timing')
        total={k:0 for k in ('write_sum_us','hash_sum_us','chunk_sum_us','chunk_count')}
        for offset in range(0,len(image),1024):
            chunk=image[offset:offset+1024];r=command(f'FW_CHUNK {offset} {chunk.hex()}',{'fw_chunk'})
            typed(r,dict(event='fw_chunk',ok=True,offset=offset+len(chunk),timing_schema=2),'OTA chunk')
            w,h,t=integer(r,'write_us'),integer(r,'hash_us'),integer(r,'chunk_us')
            if w+h>t:raise RuntimeError('Invalid OTA chunk timing')
            for key,value in (('write_sum_us',w),('hash_sum_us',h),('chunk_sum_us',t),('chunk_count',1)):total[key]+=value
            typed(r,total,'OTA cumulative timing')
        ready=command('FW_END',{'fw_error'} if negative=='image_hash' else {'fw_ready'})
        if negative=='image_hash':
            typed(ready,dict(event='fw_error',ok=False,error='image_sha256'),'OTA image hash rejection');self.status(prior);self.summary['negative_controls_passed']+=1;return
        typed(ready,dict(event='fw_ready',ok=True,version=version,bytes=len(image),reboot_required=True,timing_schema=2,begin_us=begin['begin_us'],**total),'OTA ready')
        if integer(ready,'device_active_us')!=begin['begin_us']+total['chunk_sum_us']+integer(ready,'finalize_us'):raise RuntimeError('OTA total time mismatch')
        self.status(prior);self.reboot(version)
        self.evidence.event('cost',policy='whole',family=self.family,version=version,transition='A_to_B_clean' if version==2 else 'B_to_C_reused' if version==3 else 'repeated_B',primary=version==3,unmeasured_warmup=self.evidence.phase.endswith('-warmup'),begin=begin,ready=ready,image_bytes=len(image),tx_wire_bytes=wire,host_elapsed_ns=time.monotonic_ns()-start,image_partition_erase_bytes=math.ceil(len(image)/4096)*4096,image_partition_write_bytes=len(image),otadata_flash_work_included=False,transport='USB Serial/JTAG hex stop-and-wait, 1024-byte chunks')
        self.summary['accepted_updates']+=1
    def close(self):self.link.close();self.evidence.close()

def empty_summary():
    return dict(stage='030',status='failed',measurement_origin='not_measured',inferred_records=0,label_mismatches=0,max_probability_abs_error=0.,accepted_updates=0,verified_reboots=0,faults_verified=0,negative_controls_passed=0,completed_trials=0,hardware_access_attempted=False,physical_power_loss_tested=False,energy_measured=False)

def expected_counters(art):
    totals=dict(inferred_records=0,accepted_updates=0,verified_reboots=0,faults_verified=0,negative_controls_passed=0,completed_trials=0,label_mismatches=0)
    for family in FAMILIES:
        f=art['families'][family];n=len(f['variants']);g=len(read(art['root']/f['golden'])['raw']);restore=int(n>0)
        totals['inferred_records']+=(3+n)*g+4+2*restore+min(16,g)+6*min(8,g)+BLOCKS*4
        totals['accepted_updates']+=1+n+restore+1+6+BLOCKS*(BUNDLE_UPDATES+WHOLE_UPDATES+2)
        totals['verified_reboots']+=1+restore+1+6+BLOCKS*(WHOLE_UPDATES+1)
        totals['faults_verified']+=6;totals['negative_controls_passed']+=12;totals['completed_trials']+=8+BLOCKS*2
    return totals

def hardware(args,artifacts_path,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    verify_pins(artifacts_path)
    art=read(Path(artifacts_path)/'artifacts.json');art['root']=Path(artifacts_path)
    if art.get('validation_only_synthetic') is not False:raise ValueError('Only full real-data prepared artifacts may enter the hardware campaign')
    summary=empty_summary();summary.update(board_id=args.board_id,energy_recording_requested=not args.no_energy)
    expected=expected_counters(art)
    plan=cost_plan();save(output/'campaign_before_hardware.json',dict(stage='030',board_id=args.board_id,artifacts_manifest_sha256=sha(art['root']/'evidence_manifest.json'),cost_plan=plan,expected_completed_counters=expected,accepted_counter_scope='acknowledged accepted UPDATE or fully verified OTA; checkpoint interruption has no accepted receipt and is counted separately',software_checkpoints=list(CHECKPOINTS),software_repeats_per_checkpoint_per_family=1,probability_tolerance=TOLERANCE,primary_cost='first B-to-C update, version3, one value per block/family/policy',energy_blocks='128 bundle updates vs 4 whole updates; fixed 0.2s quiet after each update; joules per accepted update with explicit transport, cadence and journal rotation',quiet_after_update_seconds=QUIET_AFTER_UPDATE_SECONDS,physical_power_loss_tested=False,provisioning_excluded=True,warmup_version2_excluded=True,measured_versions='3 through N+2'))
    timeline=None;session=None
    def start(path,family,policy):
        nonlocal session
        if session:session.close();session=None
        path=output/path;path.mkdir(parents=True,exist_ok=False)
        summary['hardware_access_attempted']=True;provision(args,path,art,family,policy)
        session=Session(args,path,art,family,policy,summary);session.open();return session
    try:
        for family in FAMILIES:
            print(f'MCU verification: {family}',flush=True)
            s=start(Path('correctness')/(family+'-bundle'),family,'bundle');s.infer(1);s.bundle(2);s.infer(2);s.reboot(2);s.infer(2,1)
            for kind in ('signature','contract','replay'):s.phase('negative_'+kind);s.reject(kind);s.infer(2,1)
            for variant in s.f['variants']:
                s.phase(variant['model']);s.bundle(variant['version']);s.infer(variant['version'])
            if s.f['variants']:
                s.phase('restored_B');s.bundle(300);s.infer(300,1);s.reboot(300);s.infer(300,1)
            summary['completed_trials']+=1
            # Whole images bind exactly the same trained A and B payloads.
            s=start(Path('correctness')/(family+'-whole'),family,'whole');s.infer(1,16)
            s.whole(2,'signature');s.whole(2,'image_hash');s.whole(2);s.infer(2);s.whole(2,'replay')
            summary['completed_trials']+=1
            for checkpoint in CHECKPOINTS:
                s=start(Path('faults')/family/checkpoint,family,'bundle');s.bundle(2);s.bundle(3,checkpoint);s.infer(s.version,8);s.reject('replay');summary['completed_trials']+=1
        if not args.no_energy:
            print('\nПодготовьте FNB58: непрерывная запись VBUS/IBUS/PBUS, 100 sps, автоостановка выключена.\nПосле серии сохраните исходный CFN. Не отсоединяйте USB и не меняйте настройки питания.',flush=True)
            if not args.energy_recording_started:input('Начните запись в GUI FNB58 и нажмите Enter здесь: ')
            energy=module('energy030_timeline',KIT/'energy/timeline.py');timeline=energy.EnergyTimeline(output/'energy')
            timeline.marker(session.link,'calibration_before');timeline.marker(session.link,'validation_before')
        for item in plan:
            print(f"Cost/energy block {item['block']}/{BLOCKS}: {item['family']}/{item['policy']} ({item['updates']} updates)",flush=True)
            s=start(Path('costs')/item['id'],item['family'],item['policy']);s.phase(item['id']+'-warmup');s.infer(1,1)
            # Populate the second slot outside measurement; every recorded block
            # then begins by overwriting the occupied factory-A slot.
            if item['policy']=='bundle':s.bundle(2)
            else:s.whole(2)
            s.phase(item['id'])
            before=item['id']+'-before';after=item['id']+'-after'
            if timeline:timeline.baseline(10,before)
            def updates():
                for version in range(3,item['updates']+3):
                    if item['policy']=='bundle':s.bundle(version)
                    else:s.whole(version)
                    time.sleep(QUIET_AFTER_UPDATE_SECONDS)
                s.infer(s.version,1);s.status()
            if timeline:
                with timeline.update_block(item['id'],item['policy'],item['updates'],[before,after],family=item['family'],block=item['block'],quiet_after_update_seconds=QUIET_AFTER_UPDATE_SECONDS,initial_state='both slots contain accepted releases; warm A-to-B update excluded; measured versions start at3',scope='end-to-end accepted updates including USB protocol, validation STATUS, fixed 0.2s quiet cadence and firmware reboot') as receipt:
                    old=summary['accepted_updates'];updates();receipt['accepted_updates']=summary['accepted_updates']-old
                timeline.baseline(10,after)
            else:updates()
            summary['completed_trials']+=1
            save(output/'progress.json',dict(**summary,last_completed=item))
        if timeline:
            timeline.marker(session.link,'validation_after');timeline.marker(session.link,'calibration_after');timeline.finish()
            summary['energy_analysis_pending']=True
            print('Запись MCU завершена. Остановите GUI FNB58 и сохраните CFN рядом с результатами.',flush=True)
        typed(summary,expected,'final campaign counters')
        summary['status']='complete'
    except BaseException as exc:
        summary['error']=type(exc).__name__+': '+str(exc);raise
    finally:
        if session:session.close()
        summary['finished_utc_ns']=time.time_ns();save(output/'summary.json',summary);pins(output)
    return summary

def analyze_costs(hardware_dir,output):
    import numpy as np
    hardware_dir,output=Path(hardware_dir),Path(output)
    summary=read(hardware_dir/'summary.json')
    verify_pins(hardware_dir)
    typed(summary,dict(status='complete',measurement_origin='actual_mcu',label_mismatches=0),'hardware summary')
    campaign=read(hardware_dir/'campaign_before_hardware.json')
    if campaign.get('cost_plan')!=cost_plan() or campaign.get('board_id')!=summary.get('board_id'):raise ValueError('Hardware campaign/board mismatch')
    expected=campaign.get('expected_completed_counters')
    if not isinstance(expected,dict) or expected.get('completed_trials')!=112:raise ValueError('Missing frozen expected counters')
    typed(summary,expected,'campaign completion counters')
    artifact_directory=hardware_dir.parent/'artifacts'
    verify_pins(artifact_directory)
    if sha(artifact_directory/'evidence_manifest.json')!=campaign.get('artifacts_manifest_sha256'):raise ValueError('Hardware campaign is not bound to the adjacent prepared artifacts')
    rows=[]
    for item in cost_plan():
        path=hardware_dir/'costs'/item['id']/'events.jsonl'
        costs=[json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        costs=[r for r in costs if r.get('event')=='cost']
        if len(costs)!=item['updates']+1 or [r['version'] for r in costs]!=list(range(2,item['updates']+3)):raise ValueError('Wrong number/order of accepted update cost receipts (includes one unmeasured warmup)')
        if costs[0].get('unmeasured_warmup') is not True or any(r.get('unmeasured_warmup') is not False for r in costs[1:]):raise ValueError('Warmup measurement boundaries differ from frozen plan')
        primary=[r for r in costs if r.get('primary') is True]
        if len(primary)!=1 or primary[0]['version']!=3:raise ValueError('Missing unique primary cost')
        r=primary[0];device=r['timing_us']['total'] if item['policy']=='bundle' else r['ready']['device_active_us']
        for receipt in costs:typed(receipt,dict(family=item['family'],policy=item['policy']),'cost series identity')
        detail=dict(timing_us=r.get('timing_us'),ota_begin=r.get('begin'),ota_ready=r.get('ready'))
        if item['policy']=='bundle':
            response=r['response'];detail['successful_flash_request_bytes']={k:response[k] for k in ('model_erase_bytes','model_write_bytes','journal_erase_bytes','journal_write_bytes')}
        else:detail['successful_flash_request_bytes']=dict(image_partition_erase_bytes=r['image_partition_erase_bytes'],image_partition_write_bytes=r['image_partition_write_bytes'],otadata_accounted=False)
        rows.append(dict(**item,device_active_us=device,host_elapsed_ns=r['host_elapsed_ns'],tx_wire_bytes=r['tx_wire_bytes'],payload_or_image_bytes=r.get('envelope_bytes',r.get('image_bytes')),**detail))
    result=dict(stage='030',status='complete',metric_scope='bundle active total vs OTA active summed stages; OTA reboot excluded from device_active and included in host_elapsed',host_metric_scope='end-to-end serial protocol, not intrinsic update algorithm time',primary_rows=rows,comparisons={})
    rng=np.random.default_rng(30092026);draws=rng.integers(0,BLOCKS,size=(10000,BLOCKS))
    for family in FAMILIES:
        per={p:sorted([r for r in rows if r['family']==family and r['policy']==p],key=lambda r:r['block']) for p in ('bundle','whole')}
        if any(len(v)!=BLOCKS for v in per.values()):raise ValueError('Incomplete paired blocks')
        a=np.array([r['device_active_us'] for r in per['bundle']]);b=np.array([r['device_active_us'] for r in per['whole']]);difference=a-b
        result['comparisons'][family]=dict(n_paired_blocks=BLOCKS,bundle_median_us=float(np.median(a)),whole_median_us=float(np.median(b)),median_paired_bundle_minus_whole_us=float(np.median(difference)),paired_percentile_bootstrap_95CI_us=np.percentile(np.median(difference[draws],axis=1),[2.5,97.5]).tolist(),bootstrap_draws=10000,bootstrap_seed=30092026)
    resources={}
    artifacts=read(artifact_directory/'artifacts.json')
    for family in FAMILIES:
        for policy in ('bundle','whole'):
            directory=hardware_dir/'correctness'/(family+'-'+policy)
            observations=[json.loads(line) for line in (directory/'observations.jsonl').read_text().splitlines() if line.strip()]
            groups={}
            for observation in observations:
                response=observation['response'];version=str(response['version'])
                group=groups.setdefault(version,dict(latencies=[],heap=[],raw=set(),max_probability_abs_error=0.,label_mismatches=0))
                group['latencies'].append(integer(response,'latency_us'));group['heap'].append(integer(response,'free_heap'));group['raw'].add(tuple(observation['raw']))
                group['max_probability_abs_error']=max(group['max_probability_abs_error'],observation['probability_abs_error']);group['label_mismatches']+=int(not observation['label_match'])
            by_version={}
            for version,group in groups.items():
                by_version[version]=dict(model_reference=artifacts['families'][family]['versions'][version]['reference'],inference_calls=len(group['latencies']),unique_input_vectors=len(group['raw']),device_inference_median_us=float(np.median(group['latencies'])),device_inference_p95_us=float(np.percentile(group['latencies'],95)),minimum_observed_free_heap_bytes=min(group['heap']),max_probability_abs_error=group['max_probability_abs_error'],label_mismatches=group['label_mismatches'])
            events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines() if line.strip()]
            initial=[event['response'] for event in events if event.get('event')=='initial_status_verified']
            if len(initial)!=1:raise ValueError('Expected one initial status in correctness session')
            image=artifacts['families'][family]['policies'][policy]['images']['1']
            resources[family+'/'+policy]=dict(factory_image_bytes=image['image_size'],trained_B_envelope_bytes=artifacts['families'][family]['versions']['2']['envelope_bytes'],sizeof_model_bytes=initial[0].get('sizeof_model_bytes'),sizeof_engine_bytes=initial[0].get('sizeof_engine_bytes'),by_model_version=by_version)
    result['resources_and_inference']=resources
    result['resource_limitations']='Free heap is sampled at protocol response points, not peak RAM; sizeof values are static structures, not total working memory; repeated inputs do not constitute independent detection examples; provision and non-image otadata work are excluded from flash request metrics.'
    save(output,result);return result
