"""Pinned stage-025 inputs and strict semantic/storage gates; no hardware at import."""
from __future__ import annotations
from dataclasses import replace
import hashlib
import importlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shlex
import sys

CONFIGURATIONS = ('lr_full_slot', 'lr_necessary_sectors', 'dt_full_slot', 'dt_necessary_sectors')
CHECKPOINTS = ('after_erase', 'after_write', 'after_verify', 'after_slot_commit', 'after_journal_body', 'after_commit')
STAGES = ('candidate_verify','erase','body_write','readback','readback_verify','commit','journal_prepare','journal_body','journal_commit')
TOLERANCE = 2e-6
COUNTERS = ('inferred_records','label_mismatches','accepted_updates','verified_reboots','faults_verified','negative_controls_passed')
STORAGE_FIELDS = ('model_erase_bytes','model_write_bytes','journal_erase_bytes','journal_write_bytes')
BASE = None


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read_json(path): return json.loads(Path(path).read_text(encoding='utf-8'), parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Nonfinite JSON '+x)))
def save(path, value): Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+'\n', encoding='utf-8')


def load_base(root):
    global BASE
    spec=importlib.util.spec_from_file_location('stage025_immutable_support',Path(root)/'tools/campaign_support.py')
    BASE=importlib.util.module_from_spec(spec); spec.loader.exec_module(BASE)
    return BASE


def pins(root):
    root=Path(root).resolve(); data=read_json(root/'KIT_MANIFEST.json'); files=data.get('sha256',data.get('files',data))
    required={'tools/run_erase025.py','tools/erase_support025.py','tools/summarize_erase025.py','tools/run_completion.py','tools/campaign_support.py','tools/legacy_runner018.py','BUILD_METADATA.json','protocol.json','reference020/BUILD_METADATA.json','host/ids_update_lab/package.py','host/ids_update_lab/serial_runner.py'}
    if not isinstance(files,dict) or not required.issubset(files): raise ValueError('Incomplete stage025 manifest')
    for name,digest in files.items():
        p=(root/name).resolve()
        if not isinstance(name,str) or '\\' in name or Path(name).is_absolute() or not p.is_relative_to(root) or '..' in Path(name).parts: raise ValueError('Invalid pinned path')
        if not re.fullmatch('[a-f0-9]{64}',str(digest)) or not p.is_file() or sha(p)!=digest: raise ValueError('Kit integrity mismatch: '+name)
    for directory in ('host','tools'):
        for p in (root/directory).rglob('*.py'):
            if p.relative_to(root).as_posix() not in files: raise ValueError('Unpinned Python file: '+str(p))
    return files


def plan(command):
    if command=='series':
        rows=[]
        for block in range(30):
            offset=(block//2)%4; order=CONFIGURATIONS[offset:]+CONFIGURATIONS[:offset]
            if block%2: order=order[::-1]
            for position,configuration in enumerate(order,1):
                rows.append({'kind':'cost','configuration':configuration,'block':block+1,'position':position,'transitions':['A_to_B_clean','B_to_C_reused']})
    elif command=='pilot':
        rows=[]
        for configuration in CONFIGURATIONS:
            rows.append({'kind':'smoke','configuration':configuration,'transitions':['A_to_B_clean','B_to_C_reused']})
            rows.extend({'kind':'fault','configuration':configuration,'checkpoint':point,'target_condition':'reused'} for point in CHECKPOINTS)
    else: raise ValueError('No hardware plan for '+command)
    return [{'trial':i+1,**row,'path':f"trial-{i+1:03d}-{row['configuration']}-{row['kind']}"} for i,row in enumerate(rows)]


def expected_storage(envelope_bytes, policy):
    if type(envelope_bytes) is not int or not 16<=envelope_bytes<=4096: raise ValueError('Invalid envelope size')
    if policy not in ('full_slot','necessary_sectors'): raise ValueError('Unknown erase policy')
    return {'model_erase_bytes':65536 if policy=='full_slot' else ((envelope_bytes+8+4095)//4096)*4096,'model_write_bytes':envelope_bytes+8,'journal_erase_bytes':0,'journal_write_bytes':128}


def storage(reply, context, key=None, accepted=True):
    BASE.typed(reply, {'erase_policy':context['erase_policy'],'model_slot_capacity_bytes':65536,'erase_sector_bytes':4096,'storage_metrics_schema':1,'storage_metrics_kind':'successful_flash_request_bytes'}, 'storage telemetry')
    expected=expected_storage(len(context['envelopes'][key]),context['erase_policy']) if accepted else {k:0 for k in STORAGE_FIELDS}
    BASE.typed(reply,expected,'storage request byte counters')
    return expected


def check_status(reply,c,key,event='status'):
    BASE.check_status(reply,c,key,event)
    check_storage_status(reply,c,key)


def check_storage_status(reply,c,key):
    BASE.typed(reply,{'erase_policy':c['erase_policy'],'model_slot_capacity_bytes':65536,'erase_sector_bytes':4096,'selector_sequence':{'A':1,'B':2,'C':3}[key]},'stage025 status')


def load_context(root, configuration, files=None):
    root=Path(root).resolve(); files=pins(root) if files is None else files
    if BASE is None: load_base(root)
    if configuration not in CONFIGURATIONS: raise ValueError('Unknown configuration')
    model,policy=configuration.split('_',1); sys.path.insert(0,str(root/'host'))
    package=importlib.import_module('ids_update_lab.package'); serial=importlib.import_module('ids_update_lab.serial_runner')
    for name in ('ids_update_lab','ids_update_lab.package','ids_update_lab.serial_runner'):
        if not Path(sys.modules[name].__file__).resolve().is_relative_to(root/'host'): raise ValueError('Module outside pinned host '+name)
    family=root/'artifacts'/model; experiment=read_json(family/'experiment.json')
    build=read_json(root/'BUILD_METADATA.json')['configurations'][configuration]
    abi=experiment['runtime_abi']; schema=experiment['schema_sha256']; public=package.load_public(family/'public.pem')
    if abi==3:
        package=importlib.import_module('ids_update_lab.tree_package')
        if not Path(package.__file__).resolve().is_relative_to(root/'host'): raise ValueError('Tree package outside pinned host')
    if package.contract_hash(read_json(family/'feature_contract.json')).hex()!=schema: raise ValueError('Contract hash mismatch')
    models={}; blobs={}; digests={}
    for name,meta in experiment['models'].items():
        blob=BASE.confined(family,meta['package']).read_bytes(); obj=package.verify(blob,public,bytes.fromhex(schema),8,expected_abi=abi)
        if obj.version!=meta['version'] or obj.release!=meta['release'] or hashlib.sha256(blob).hexdigest()!=meta['envelope_sha256'] or hashlib.sha256(blob[16:-256]).hexdigest()!=meta['payload_sha256']: raise ValueError('Signed model mismatch '+name)
        models[name]=obj; blobs[name]=blob; digests[name]=meta['payload_sha256']
    if [models[k].version for k in 'ABC']!=[1,2,3]: raise ValueError('ABC versions must be1,2,3')
    if replace(models['C'],version=models['B'].version,release=models['B'].release).payload()!=models['B'].payload(): raise ValueError('C changes B numerical parameters')
    golden=[json.loads(row) for row in (family/'golden.jsonl').read_text().splitlines() if row.strip()]
    if len(golden)!=258 or len({r['id'] for r in golden})!=258: raise ValueError('258 frozen golden inputs required')
    for row in golden:
        for key in 'ABC':
            p,label=package.infer(models[key],row['raw']); ref=row['expected'][key]
            if type(ref['label']) is not int or ref['label']!=label or not math.isfinite(ref['probability']) or abs(p-ref['probability'])>TOLERANCE: raise ValueError('Golden mismatch '+key)
    if set(build['images'])!={'A'} or build.get('erase_policy')!=policy: raise ValueError('Wrong build configuration')
    factory=BASE.confined(root,build['factory_dir'])
    if shlex.split((factory/'flash_args').read_text())!=BASE.FIXED_FLASH: raise ValueError('Unreviewed flash layout')
    im=build['images']['A']; imagepath=BASE.confined(root,im['path']); identity=BASE.image_identity(imagepath)
    if (factory/'ids_update_lab.bin').read_bytes()!=imagepath.read_bytes() or imagepath.read_bytes().count(blobs['A'])!=1: raise ValueError('Factory/model binding mismatch')
    expected=f"esp-idf-{identity['idf_version']};app={identity['version']};elf={identity['elf_sha256'][:9]}"
    if identity['idf_version']!='v5.3.2' or identity['version']!=1 or im['expected_build']!=expected or im['image_sha256']!=identity['image_sha256']: raise ValueError('Unexpected factory identity')
    return {'root':root,'family':family,'configuration':configuration,'erase_policy':policy,'experiment':experiment,'build':build,'factory_dir':factory,'model_family':model,'policy_name':'bundle','policy':'bundle','package':package,'serial':serial,'public':public,'schema':schema,'models':models,'envelopes':blobs,'digests':digests,'golden':golden,'pins':files,'kit_manifest_sha256':sha(root/'KIT_MANIFEST.json')}


def known_status(reply,root):
    known=set()
    for metadata in ('BUILD_METADATA.json','reference020/BUILD_METADATA.json'):
        for entry in read_json(Path(root)/metadata)['configurations'].values():
            known.update(im['expected_build'] for im in entry['images'].values())
    if reply.get('event')!='status' or reply.get('ready') is not True or reply.get('chip')!='esp32s3' or reply.get('build') not in known or type(reply.get('version')) is not int or reply['version']<1:
        raise RuntimeError('Initial STATUS is not a recognized ready020/025 build; no provisioning issued')
    # Model versions are intentionally unrestricted, including journal rotation10070.
    return reply


def verify_pilot(path,root,board_id):
    path=Path(path).resolve(); manifest=read_json(path/'campaign_manifest.json'); summary=read_json(path/'summary.json')
    BASE.typed(manifest,{'stage':'025','command':'pilot','board_id':board_id,'kit_manifest_sha256':sha(Path(root)/'KIT_MANIFEST.json'),'created_before_hardware':True},'pilot manifest')
    if manifest.get('trial_plan')!=plan('pilot'): raise ValueError('Pilot plan differs from frozen plan')
    BASE.typed(summary,{'stage':'025','command':'pilot','status':'complete','measurement_origin':'actual_mcu','board_id':board_id,'kit_manifest_sha256':sha(Path(root)/'KIT_MANIFEST.json'),'completed_trials':28,'attempted_trials':28,'inferred_records':3316,'accepted_updates':32,'verified_reboots':28,'faults_verified':24,'negative_controls_passed':32,'label_mismatches':0},'pilot result')
    verify_evidence(path,'run_evidence_manifest.json')
    for row in manifest['trial_plan']:
        result=read_json(path/row['path']/'summary.json')
        verify_evidence(path/row['path'],'evidence_manifest.json')
        counters={'inferred_records':775,'accepted_updates':2,'verified_reboots':1,'faults_verified':0,'negative_controls_passed':2} if row['kind']=='smoke' else {'inferred_records':9,'accepted_updates':1,'verified_reboots':1,'faults_verified':1,'negative_controls_passed':1}
        BASE.typed(result,{'stage':'025','command':'pilot','status':'complete','measurement_origin':'actual_mcu','trial':row,'board_id':board_id,'kit_manifest_sha256':sha(Path(root)/'KIT_MANIFEST.json'),'configuration':row['configuration'],'label_mismatches':0,**counters},'pilot trial')
        if not math.isfinite(result.get('max_probability_abs_error',math.inf)) or result['max_probability_abs_error']>TOLERANCE: raise ValueError('Pilot numerical mismatch')
    return {'path':str(path),'manifest_sha256':sha(path/'campaign_manifest.json'),'summary_sha256':sha(path/'summary.json')}


def typed(*args,**kwargs): return BASE.typed(*args,**kwargs)
def integer(*args,**kwargs): return BASE.integer(*args,**kwargs)
def bundle_timing(*args,**kwargs): return BASE.bundle_timing(*args,**kwargs)
def check_inference(*args,**kwargs): return BASE.check_inference(*args,**kwargs)
def board_mac(*args,**kwargs): return BASE.board_mac(*args,**kwargs)
def key_for(context, letter): return letter


def verify_evidence(directory,name):
    directory=Path(directory).resolve(); files=read_json(directory/name).get('sha256')
    if not isinstance(files,dict) or not files: raise ValueError('Missing evidence hashes')
    for relative,digest in files.items():
        path=(directory/relative).resolve()
        if not path.is_relative_to(directory) or '\\' in relative or '..' in Path(relative).parts or not path.is_file() or sha(path)!=digest: raise ValueError('Evidence integrity mismatch '+relative)
    expected={p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file() and p.name!=name}
    if set(files)!=expected: raise ValueError('Evidence manifest does not cover all files')
    return files
