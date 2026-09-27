"""Strict gates shared by completion-020 campaigns (no hardware at import)."""
from __future__ import annotations
import hashlib
from dataclasses import replace
import importlib
import json
import math
from pathlib import Path, PurePosixPath
import random
import re
import shlex
import struct
import sys

TOLERANCE = 2e-6
CHECKPOINTS = ('after_erase','after_write','after_verify','after_slot_commit','after_journal_body','after_commit')
STAGES = ('candidate_verify','erase','body_write','readback','readback_verify','commit','journal_prepare','journal_body','journal_commit')
POLICIES = {'bundle':'bundle', 'compatible':'model_only_factory_preprocess', 'whole':'whole_firmware'}
FIXED_FLASH = ['--flash_mode','dio','--flash_freq','80m','--flash_size','4MB','0x0','bootloader/bootloader.bin','0x10000','ids_update_lab.bin','0x8000','partition_table/partition-table.bin','0xd000','ota_data_initial.bin']
REQUIRED = {'tools/run_completion.py','tools/campaign_support.py','tools/legacy_runner018.py','BUILD_METADATA.json','host/ids_update_lab/package.py','host/ids_update_lab/serial_runner.py'}
META = struct.Struct('<8sII32sI32s')


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'),parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Nonfinite JSON '+x)))

def save(path, value):
    Path(path).write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')

def confined(root, name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name: raise ValueError('Invalid relative path '+name)
    result=(root/name).resolve()
    if not result.is_relative_to(root.resolve()): raise ValueError('Path escapes kit '+name)
    return result

def pins(root):
    data=read_json(root/'KIT_MANIFEST.json')
    files=data.get('sha256', data.get('files',data))
    if not isinstance(files,dict) or not REQUIRED.issubset(files): raise ValueError('Kit manifest missing required inputs')
    for name,digest in files.items():
        p=confined(root,name)
        if not re.fullmatch('[a-f0-9]{64}',str(digest)) or not p.is_file() or sha(p)!=digest: raise ValueError('Kit integrity mismatch: '+name)
    for directory in ('host','tools'):
        for p in (root/directory).rglob('*.py'):
            if p.relative_to(root).as_posix() not in files: raise ValueError('Unpinned executable input: '+str(p))
    return files

def typed(row, expected, where):
    for key,value in expected.items():
        if type(row.get(key)) is not type(value) or row[key]!=value:
            raise RuntimeError(f'{where}: {key}={row.get(key)!r}, expected {value!r}')

def integer(row,key):
    value=row.get(key)
    if type(value) is not int or value<0: raise RuntimeError('Invalid nonnegative timing '+key)
    return value

def bundle_timing(reply, accepted=True):
    typed(reply, {'timing_schema':3,'timing_measured':True,'timing_executed_mask':511 if accepted else 1},'bundle timing')
    t=reply.get('timing_us')
    if not isinstance(t,dict) or set(t)!=set(STAGES)|{'total'}: raise RuntimeError('Wrong schema-3 stages')
    for name in (*STAGES,'total'): integer(t,name)
    if sum(t[n] for n in STAGES)>t['total'] or t['total']>integer(reply,'latency_us'): raise RuntimeError('Timing sum inconsistency')
    if not accepted and any(t[n] for n in STAGES if n!='candidate_verify'): raise RuntimeError('Rejected input executed a flash stage')
    return t

def plan(command):
    if command=='faults':
        rows=[{'checkpoint':point,'target_condition':cond,'replicate':rep} for point in CHECKPOINTS for cond in ('clean','reused') for rep in range(1,11)]
        random.Random(24092026).shuffle(rows)
    elif command=='negatives':
        rows=[{'negative':kind,'replicate':rep} for kind in ('signature','contract','replay') for rep in range(1,11)]
        random.Random(24092026).shuffle(rows)
    elif command=='costs': rows=[{'replicate':rep,'transitions':['A_to_B_clean','B_to_C_reused']} for rep in range(1,31)]
    else: rows=[{'replicate':1}]
    return [{'trial':i+1,**row} for i,row in enumerate(rows)]

def board_mac(board):
    match=re.fullmatch(r'esp32s3-([0-9a-fA-F]{12})',board)
    if not match: raise ValueError('board-id must be esp32s3- followed by the 12 hex MAC digits')
    raw=match[1].lower()
    return ':'.join(raw[i:i+2] for i in range(0,12,2))

def image_identity(path):
    blob=Path(path).read_bytes()
    if len(blob)<288 or blob[0]!=0xe9 or struct.unpack_from('<I',blob,32)[0]!=0xabcd5432: raise ValueError('Invalid ESP-IDF application image')
    version=blob[48:80].split(b'\0',1)[0].decode('ascii')
    if not version.isdigit(): raise ValueError('Nondecimal PROJECT_VER')
    return {'version':int(version),'elf_sha256':blob[176:208].hex(),'idf_version':blob[144:176].split(b'\0',1)[0].decode('ascii'),'image_sha256':hashlib.sha256(blob).hexdigest()}

def load_context(root, model, policy):
    root=Path(root).resolve(); files=pins(root)
    if model not in ('lr','dt') or policy not in POLICIES or (model=='dt' and policy=='compatible'): raise ValueError('Unsupported model/policy')
    sys.path.insert(0,str(root/'host'))
    package=importlib.import_module('ids_update_lab.package'); serial=importlib.import_module('ids_update_lab.serial_runner')
    for name in ('ids_update_lab','ids_update_lab.package','ids_update_lab.serial_runner'):
        if not Path(sys.modules[name].__file__).resolve().is_relative_to(root/'host'): raise ValueError('Module imported outside pinned kit: '+name)
    family=root/'artifacts'/model; experiment=read_json(family/'experiment.json')
    build=read_json(root/'BUILD_METADATA.json')['configurations'][model+'_'+policy]
    expected_abi=experiment['runtime_abi']; schema=experiment['schema_sha256']; public=package.load_public(family/'public.pem')
    if expected_abi==3:
        package=importlib.import_module('ids_update_lab.tree_package')
        if not Path(package.__file__).resolve().is_relative_to(root/'host'): raise ValueError('Tree package outside pinned kit')
    if package.contract_hash(read_json(family/'feature_contract.json')).hex()!=schema:raise ValueError('Contract document hash differs from signed schema')
    models={}; blobs={}; digests={}
    for name,meta in experiment['models'].items():
        blob=confined(family,meta['package']).read_bytes()
        obj=package.verify(blob,public,bytes.fromhex(schema),8,expected_abi=expected_abi)
        if obj.version!=meta['version'] or obj.release!=meta['release'] or hashlib.sha256(blob[16:-256]).hexdigest()!=meta['payload_sha256']: raise ValueError('Signed model mismatch '+name)
        models[name]=obj; blobs[name]=blob; digests[name]=meta['payload_sha256']
    if [models[k].version for k in 'ABC']!=[1,2,3]:raise ValueError('Campaign requires fixed factoryA1/B2/C3')
    if replace(models['C'],version=models['B'].version,release=models['B'].release).payload()!=models['B'].payload():raise ValueError('C must retain exact B numerical parameters')
    if policy=='compatible':
        for key in ('compatible_B','compatible_C'):
            prep=replace(models['A'],means=models[key].means,scales=models[key].scales,threshold=models[key].threshold)
            if prep.payload()!=models['A'].payload():raise ValueError('Compatible export changes immutable factory preprocessing')
    golden=[json.loads(s) for s in (family/'golden.jsonl').read_text().splitlines() if s.strip()]
    if len(golden)!=258 or len({r['id'] for r in golden})!=258: raise ValueError('Must retain 258 original golden inputs')
    for row in golden:
        for name,obj in models.items():
            p,label=package.infer(obj,row['raw']); expected=row['expected'][name]
            if type(expected.get('label')) is not int or label!=expected['label'] or not math.isfinite(expected['probability']) or abs(p-expected['probability'])>TOLERANCE: raise ValueError('Golden differs from signed model '+name)
    factory_dir=confined(root,build['factory_dir'])
    if shlex.split((factory_dir/'flash_args').read_text())!=FIXED_FLASH: raise ValueError('Nonreviewed flash_args layout')
    if (factory_dir/'ids_update_lab.bin').read_bytes()!=confined(root,build['images']['A']['path']).read_bytes():raise ValueError('Flash image differs from pinned factory image')
    for name,im in build['images'].items():
        image_path=confined(root,im['path']);identity=image_identity(image_path)
        if identity['version']!=models[name].version or image_path.read_bytes().count(blobs[name])!=1:raise ValueError('Application embeds wrong factory model '+name)
        expected=f"esp-idf-{identity['idf_version']};app={identity['version']};elf={identity['elf_sha256'][:9]}"
        if im['expected_build']!=expected: raise ValueError('Build description differs from application image '+name)
    return {'root':root,'family':family,'experiment':experiment,'build':build,'factory_dir':factory_dir,'model_family':model,'policy_name':policy,'policy':POLICIES[policy], 'package':package,'serial':serial,'public':public,'schema':schema,'models':models,'envelopes':blobs,'digests':digests,'golden':golden,'pins':files,'kit_manifest_sha256':sha(root/'KIT_MANIFEST.json')}

def key_for(context, letter): return 'compatible_'+letter if context['policy_name']=='compatible' and letter!='A' else letter

def check_status(reply,c,key,event='status'):
    m=c['models'][key]; image_key=key if c['policy_name']=='whole' else 'A'
    expected={'event':event,'ready':True,'reason':'ok','version':m.version,'release':m.release,'policy':c['policy'],'schema':c['schema'],'feature_count':8,'bundle_sha256':c['digests'][key],'chip':'esp32s3','build':c['build']['images'][image_key]['expected_build'],'data_origin':'TON_IoT_development','runtime_abi':c['experiment']['runtime_abi'],'pretransform':c['experiment']['pretransform'],'storage_layout':2,'storage_scheme':'journal_dualrail_v1','timing_schema':3,'crypto_context':'shared_warm'}
    typed(reply,expected,'status')
    integer(reply,'crypto_key_setup_us'); integer(reply,'crypto_first_verify_us')
    if c['policy_name']!='whole':
        typed(reply,{'active_slot':0 if m.version in (1,3) else 1},'active slot')
        integer(reply,'selector_sequence')
    else:typed(reply,{'active_slot':-1,'selector_sequence':0},'whole factory-only storage')

def check_inference(reply,c,key,expected):
    m=c['models'][key]
    typed(reply,{'event':'inference','version':m.version,'policy':c['policy'],'bundle_sha256':c['digests'][key],'runtime_abi':c['experiment']['runtime_abi'],'pretransform':c['experiment']['pretransform'],'data_origin':'TON_IoT_development'},'inference')
    p=reply.get('probability')
    if type(p) not in (int,float) or not math.isfinite(p) or not 0<=p<=1: raise RuntimeError('Invalid inference probability')
    match=type(reply.get('label')) is int and reply['label']==expected['label']; error=abs(p-expected['probability'])
    return error,match

def validate_ota(context, key):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    directory=confined(context['root'],context['build']['ota'][key])
    image=(directory/'image.bin').read_bytes(); meta=(directory/'metadata.bin').read_bytes(); signature=(directory/'signature.bin').read_bytes()
    if len(meta)!=META.size or len(signature)!=256: raise ValueError('Bad OTA metadata size')
    context['public'].verify(signature,meta,padding.PKCS1v15(),hashes.SHA256())
    magic,version,length,digest,abi,schema=META.unpack(meta)
    if (magic!=b'SIDSFW1\0' or version!=context['models'][key].version or length!=len(image) or digest!=hashlib.sha256(image).digest() or abi!=context['experiment']['runtime_abi'] or schema.hex()!=context['schema'] or image.count(context['envelopes'][key])!=1): raise ValueError('OTA metadata/image/model binding failure')
    image_path=confined(context['root'],context['build']['images'][key]['path'])
    if image!=image_path.read_bytes(): raise ValueError('OTA image differs from expected build')
    return image,meta,signature


def suite_plan(model, full=False):
    configurations=[('lr','bundle'),('lr','compatible'),('lr','whole'),('dt','bundle'),('dt','whole')]
    if model!='all': configurations=[pair for pair in configurations if pair[0]==model]
    tasks=[]
    if full:
        for family,policy in configurations:
            commands=['flash','smoke']+(['faults'] if policy=='bundle' else [])+['negatives']
            for command in commands:tasks.append({'command':command,'model':family,'policy':policy,'phase':'functional'})
    # Thirty blocks, every policy once per block. Rotation balances serial order
    # exactly for 2/3/5 configurations because 30 is divisible by each count.
    for block in range(30):
        offset=block%len(configurations)
        order=configurations[offset:]+configurations[:offset]
        for position,(family,policy) in enumerate(order,1):
            tasks.append({'command':'costs','model':family,'policy':policy,'phase':'cost','block':block+1,'position':position,'trial':block+1,'replicate':block+1,'transitions':['A_to_B_clean','B_to_C_reused']})
    return [{'task':i+1,**task} for i,task in enumerate(tasks)]
