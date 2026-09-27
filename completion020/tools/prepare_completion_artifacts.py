#!/usr/bin/env python3
"""Export frozen LR and DT5 models; never fit, select thresholds, or read old test.

Example: python tools/prepare_completion_artifacts.py --private-key /external/key.pem --output artifacts-regenerated
The private key is read in memory, never copied or logged.
"""
import argparse
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'))
import numpy as np
from ids_update_lab import package as lr
from ids_update_lab import tree_package as dt

def sha(data): return hashlib.sha256(data).hexdigest()
def load(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def write(path,value): Path(path).write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')

def float32_floor(value):
    """Largest binary32 <= original binary64 split; exact <= on x32 domain."""
    v=np.float32(value)
    if not np.isfinite(v): raise ValueError('split not finite float32')
    if float(v)>value: v=np.nextafter(v,np.float32(-np.inf),dtype=np.float32)
    return float(v)

def export_tree(source,metrics,schema,version,release):
    nodes=[]
    for left,right,feature,split,p in zip(source['children_left'],source['children_right'],source['feature'],source['split_thresholds_float64'],source['node_attack_probability_float64']):
        leaf=left==-1 and right==-1
        nodes.append(dt.TreeNode(left,right,-1 if leaf else feature,0.0 if leaf else float32_floor(split),float(np.float32(p))))
    model=dt.TreeModel(version,release,schema,len(source['features_ordered']),
        float(np.float32(metrics['validation']['selected_FPR5']['threshold'])),tuple(nodes))
    return dt.parse_payload(model.payload())

def compatible(A,B,version,release):
    wa=np.asarray(B.weights,dtype=np.float64)*np.asarray(A.scales,dtype=np.float64)/np.asarray(B.scales,dtype=np.float64)
    b=float(B.bias)+float(np.sum(np.asarray(B.weights,dtype=np.float64)*(np.asarray(A.means,dtype=np.float64)-np.asarray(B.means,dtype=np.float64))/np.asarray(B.scales,dtype=np.float64),dtype=np.float64))
    b+=math.log(A.threshold/(1-A.threshold))-math.log(B.threshold/(1-B.threshold))
    return lr.parse_payload(replace(B,version=version,release=release,means=A.means,scales=A.scales,
        weights=tuple(float(np.float32(v)) for v in wa),bias=float(np.float32(b)),threshold=A.threshold).payload())

def header(model,envelope,public):
    def array(name,data):
        lines=['    '+', '.join('0x%02x'%v for v in data[i:i+16])+',' for i in range(0,len(data),16)]
        return 'inline constexpr unsigned char '+name+'[] = {\n'+'\n'.join(lines)+'\n};\n'
    return ('// Generated public experimental artifact. No private material.\n#pragma once\nnamespace ids_generated {\n'
        f'inline constexpr unsigned kFeatureCount = {model.count if model.runtime_abi==3 else len(model.means)};\n'
        f'inline constexpr unsigned kRuntimeAbi = {model.runtime_abi};\n'
        f'inline constexpr unsigned kFactoryVersion = {model.version};\n'
        +array('kFeatureContractHash',model.schema)+array('kFactoryEnvelope',envelope)
        +array('kPublicKeyPem',public+b'\0')+'inline constexpr char kDataOrigin[] = "TON_IoT_development";\n}\n')

def prepare(source,output,key):
    source=Path(source);output=Path(output);output.mkdir(parents=True,exist_ok=False)
    public=(source/'public.pem').read_bytes(); pub=lr.load_public(source/'public.pem')
    A=lr.verify((source/'release-A.sids').read_bytes(),pub,expected_abi=2)
    B=lr.verify((source/'release-B.sids').read_bytes(),pub,expected_abi=2)
    # This identity check ties the exporter to the already measured 018 LR pair.
    if A.version!=1 or B.version!=2 or A.runtime_abi!=2 or B.runtime_abi!=2: raise ValueError('frozen LR identity')
    models_lr={'A':A,'B':B,'C':replace(B,version=3,release='log1p-C'),
        'compatible_B':compatible(A,B,2,'compat-B'),'compatible_C':compatible(A,B,3,'compat-C')}
    dt_source={p:load(source/('DT5_raw_'+p)/'model.json') for p in ('A','B')}
    contract_dt=dt.new_contract(dt_source['A']['features_ordered'],dt_source['A']['units_before_pretransform'])
    schema=dt.contract_hash(contract_dt)
    models_dt={p:export_tree(dt_source[p],load(source/('DT5_raw_'+p)/'metrics_development.json'),schema,i,'dt5-'+p)
        for p,i in (('A',1),('B',2))}
    models_dt['C']=replace(models_dt['B'],version=3,release='dt5-C')
    golden=[json.loads(line) for line in (source/'golden.jsonl').read_text().splitlines()]
    if len(golden)!=258: raise ValueError('frozen golden count')
    for family,models,codec,contract in (('lr',models_lr,lr,load(source/'feature_contract.json')),('dt',models_dt,dt,contract_dt)):
        folder=output/family;folder.mkdir();(folder/'headers').mkdir()
        (folder/'public.pem').write_bytes(public);write(folder/'feature_contract.json',contract)
        meta=dict(stage='completion020',family=family,data_origin='TON_IoT_development',runtime_abi=models['A'].runtime_abi,
            pretransform='log1p' if family=='lr' else 'identity',feature_count=8,schema_sha256=models['A'].schema.hex(),
            golden_records=258,real_vectors=256,synthetic_vectors=2,probability_abs_tolerance=2e-6,
            hardware_tested=False,heldout_detection_quality_measured=False,models={},
            compatible_policy_available=(family=='lr'),C_is_exact_B_parameters_new_version=True)
        for name,model in models.items():
            envelope=codec.sign(model,key)
            parsed=codec.verify(envelope,pub,model.schema,8,model.runtime_abi)
            fname=('compatible-'+name[-1] if name.startswith('compatible') else 'release-'+name)+'.sids'
            (folder/fname).write_bytes(envelope)
            (folder/'headers'/(name+'.h')).write_text(header(parsed,envelope,public),encoding='utf-8')
            info=dict(package=fname,version=model.version,release=model.release,payload_sha256=sha(model.payload()),
                envelope_sha256=sha(envelope),threshold=model.threshold,envelope_bytes=len(envelope),payload_bytes=len(model.payload()))
            if family=='dt': info['node_count']=len(model.nodes)
            meta['models'][name]=info
        bad=bytearray((folder/'release-B.sids').read_bytes());bad[-1]^=1
        (folder/'bad-signature.sids').write_bytes(bad)
        (folder/'bad-contract.sids').write_bytes(codec.sign(replace(models['B'],schema=b'\xa5'*32),key))
        meta['negative_packages']={'signature':'bad-signature.sids','feature_contract':'bad-contract.sids','replay':'release-A.sids'}
        write(folder/'experiment.json',meta)
        with (folder/'golden.jsonl').open('w',encoding='utf-8') as fh:
            for row in golden:
                clean={k:row[k] for k in ('id','origin','raw')}
                if 'source_row_id' in row:clean['source_row_id']=row['source_row_id']
                clean['expected']={}
                for name,model in models.items():
                    p,label=codec.infer(model,row['raw']);clean['expected'][name]={'probability':p,'label':label}
                fh.write(json.dumps(clean,allow_nan=False)+'\n')
    provenance=dict(source_kind='frozen_preexisting_development_models',new_training_performed=False,
        old_test_read=False,threshold_selection_performed=False,hardware_measured=False,
        source_sha256={str(path.relative_to(source)):sha(path.read_bytes()) for path in sorted(source.rglob('*')) if path.is_file()},
        semantics={'DT':'float32 raw; directed-down float32 branch split; leaf float32; strict probability > threshold',
        'LR_compatible':'float64 coefficient reexpression then once rounded float32; decision preserving in real arithmetic, measured agreement required',
        'C':'B parameters with version3 releaseC, no new training, used only for occupied-slot reuse'},
        development_metrics={family:{p:load(source/(family+'_'+p)/'metrics_development.json')['validation']['selected_FPR5'] for p in ('A','B')} for family in ('LR_log1p','DT5_raw')})
    write(output/'PROVENANCE.json',provenance)
    make_powercut_series(B,key,output/'powercut')
    return {family:load(output/family/'experiment.json') for family in ('lr','dt')}

def make_powercut_series(B,key,folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    series=[]
    for trial in range(1,201):
        model=replace(B,version=10000+trial,release='pc-B')
        package='powercut-%03d.sids'%trial;envelope=lr.sign(model,key)
        (folder/package).write_bytes(envelope)
        series.append(dict(trial=trial,version=model.version,package=package,model_sha256=sha(model.payload()),
            envelope_sha256=sha(envelope),release=model.release))
    write(folder/'series.json',dict(format_version=1,stage='completion020',runtime_abi=2,feature_count=8,
        schema_sha256=B.schema.hex(),source_parameters='frozen LR_log1p_B from stage018',
        trials=series,hardware_measured=False,physical_switch_required=True,
        delay_note='Delay allocation and controller timing belong to the power-cut runner; no physical timing claim is made by these signed packages.'))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-key',type=Path,required=True)
    parser.add_argument('--source',type=Path,default=ROOT/'references/frozen_development')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=prepare(args.source,args.output,lr.load_private(args.private_key))
    print(json.dumps({'status':'complete','families':{k:len(v['models']) for k,v in result.items()},'private_material_copied':False}))

if __name__=='__main__':main()
