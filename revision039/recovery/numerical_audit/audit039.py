#!/usr/bin/env python3
"""Read-only numerical audit of recorded 039, without hardware or retuning.

Original software author: Oleksandr Kuznetsov.

Creates only files in --output. Requires numpy, g++, and OpenSSL development
headers. The native executable uses the unchanged delivered C++ core; the
adapter adds output of its existing q_score argument.
"""
import argparse
from collections import Counter, defaultdict
import csv
import ctypes
import ctypes.util
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import numpy as np

sys.dont_write_bytecode = True


def load(p):
    return json.loads(Path(p).read_text())


def lines(p):
    return [json.loads(s) for s in Path(p).read_text().splitlines()]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def save(p, obj):
    Path(p).write_text(json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False)+'\n')


def check(ok, why):
    if not ok:
        raise ValueError(why)


def verify_dir(d):
    count=0
    for name,digest in load(d/'manifest.json')['sha256'].items():
        p=(d/name.replace('\\','/')).resolve()
        check(p.is_relative_to(d.resolve()) and sha(p)==digest, 'File hash: '+name)
        count+=1
    return count


def parse_raw(transcript):
    buf=b'';result=[]
    for r in transcript:
        if r.get('direction')!='rx_bytes':continue
        buf+=bytes.fromhex(r['bytes_hex'])
        while b'\n' in buf:
            line,buf=buf.split(b'\n',1)
            if line.lstrip().startswith(b'{'):
                result.append((r['phase'],json.loads(line)))
    check(not buf,'Incomplete receive bytes')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--results',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); root=a.root.resolve();run=a.results.resolve();out=a.output.resolve()
    check(not out.is_relative_to(root) and not out.is_relative_to(run),'Output must be separate')
    out.mkdir(parents=True,exist_ok=True)
    prep=run/'prepared/numerics';hw=run/'mcu/esp32s3-a0f262ebb558/Og/numerics'
    hashes=dict(prepared_files_verified=verify_dir(prep),hardware_files_verified=verify_dir(hw))
    panel=load(prep/'panel.json')['vectors'];raw=np.asarray([r['raw'] for r in panel],dtype='<f4')
    check(raw.shape==(1024,8),'Panel shape')
    check(len({r.tobytes() for r in raw})==1024,'Unique inputs')
    lock=load(prep/'PROTOCOL_LOCK.json')
    for name,digest in lock['code_sha256'].items():
        check(sha(root/name.replace('\\','/'))==digest,'Recorded code fingerprint '+name)
    meta=load(hw/'artifacts/artifacts.json')
    models={p.stem:load(p) for p in (prep/'models').glob('*.json')}
    golden={p.stem:load(p) for p in (prep/'golden').glob('*.json')}
    observations={}
    counts=defaultdict(Counter);family_counts=defaultdict(Counter);bad=[];max_error=0.
    for family,fm in meta['families'].items():
        tr=lines(hw/family/'transcript.jsonl');rx=parse_raw(tr);obs=lines(hw/family/'observations.jsonl')
        for version,v in fm['versions'].items():
            name=v['model'];og=[r for r in obs if r['phase']==name]
            got=[r for phase,r in rx if phase==name and r.get('event')=='inference']
            tx=[r['line'] for r in tr if r.get('direction')=='tx' and r['phase']==name and r['line'].startswith('INFER ')]
            check(len(og)==len(got)==len(tx)==1024,'Phase counts '+name)
            observations[name]=og
            for i,(o,reply,cmd) in enumerate(zip(og,got,tx)):
                check(o['index']==i and o['response']==reply,'Raw/observation '+name)
                actual=np.asarray([float(x) for x in cmd[6:].split(',')],dtype='<f4')
                check(actual.tobytes()==raw[i].tobytes()==np.asarray(o['raw'],dtype='<f4').tobytes(),'TX input '+name)
                check(reply['bundle_sha256']==v['identity']['bundle_sha256'] and reply['version']==int(version),'Model identity')
                g=golden[name];err=abs(reply['probability']-g['probabilities'][i]);lm=reply['label']!=g['labels'][i]
                qm=reply['q_score']!=g['scores'][i] if family=='mlp_int8' else None
                check(o['expected_probability']==g['probabilities'][i] and o['expected_label']==g['labels'][i],'Golden reference')
                check(err==o['probability_abs_error'] and lm==o['label_mismatch'] and qm==o['integer_code_mismatch'],'Computed errors')
                cat=panel[i]['category'];c=counts[cat];c['evaluations']+=1;c['label_mismatches']+=int(lm)
                c['probability_tolerance_exceeded']+=int(err>2e-6)
                if qm is not None:c['integer_codes_compared']+=1;c['integer_code_mismatches']+=int(qm)
                fc=family_counts[family];fc['evaluations']+=1;fc['label_mismatches']+=int(lm)
                fc['probability_tolerance_exceeded']+=int(err>2e-6)
                fc['max_probability_abs_error']=max(fc['max_probability_abs_error'],err)
                if qm is not None:fc['integer_codes_compared']+=1;fc['integer_code_mismatches']+=int(qm)
                max_error=max(max_error,err)
                if lm or qm or err>2e-6:
                    bad.append(dict(model=name,family=family,index=i,category=cat,panel=panel[i],expected_probability=g['probabilities'][i],
                        actual_probability=reply['probability'],expected_label=g['labels'][i],actual_label=reply['label'],
                        probability_error=err,threshold=models[name]['threshold'],
                        expected_score=g['scores'][i],actual_q_score=reply.get('q_score'),q_threshold=models[name].get('q_threshold'),
                        label_mismatch=lm,integer_code_mismatch=qm))
    # Native harness uses actual signed MCU artifacts; OpenSSL verifies each.
    original=root/'research030/validation/native030.cpp';src=original.read_text()
    before='auto inf=engine.infer(raw.data(),8,p,label);'
    after='int32_t qs=0;auto inf=engine.infer(raw.data(),8,p,label,&qs);'
    check(src.count(before)==1,'Harness call anchor')
    src=src.replace(before,after)
    before='\\"label\\":%d}\\n",double(p),label'
    after='\\"label\\":%d,\\"q_score\\":%d}\\n",double(p),label,qs'
    check(src.count(before)==1,'Harness output anchor')
    src=src.replace(before,after);(out/'native039_qscore.cpp').write_text(src)
    header=(root/'revision039/build/prebuilt/Og/mlp_int8_bundle/factory_model_contract.h').read_text()
    pem=re.search(r'-----BEGIN PUBLIC KEY-----\n.*?-----END PUBLIC KEY-----',header,re.S).group(0)+'\n'
    (out/'public.pem').write_text(pem)
    core=root/'revision039/firmware/components/ids_core';exe=out/'native039_qscore'
    command=['g++','-std=c++17','-O2','-ffp-contract=off','-I',str(core/'include'),str(out/'native039_qscore.cpp'),
             *[str(core/n) for n in ('ids_core.cpp','ids_tree.cpp','ids_mlp.cpp')],'-lcrypto','-o',str(exe)]
    build=subprocess.run(command,capture_output=True,text=True,check=True)
    (out/'compile_stdout.txt').write_text(build.stdout);(out/'compile_stderr.txt').write_text(build.stderr)
    native_results={}
    for family,fm in meta['families'].items():
        for v in fm['versions'].values():
            name=v['model'];res=subprocess.run([str(exe),str(hw/'artifacts'/v['path']),str(out/'public.pem')],
                input=raw.tobytes(),capture_output=True,check=True)
            (out/f'native_{name}.jsonl').write_bytes(res.stdout)
            nr=[json.loads(l) for l in res.stdout.splitlines()];check(len(nr)==1024 and all(x['ok'] for x in nr),'Native inference')
            g=golden[name];og=observations[name]
            n=dict(native_vs_MCU_label_mismatch_indices=[i for i,(x,o) in enumerate(zip(nr,og)) if x['label']!=o['response']['label']],
                   native_vs_golden_label_mismatch_indices=[i for i,x in enumerate(nr) if x['label']!=g['labels'][i]],
                   max_native_vs_MCU_probability_error=max(abs(x['p']-o['response']['probability']) for x,o in zip(nr,og)))
            if family=='mlp_int8':n.update(
                native_vs_MCU_q_score_mismatch_indices=[i for i,(x,o) in enumerate(zip(nr,og)) if x['q_score']!=o['response']['q_score']],
                native_vs_golden_q_score_mismatch_indices=[i for i,x in enumerate(nr) if x['q_score']!=g['scores'][i]])
            native_results[name]=n
    save(out/'native_comparison.json',native_results)
    # Independent scalar integer trace and one-ULP transcendental sensitivity.
    libname=ctypes.util.find_library('m');lib=ctypes.CDLL(libname);logf=lib.log1pf
    logf.argtypes=[ctypes.c_float];logf.restype=ctypes.c_float
    m=models['B_mlp_int8'];trace=[]
    def integer_trace(q):
        values=[q.tolist()]
        for j,l in enumerate(m['layers']):
            acc=q@np.asarray(l['weights'],np.int64)+np.asarray(l['bias'],np.int64)
            prod=acc*int(l['multiplier']);shift=int(l['shift'])
            q=np.clip(np.sign(prod)*((np.abs(prod)+(1<<(shift-1)))>>shift),-127,127)
            if j<2:q=np.maximum(q,0)
            values.append(q.tolist())
        return values
    for index,feature,direction in ((850,0,-np.inf),(877,3,np.inf),(1004,2,-np.inf)):
        transformed=np.asarray([logf(float(v)) for v in raw[index]],np.float32)
        cases=[]
        for case in ('scalar_libm','one_ulp_neighbor'):
            if case=='one_ulp_neighbor':transformed[feature]=np.nextafter(transformed[feature],np.float32(direction))
            normalized=np.asarray((transformed-np.asarray(m['mean'],np.float32))/np.asarray(m['scale'],np.float32),np.float32)
            ratio=np.asarray(normalized/np.float32(m['input_scale']),np.float32)
            q=np.clip(np.copysign(np.floor(np.abs(ratio.astype(np.float64))+.5),ratio),-127,127).astype(np.int64)
            layers=integer_trace(q)
            cases.append(dict(case=case,log1p_feature=float(transformed[feature]),quantizer_input_feature=float(ratio[feature]),
                input_quantized=q.tolist(),layer_outputs=layers[1:],output_score=layers[-1][0]))
        actual=observations['B_mlp_int8'][index]['response']['q_score'];expected=int(golden['B_mlp_int8']['scores'][index])
        check(cases[0]['output_score']==actual and cases[1]['output_score']==expected,'One-ULP sensitivity witness')
        trace.append(dict(index=index,feature=feature,feature_name=load(prep/'panel.json')['features'][feature],
            actual_q_score=actual,golden_q_score=expected,cases=cases,
            scope='Native scalar frontend reproduces MCU; one-ULP neighbor is a mechanism witness, not MCU intermediate telemetry'))
    save(out/'quantizer_boundary_traces.json',trace)
    # Saved Windows golden stays authoritative. Additional Linux evaluation is
    # a diagnostic of reference portability, never a replacement golden.
    spec=importlib.util.spec_from_file_location('audited_ref030',root/'research030/training/model030.py')
    ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
    py_results={}
    for name,m in models.items():
        pp,yy,ss=ref.predict(m,raw,True);g=golden[name]
        py_results[name]=dict(saved_Windows_vs_local_Linux_label_mismatch_indices=np.flatnonzero(yy!=g['labels']).tolist(),
            max_probability_error=float(np.max(np.abs(pp.astype(np.float64)-g['probabilities']))))
        if m['kind']=='mlp_int8':py_results[name]['q_score_mismatch_indices']=np.flatnonzero(ss!=g['scores']).tolist()
    save(out/'host_platform_comparison.json',py_results)
    result=dict(status='AUDIT_COMPLETE_DISAGREEMENTS_PRESERVED',source_summary_status=load(hw/'summary.json')['status'],
        source_all_numerical_checks_agree=load(hw/'summary.json')['all_numerical_checks_agree'],
        models=len(models),unique_inputs=1024,inference_records=sum(c['evaluations'] for c in counts.values()),
        counts_by_category={k:dict(v) for k,v in counts.items()},max_probability_abs_error=max_error,
        counts_by_family={k:dict(v) for k,v in family_counts.items()},
        label_mismatches=sum(c['label_mismatches'] for c in counts.values()),
        integer_code_mismatches=sum(c['integer_code_mismatches'] for c in counts.values()),
        probability_tolerance_exceeded=sum(c['probability_tolerance_exceeded'] for c in counts.values()),
        failed_unique_input_indices=sorted({b['index'] for b in bad}),
        integer_failed_unique_input_indices=sorted({b['index'] for b in bad if b['integer_code_mismatch']}),
        native_vs_MCU_label_mismatches=sum(len(r['native_vs_MCU_label_mismatch_indices']) for r in native_results.values()),
        native_vs_MCU_integer_code_mismatches=sum(len(r.get('native_vs_MCU_q_score_mismatch_indices',[])) for r in native_results.values()),
        evidence_hashes=hashes,source_hashes={str(p.relative_to(root)):sha(p) for p in [original,*[core/n for n in ('ids_core.cpp','ids_tree.cpp','ids_mlp.cpp')]]},
        compile_command=command,compiler=subprocess.run(['g++','--version'],capture_output=True,text=True,check=True).stdout,
        environment=dict(python=sys.version,numpy=np.__version__,platform=platform.platform(),libm=libname),
        limits=['The panel deliberately targets boundaries; rates do not estimate real-world error probabilities.',
                '512 real inputs are already-exposed saved fitting/calibration samples, not a new detection test.',
                'No MCU intermediate logs were recorded; exact MCU log1p and input q values are inferred from native reproduction and sensitivity witnesses.',
                'Original golden, models, thresholds and protocol remain unchanged. No pass is manufactured by replacing the reference.',
                'This is Og on one board. O2 and other-board numerical runs are not present.'])
    save(out/'result.json',result);save(out/'disagreements.json',bad)
    with (out/'label_disagreements.csv').open('w',newline='') as f:
        keys=['family','model','index','category','decision_rule','expected_probability','actual_probability','probability_error',
              'threshold','expected_probability_margin','actual_probability_margin','expected_label','actual_label',
              'expected_score','actual_q_score','q_threshold','expected_code_margin','actual_code_margin']
        w=csv.DictWriter(f,keys);w.writeheader()
        for b in bad:
            if not b['label_mismatch']:continue
            row={k:b.get(k) for k in keys};row['expected_probability_margin']=b['expected_probability']-b['threshold']
            row['decision_rule']='q_score >= q_threshold' if b['q_threshold'] is not None else 'probability > threshold'
            row['actual_probability_margin']=b['actual_probability']-b['threshold']
            if b['q_threshold'] is not None:
                row['expected_code_margin']=b['expected_score']-b['q_threshold'];row['actual_code_margin']=b['actual_q_score']-b['q_threshold']
            w.writerow(row)
    with (out/'family_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,['family','evaluations','label_mismatches','probability_tolerance_exceeded','max_probability_abs_error',
                            'integer_codes_compared','integer_code_mismatches']);w.writeheader()
        for fam,c in family_counts.items():w.writerow({'family':fam,**dict(c)})
    print(json.dumps({k:v for k,v in result.items() if k in ('status','models','unique_inputs','inference_records','label_mismatches','integer_code_mismatches','probability_tolerance_exceeded','native_vs_MCU_label_mismatches','native_vs_MCU_integer_code_mismatches','counts_by_category')}))


if __name__=='__main__':main()
