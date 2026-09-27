#!/usr/bin/env python3
"""Stage028: frozen-model, frequency-aware TON diagnosis. No training or MCU IO."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import shutil
import sys
import time
import traceback
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
TOP_N=20
WEIGHT_CAP=100
COHORTS=('all_valid','known_vectors','retained_vectors','top20_frequency','remainder')
WEIGHTS=('rows','vector_balanced','frequency_cap100')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m


def now(): return datetime.now(timezone.utc).isoformat()
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
def dump(path,value):
    path=Path(path);tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8');os.replace(tmp,path)
def verify_kit():
    p=ROOT/'KIT_MANIFEST.json'
    data=json.loads(p.read_text(encoding='utf-8'))
    for rel,digest in data['sha256'].items():
        q=(ROOT/rel).resolve()
        if not q.is_relative_to(ROOT.resolve()) or sha(q)!=digest:raise ValueError('Kit file differs: '+rel)
    return sha(p)
def load_runtime():
    audit=load('audit028_frozen',ROOT/'vendor/audit_ton_full.py')
    core=load('evaluate028_frozen',ROOT/'vendor/evaluate_ton.py')
    known,kbind=audit.load_known(ROOT/'frozen020')
    models,predictors,mbind=core.load_frozen_models(ROOT/'frozen020')
    return audit,known,models,predictors,{'models':mbind,'known':kbind}


def discover(root,data_root=None,subset=False):
    audit=load('audit028_discover',ROOT/'vendor/audit_ton_full.py')
    expected=set(audit.EXPECTED_NAMES)
    if data_root is not None: candidates=[Path(data_root).resolve()]
    else:
        candidates=set()
        for directory,dirs,files in os.walk(Path(root).resolve()):
            dirs[:]=[d for d in dirs if d not in {'.venv','.git','node_modules','__pycache__','runs','frozen020'}]
            if expected.intersection(files):candidates.add(Path(directory))
        candidates=sorted(candidates)
    reports=[]
    for p in candidates:
        present=[n for n in audit.EXPECTED_NAMES if (p/n).is_file()]
        if present:reports.append({'path':str(p),'files':len(present),'names':present})
    eligible=[r for r in reports if r['files']==23 or subset]
    if len(eligible)!=1:raise ValueError('Need exactly one complete data directory. Use --data-root. Found: '+json.dumps(reports,ensure_ascii=False))
    selected=eligible[0]
    return Path(selected['path']),selected['names'],reports


class Progress:
    def __init__(self,path=None):self.path=path;self.last=0
    def __call__(self,event,force=True):
        if not force and time.monotonic()-self.last<15:return
        self.last=time.monotonic();event={'utc':now(),**event}
        print(json.dumps(event,ensure_ascii=False),flush=True)
        if self.path:
            with self.path.open('a',encoding='utf-8') as f:f.write(json.dumps(event,ensure_ascii=False)+'\n')


def verify_sources(data_dir,names,progress):
    receipt=json.loads((ROOT/'inputs/acquisition_download_20260925T090032614352Z.json').read_text())
    manifest=json.loads((ROOT/'inputs/ton_iot_mirror_v1_manifest.json').read_text())
    expected={e['file']:e for e in receipt['files']};headers={e['name']:e['csv_header'] for e in manifest['files']}
    bound=[]
    for name in names:
        p=data_dir/name;progress({'phase':'hash_inputs','file':name})
        before=(p.stat().st_size,p.stat().st_mtime_ns)
        digest=sha(p)
        if digest!=expected[name]['local_sha256'] or before[0]!=expected[name]['bytes']:raise ValueError('Source SHA256/size mismatch: '+name)
        with p.open(encoding='utf-8-sig',newline='') as f:header=next(csv.reader(f))
        if header!=headers[name] or before!=(p.stat().st_size,p.stat().st_mtime_ns):raise ValueError('Source header/stat changed: '+name)
        bound.append({'file':name,'path':str(p),'sha256':digest,'bytes':before[0],'mtime_ns':before[1],'header':header})
    return bound


def database(path):
    db=sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA cache_size=-65536');db.execute('PRAGMA temp_store=FILE')
    db.executescript('''CREATE TABLE IF NOT EXISTS vectors (key BLOB PRIMARY KEY, n0 INTEGER NOT NULL,n1 INTEGER NOT NULL,known INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS files (name TEXT PRIMARY KEY,report TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hourly (hour TEXT,stage TEXT,label INTEGER,kind TEXT,n INTEGER,PRIMARY KEY(hour,stage,label,kind)) WITHOUT ROWID;''')
    return db


def csv_batches(path,features,chunk_rows):
    csv.field_size_limit(16<<20)
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        reader=csv.reader(f,strict=True);header=next(reader);fi=[header.index(n) for n in features]
        meta={n:header.index(n) for n in ('ts','label','type','proto','conn_state')}
        for optional in ('history','service'):
            if optional in header:meta[optional]=header.index(optional)
        batch=[]
        for number,row in enumerate(reader,2):
            if len(row)!=len(header):raise ValueError(f'Malformed CSV {path.name}:{number}')
            if row[meta['label']] not in ('0','1'):raise ValueError('Unknown label')
            if any(len(row[j])>1024 for j in meta.values()):raise ValueError('Oversized metadata token')
            batch.append(([row[j] for j in fi],{n:row[j] for n,j in meta.items()}))
            if len(batch)>=chunk_rows:yield batch;batch=[]
        if batch:yield batch


def hour_of_timestamp(token):
    ts=float(token)
    if not np.isfinite(ts):raise ValueError('Invalid timestamp')
    return datetime.fromtimestamp(ts,tz=timezone.utc).replace(minute=0,second=0,microsecond=0).isoformat()


def aggregate_file(db,source,audit,known,chunk_rows,progress):
    name=source['file'];old=db.execute('SELECT report FROM files WHERE name=?',(name,)).fetchone()
    if old:return json.loads(old[0])
    report={'file':name,'rows':0,'valid_rows':0,'invalid_rows':0,'invalid_class_counts':[0,0],
            'valid_class_counts':[0,0],'known_class_counts':[0,0],'all_zero_class_counts':[0,0],
            'per_feature_zero_by_class':[[0]*8,[0]*8],'invalid_field_reasons':{},'sha256':source['sha256']}
    hours=Counter();bad=Counter();knownbytes=known.tobytes();knownset={knownbytes[i:i+32] for i in range(0,len(knownbytes),32)}
    path=Path(source['path']);before=(path.stat().st_size,path.stat().st_mtime_ns)
    if before!=(source['bytes'],source['mtime_ns']):raise ValueError('Source changed before reading '+name)
    try:
        db.execute('BEGIN')
        for batch in csv_batches(path,audit.FEATURES,chunk_rows):
            raw,valid,reasons,_=audit.normalize_raw([r[0] for r in batch])
            rows={};labels=np.array([int(r[1]['label']) for r in batch],dtype=np.int64)
            report['rows']+=len(batch);report['valid_rows']+=int(valid.sum());report['invalid_rows']+=int((~valid).sum())
            for c in (0,1):
                report['valid_class_counts'][c]+=int((valid&(labels==c)).sum())
                report['invalid_class_counts'][c]+=int((~valid&(labels==c)).sum())
                report['all_zero_class_counts'][c]+=int((valid&(labels==c)&(raw==0).all(axis=1)).sum())
                counts=(raw[valid&(labels==c)]==0).sum(axis=0)
                report['per_feature_zero_by_class'][c]=[int(a+b) for a,b in zip(report['per_feature_zero_by_class'][c],counts)]
            for j,n in enumerate(audit.FEATURES):
                vals,counts=np.unique(reasons[:,j],return_counts=True)
                for v,c in zip(vals,counts):
                    if v:bad[(n,audit.REASONS[int(v)])]+=int(c)
            for i,(_,m) in enumerate(batch):
                c=int(m['label']);hour=hour_of_timestamp(m['ts']);hours[(hour,'all_source',c,m['type'])]+=1
                if valid[i]:
                    hours[(hour,'valid_raw_contract',c,m['type'])]+=1
                    key=raw[i].tobytes();v=rows.setdefault(key,[0,0,None]);v[c]+=1
            updates=[]
            for key,(n0,n1,_) in rows.items():
                k=int(hashlib.sha256(key).digest() in knownset);updates.append((key,n0,n1,k))
                if k:report['known_class_counts'][0]+=n0;report['known_class_counts'][1]+=n1
            db.executemany('INSERT INTO vectors VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET n0=n0+excluded.n0,n1=n1+excluded.n1',updates)
            progress({'phase':'aggregate','file':name,'rows':report['rows']},force=False)
        if before!=(path.stat().st_size,path.stat().st_mtime_ns):raise ValueError('Source changed during read '+name)
        report['invalid_field_reasons']={f'{a}/{b}':n for (a,b),n in sorted(bad.items())}
        db.executemany('INSERT INTO hourly VALUES(?,?,?,?,?) ON CONFLICT(hour,stage,label,kind) DO UPDATE SET n=n+excluded.n',[(h,s,l,t,n) for (h,s,l,t),n in hours.items()])
        db.execute('INSERT INTO files VALUES(?,?)',(name,json.dumps(report)));db.commit()
    except BaseException:db.rollback();raise
    progress({'phase':'file_complete','file':name,'rows':report['rows']})
    return report


def metrics_from_mass(v):
    tn,fp,fn,tp,changed=map(float,v);n=tn+fp+fn+tp
    recall=tp/(tp+fn) if tp+fn else None;fpr=fp/(tn+fp) if tn+fp else None
    return {'confusion_mass_truth_pred_0_1':[[tn,fp],[fn,tp]],'total_mass':n,
            'recall':recall,'FPR':fpr,'balanced_accuracy':(recall+1-fpr)/2 if recall is not None and fpr is not None else None,
            'accuracy':(tn+tp)/n if n else None,'decision_disagreement_vs_family_B':changed/n if n else None}


def weighted_counts(n0,n1,pred,refs,mult):
    a=np.asarray(n0,dtype=np.float64)*mult;b=np.asarray(n1,dtype=np.float64)*mult
    return np.stack(((a[:,None]*(pred==0)).sum(0),(a[:,None]*(pred==1)).sum(0),
                     (b[:,None]*(pred==0)).sum(0),(b[:,None]*(pred==1)).sum(0),
                     ((a+b)[:,None]*(pred!=pred[:,refs])).sum(0)),axis=1)


def evaluate_vectors(db,models,predictors,progress,chunk_rows):
    names=list(models);refs=[names.index('DT_B' if n.startswith('DT_') else 'B') for n in names]
    top=db.execute('SELECT key,n0,n1,known FROM vectors ORDER BY n0+n1 DESC,key LIMIT ?',(TOP_N,)).fetchall();topkeys={r[0] for r in top}
    masses={g:{w:np.zeros((len(names),5)) for w in WEIGHTS} for g in COHORTS}
    changes={g:{w:np.zeros((2,2,2)) for w in WEIGHTS} for g in COHORTS}
    stats={g:{'vectors':0,'conflicting_vectors':0,'empirical_minimum_errors_on_observed_vectors':0,'rows':0,'normal_rows':0,'attack_rows':0,'changed_DT_A_B_rows':0,'changed_DT_A_B_vectors':0} for g in COHORTS}
    allzero=None;topchanged=[];processed=0
    cursor=db.execute('SELECT key,n0,n1,known FROM vectors ORDER BY key')
    while True:
        rows=cursor.fetchmany(chunk_rows)
        if not rows:break
        raw=np.frombuffer(b''.join(r[0] for r in rows),dtype='<f4').reshape(-1,8)
        pairs=[predictors[n](models[n],raw) for n in names]
        pred=np.stack([p[1] for p in pairs],axis=1)
        if pred.shape!=(len(rows),len(names)) or not np.isin(pred,[0,1]).all():raise ValueError('Invalid predictions')
        for prob,_ in pairs:
            if not np.isfinite(prob).all() or (prob<0).any() or (prob>1).any():raise ValueError('Invalid probabilities')
        n0=np.array([r[1] for r in rows],dtype=np.int64);n1=np.array([r[2] for r in rows],dtype=np.int64);n=n0+n1
        known=np.array([r[3] for r in rows],dtype=bool);topmask=np.array([r[0] in topkeys for r in rows])
        pa=pred[:,names.index('DT_A')];pb=pred[:,names.index('DT_B')]
        for g,mask in zip(COHORTS,(np.ones(len(rows),bool),known,~known,topmask,~topmask)):
            st=stats[g];st['vectors']+=int(mask.sum());st['conflicting_vectors']+=int((mask&(n0>0)&(n1>0)).sum());st['empirical_minimum_errors_on_observed_vectors']+=int(np.minimum(n0,n1)[mask].sum())
            st['rows']+=int(n[mask].sum());st['normal_rows']+=int(n0[mask].sum());st['attack_rows']+=int(n1[mask].sum());st['changed_DT_A_B_rows']+=int(n[mask&(pa!=pb)].sum());st['changed_DT_A_B_vectors']+=int((mask&(pa!=pb)).sum())
            for w,mult in zip(WEIGHTS,(np.ones(len(rows)),1/n,np.minimum(n,WEIGHT_CAP)/n)):
                coeff=mult*mask;masses[g][w]+=weighted_counts(n0,n1,pred,refs,coeff)
                for c,counts in ((0,n0),(1,n1)):np.add.at(changes[g][w][c],(pa,pb),counts*coeff)
        for i,r in enumerate(rows):
            if pa[i]!=pb[i]:topchanged.append((int(n[i]),r[0],r[1],r[2],r[3],int(pa[i]),int(pb[i])))
            if r[0]==b'\x00'*32:allzero={'normal_rows':r[1],'attack_rows':r[2],'known_vector':bool(r[3]),'predictions':{nm:{'probability':float(pairs[j][0][i]),'label':int(pred[i,j])} for j,nm in enumerate(names)}}
        topchanged=sorted(topchanged,key=lambda r:(-r[0],r[1]))[:20]
        processed+=len(rows);progress({'phase':'predict_unique_vectors','unique_vectors':processed},force=False)
    results={g:{'counts':stats[g],'weighted_metrics':{w:{name:metrics_from_mass(masses[g][w][j]) for j,name in enumerate(names)} for w in WEIGHTS},
                'DT_A_B_transition_mass_truth_A_B':{w:changes[g][w].tolist() for w in WEIGHTS}} for g in COHORTS}
    if results['known_vectors']['counts']['rows']+results['retained_vectors']['counts']['rows']!=results['all_valid']['counts']['rows']:raise ValueError('Cohort count mismatch')
    if results['top20_frequency']['counts']['rows']+results['remainder']['counts']['rows']!=results['all_valid']['counts']['rows']:raise ValueError('Top/remainder count mismatch')
    def descriptor(r):
        key,n0_,n1_,known_=r
        raw_=np.frombuffer(key,dtype='<f4').reshape(1,8)
        pr={name:{'probability':float(pair[0][0]),'label':int(pair[1][0])} for name in names for pair in [predictors[name](models[name],raw_)]}
        return {'vector':raw_[0].astype(float).tolist(),'sha256_float32':hashlib.sha256(key).hexdigest(),'normal_rows':n0_,'attack_rows':n1_,'known_vector':bool(known_),'predictions':pr}
    changeddescs=[descriptor((r[1],r[2],r[3],r[4])) for r in topchanged]
    probe_keys={np.array([0,0,0,0,1,size,0,0],dtype='<f4').tobytes() for size in (40,44,48)}
    probe_records=[]
    for key in sorted(probe_keys):
        r=db.execute('SELECT key,n0,n1,known FROM vectors WHERE key=?',(key,)).fetchone()
        if r is not None:probe_records.append(descriptor(r))
        else:probe_records.append({'vector':np.frombuffer(key,dtype='<f4').astype(float).tolist(),'sha256_float32':hashlib.sha256(key).hexdigest(),'normal_rows':0,'attack_rows':0,'present':False})
    return {'cohorts':results,'all_zero_vector':allzero,'top20_frequency':[descriptor(r) for r in top],
            'top20_DT_A_B_changed_frequency':changeddescs,'requested_probe_vectors':probe_records},topkeys|{r[1] for r in topchanged}|{b'\x00'*32}|probe_keys


def top_metadata(sources,keys,audit,chunk_rows,progress,checkpoint):
    allrecords={};done={}
    if checkpoint.exists():done=json.loads(checkpoint.read_text())
    for source in sources:
        name=source['file']
        if name in done:continue
        per=defaultdict(Counter);count=0
        for batch in csv_batches(Path(source['path']),audit.FEATURES,chunk_rows):
            raw,valid,_,_=audit.normalize_raw([r[0] for r in batch]);count+=len(batch)
            for i,(_,m) in enumerate(batch):
                if not valid[i]:continue
                key=raw[i].tobytes()
                if key not in keys:continue
                digest=hashlib.sha256(key).hexdigest()
                joint={k:m.get(k,'<column_absent>') for k in ('proto','conn_state','history','service','label','type')}
                per[digest][json.dumps(joint,sort_keys=True)]+=1
            progress({'phase':'top_vector_metadata_second_pass','file':name,'rows':count},force=False)
        done[name]={h:dict(c) for h,c in per.items()};dump(checkpoint,done)
    totals=defaultdict(Counter)
    for filedata in done.values():
        for h,counts in filedata.items():totals[h].update(counts)
    for h,counts in totals.items():
        marginal={k:Counter() for k in ('proto','conn_state','history','service','label','type')}
        joint=[]
        for token,n in sorted(counts.items(),key=lambda x:(-x[1],x[0])):
            m=json.loads(token);joint.append({**m,'rows':n})
            for k,v in m.items():marginal[k][v]+=n
        allrecords[h]={'rows':sum(counts.values()),'marginal_counts':{k:dict(c) for k,c in marginal.items()},'joint_counts':joint}
    return allrecords


def execute(args):
    kit_hash=verify_kit();out=Path(args.output).resolve()
    if args.resume:
        if not out.is_dir():raise ValueError('--resume needs existing output')
        if (out/'summary.json').exists() and json.loads((out/'summary.json').read_text()).get('status')=='complete':raise ValueError('Run already complete')
    else:out.mkdir(parents=True,exist_ok=False)
    progress=Progress(out/'progress.jsonl');start=time.monotonic()
    state={'stage':'028','status':'running','hardware_accessed':False,'training_performed':False,'threshold_selection_performed':False,'started_utc':now()}
    dump(out/'summary.json',state)
    db=None
    try:
        data_dir,names,_=discover(args.root,args.data_root,args.smoke_one_file)
        if args.smoke_one_file and len(names)!=1:raise ValueError('Smoke requires exactly one pinned source file')
        sources=verify_sources(data_dir,names,progress)
        audit,known,models,predictors,bindings=load_runtime()
        lock={'stage':'028','kit_manifest_sha256':kit_hash,'sources':sources,'models_and_known_inputs':bindings,
              'model_ids':list(models),'feature_order':list(audit.FEATURES),'top_vectors':TOP_N,'frequency_cap':WEIGHT_CAP,
              'weight_definitions':{'rows':'each valid row has weight 1','vector_balanced':'each row of vector v has weight 1/n_v; conflicting labels retain their empirical proportions','frequency_cap100':'each row has weight min(n_v,100)/n_v'},
              'scope':'single_file_smoke' if args.smoke_one_file else 'full_23_files','analysis_status':'prespecified implementation after exploratory analysis; not untouched independent test',
              'python':platform.python_version(),'numpy':np.__version__,'platform':platform.platform()}
        lockpath=out/'protocol_lock_before_predictions.json'
        if args.resume:
            previous=json.loads(lockpath.read_text())
            if previous!=lock:raise ValueError('Resume bindings/runtime differ from frozen lock')
        else:dump(lockpath,lock)
        db=database(out/'vectors.sqlite3')
        reports=[aggregate_file(db,s,audit,known,args.chunk_rows,progress) for s in sources]
        dump(out/'per_file.json',reports)
        with (out/'hourly_counts.csv').open('w',newline='',encoding='utf-8') as f:
            w=csv.writer(f);w.writerow(('utc_hour','stage','label','type','rows'));w.writerows(db.execute('SELECT hour,stage,label,kind,n FROM hourly ORDER BY hour,stage,label,kind'))
        coverage=load('coverage028',ROOT/'tools/coverage028.py')
        coverage_path=out/'coverage'
        if coverage_path.exists():
            old_coverage=json.loads((coverage_path/'coverage_summary.json').read_text())
            if old_coverage['source_csv_sha256']!=sha(out/'hourly_counts.csv'):raise ValueError('Coverage source changed on resume')
            coverage_summary={k:old_coverage[k] for k in ('candidate_count','candidates_with_all_four_test_groups','candidates_with_two_class_fit_and_cal_roles','candidates_with_both_properties','split_selected')}
            coverage_summary['output_dir']=str(coverage_path)
        else:
            temporary_coverage=out/'coverage.building'
            if temporary_coverage.exists():shutil.rmtree(temporary_coverage)
            coverage_summary=coverage.build_coverage(out/'hourly_counts.csv',temporary_coverage)
            temporary_coverage.rename(coverage_path)
            coverage_summary['output_dir']=str(coverage_path)
        result,keys=evaluate_vectors(db,models,predictors,progress,args.chunk_rows)
        metadata=top_metadata(sources,keys,audit,args.chunk_rows,progress,out/'top_metadata_checkpoint.json')
        for listname in ('top20_frequency','top20_DT_A_B_changed_frequency','requested_probe_vectors'):
            for record in result[listname]:
                record['source_metadata']=metadata.get(record['sha256_float32'],{'rows':0})
                if record['source_metadata']['rows']!=record['normal_rows']+record['attack_rows']:raise ValueError('Top-vector metadata count mismatch')
        if result['all_zero_vector']:
            result['all_zero_vector']['source_metadata']=metadata.get(hashlib.sha256(b'\x00'*32).hexdigest(),{'rows':0})
        dump(out/'diagnostics.json',result)
        source_rows=sum(r['rows'] for r in reports);valid_rows=sum(r['valid_rows'] for r in reports)
        if valid_rows!=result['cohorts']['all_valid']['counts']['rows']:raise ValueError('Aggregate/prediction row count mismatch')
        # Check every source's bytes again before declaring success; mtime alone is insufficient.
        for s in sources:
            progress({'phase':'final_hash_check','file':s['file']})
            if sha(s['path'])!=s['sha256']:raise ValueError('Source changed during run')
        state.update(status='complete',scope=lock['scope'],files_processed=len(sources),source_rows=source_rows,valid_rows=valid_rows,invalid_rows=source_rows-valid_rows,
                     unique_valid_vectors=result['cohorts']['all_valid']['counts']['vectors'],finished_utc=now(),elapsed_seconds=time.monotonic()-start,
                     coverage_summary=coverage_summary,limitations=['Post-exploration description of the same TON collection; not an independent test.',
                      'Equal-vector and capped-frequency metrics are alternative estimands, not corrected population performance or independent replicates.',
                      'Known eight-vectors are input overlaps with the old CSV, not verified identical flows or fitted rows.',
                      'proto/conn_state can support a SYN hypothesis but this CSV may lack TCP flags/history; do not infer flags from packet bytes alone.',
                      'Coverage tables show timestamp/class support only; candidate windows are not selected automatically. No model is retrained.',
                      'No confidence intervals are emitted because independent session/device/block units are not established.'])
        dump(out/'summary.json',state)
        db.close();db=None
        evidence={p.relative_to(out).as_posix():sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name not in {'vectors.sqlite3','evidence_manifest.json'} and not p.name.endswith('.tmp')}
        dump(out/'evidence_manifest.json',{'sha256':evidence,'sqlite_cache_sha256':sha(out/'vectors.sqlite3'),'sqlite_cache_reconstructible':True})
        return state
    except BaseException as e:
        state.update(status='failed',error=str(e),finished_utc=now());dump(out/'summary.json',state)
        raise
    finally:
        if db is not None:db.close()


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
    for n in ('inspect','run'):
        q=s.add_parser(n);q.add_argument('--root',type=Path,default=Path.cwd());q.add_argument('--data-root',type=Path)
        if n=='run':
            q.add_argument('--output',type=Path,required=True);q.add_argument('--chunk-rows',type=int,default=20000);q.add_argument('--resume',action='store_true')
            q.add_argument('--smoke-one-file',action='store_true',help='Only for pinned single-file local validation; never full-collection evidence')
    a=p.parse_args(argv)
    try:
        if a.command=='inspect':
            kh=verify_kit();d,n,r=discover(a.root,a.data_root);print(json.dumps({'status':'ready','kit_sha256':kh,'data_root':str(d),'files':len(n),'candidates':r,'hardware_accessed':False},ensure_ascii=False));return 0
        if not 100<=a.chunk_rows<=100000:raise ValueError('--chunk-rows must be 100..100000')
        if a.smoke_one_file and a.data_root is None:raise ValueError('Smoke requires explicit --data-root')
        result=execute(a);print(json.dumps(result,ensure_ascii=False));return 0
    except (Exception,KeyboardInterrupt) as e:print('error: '+str(e),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
