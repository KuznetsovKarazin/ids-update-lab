#!/usr/bin/env python3
"""One pass over pinned TON CSV, deterministic fitting, frozen future evaluation.

No board or power meter access. Output is never reused implicitly. The runner
can be given --resume only to reuse a fully completed, manifest-verified result
(the top-level runner implements that; this program accepts fresh output only).
"""
from __future__ import annotations
import os
for _key in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS'):
    os.environ[_key]='1'
import argparse
from collections import Counter,defaultdict
import copy
import csv
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import sqlite3
import sys
import time
import traceback
import warnings
import numpy as np
from model030 import FEATURES,predict,preprocess,sigmoid,quantize,calibrate,compatible_lr,compatible_mlp,transfer_qthreshold

ROOT=Path(__file__).resolve().parent
ROLES=('A_fit','A_cal','B_fit_added','B_cal','common_test')
SEED=25092026
CONFIG={
 'schema':'030_training_v1','study_status':'prespecified after exploratory analysis; test days previously inspected',
 'seed':SEED,'features':FEATURES,'feature_contract':'nonnegative finite float32, little endian, signed zero canonicalized',
 'sample_method':'bottom-k SplitMix64 priority of source file ordinal and CSV row index, independent of values',
 'fit_cap_per_attack_type':50000,'fit_cap_normal':100000,'cal_cap_per_label_type':100000,
 'fit_weight':'population stratum count / sampled stratum count, then class balancing by population class totals',
 'LR':{'C':1.0,'solver':'lbfgs','max_iter':1000,'tol':1e-6},
 'DT':{'max_depth':5,'min_samples_leaf':50,'criterion':'gini'},
 'MLP':{'shape':[8,16,8,1],'epochs':30,'batch_size':1024,'learning_rate':0.001,'optimizer':'Adam','l2':1e-4},
 'operating_point':{'target_empirical_calibration_FPR':0.01,'rule':'strictly above normal order statistic, preserve ties, no test tuning'},
 'frequency_cap':100,'frequent_vectors':20,'ci_minimum_days':8,'bootstrap_repeats':10000,
 'hyperparameter_selection':'none; all fixed families are reported',
 'input_quantization_calibration':'fitting sample only',
 'uncertainty':'paired UTC-day block bootstrap only if >=8 observed test days; otherwise descriptive leave-one-day-out, no CI',
 'thread_limit':1,
}

def now():return datetime.now(timezone.utc).isoformat()
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
def dump(path,value):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_suffix(p.suffix+'.tmp')
 tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8');os.replace(tmp,p)
def epoch(s):return datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
def progress(phase,**kw):print(json.dumps({'utc':now(),'phase':phase,**kw}),flush=True)

def splitmix64(x):
 x=np.asarray(x,np.uint64)
 with np.errstate(over='ignore'):
  z=x+np.uint64(0x9E3779B97F4A7C15+SEED)
  z=(z^(z>>np.uint64(30)))*np.uint64(0xBF58476D1CE4E5B9)
  z=(z^(z>>np.uint64(27)))*np.uint64(0x94D049BB133111EB)
 return z^(z>>np.uint64(31))

class BottomK:
 def __init__(self,k):self.k=k;self.n=0;self.x=np.empty((0,8),np.float32);self.ids=np.empty(0,np.uint64);self.keys=np.empty(0,np.uint64)
 def add(self,x,ids):
  self.n+=len(x)
  if not len(x):return
  keys=splitmix64(ids)
  if len(self.keys)==self.k:
   keep=keys<=self.keys.max();keys=keys[keep];ids=ids[keep];x=x[keep]
  keys=np.concatenate((self.keys,keys));ids=np.concatenate((self.ids,ids));x=np.concatenate((self.x,x))
  if len(keys)>self.k:
   # SplitMix is a permutation: priorities are distinct for distinct row IDs.
   chosen=np.argpartition(keys,self.k-1)[:self.k];keys,ids,x=keys[chosen],ids[chosen],x[chosen]
  self.keys,self.ids,self.x=keys,ids,x
 def arrays(self):
  order=np.argsort(self.ids,kind='stable');return self.x[order],self.ids[order]

def valid_numeric(tokens):
 spec=importlib.util.spec_from_file_location('audit030',ROOT/'vendor/audit_ton_full.py')
 if not hasattr(valid_numeric,'module'):
  m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);valid_numeric.module=m
 return valid_numeric.module.normalize_raw(tokens)

def effective_intervals(protocol):
 intervals=protocol['intervals'];allends=[]
 for name in ROLES:
  for lo,hi in intervals[name]:allends.extend((epoch(lo),epoch(hi)))
 outerlo,outerhi=min(allends),max(allends)
 gap=float(protocol.get('flow_boundary_enforcement',{}).get('gap_seconds',60))
 if gap!=60:raise ValueError('Version030 is frozen to 60-second internal margins')
 result={}
 for name in ROLES:
  result[name]=[(epoch(a)+(gap if epoch(a)>outerlo else 0),epoch(b)-(gap if epoch(b)<outerhi else 0)) for a,b in intervals[name]]
 return result

def masks_for_intervals(ts,duration,intervals):
 result={}
 for role,bounds in intervals.items():
  inside=np.zeros(len(ts),bool)
  for lo,hi in bounds:inside|=(ts>=lo)&(ts<hi)&((ts+duration)<hi)
  result[role]=inside
 if np.any(np.sum(list(result.values()),axis=0)>1):raise ValueError('Atomic temporal roles overlap')
 return result

def find_sources(root,data_root=None,subset=False):
 manifest=json.loads((ROOT/'vendor/source_manifest.json').read_text(encoding='utf-8'))
 entries=manifest['files'];names=[x['file'] for x in entries]
 if data_root:candidates=[Path(data_root).resolve()]
 else:
  candidates=[]
  for directory,dirs,files in os.walk(root):
   dirs[:]=[d for d in dirs if d not in {'.venv','.git','node_modules','runs','__pycache__'}]
   if set(names).intersection(files):candidates.append(Path(directory))
 complete=[p for p in candidates if sum((p/n).is_file() for n in names)==23 or (subset and any((p/n).is_file() for n in names))]
 if len(complete)!=1:raise ValueError('Need one TON folder; specify --data-root. Candidate folders: '+str(candidates))
 found=[]
 for ordinal,e in enumerate(entries):
  p=complete[0]/e['file']
  if subset and not p.is_file():continue
  progress('hash_source',file=e['file'])
  st=p.stat();digest=sha(p)
  if digest!=e['local_sha256'] or st.st_size!=e['bytes']:raise ValueError('Source SHA256/size mismatch '+p.name)
  found.append({'path':str(p),'file':p.name,'ordinal':ordinal,'sha256':digest,'bytes':st.st_size,'mtime_ns':st.st_mtime_ns})
 return found

def batches(source,chunk=32768):
 csv.field_size_limit(16<<20)
 with Path(source['path']).open(encoding='utf-8-sig',newline='') as f:
  reader=csv.reader(f,strict=True);header=next(reader)
  idx=[header.index(n) for n in FEATURES];it=header.index('ts');iy=header.index('label');ik=header.index('type')
  xb=[];ts=[];ys=[];types=[];ids=[];durs=[]
  for n,row in enumerate(reader):
   if len(row)!=len(header) or row[iy] not in ('0','1'):raise ValueError('Malformed source row')
   xb.append([row[j] for j in idx])
   try:ts.append(float(row[it]))
   except ValueError:ts.append(np.nan)
   ys.append(int(row[iy]));types.append(row[ik]);ids.append((source['ordinal']<<32)+n)
   try:durs.append(float(row[idx[0]]))
   except ValueError:durs.append(np.nan)
   if len(xb)==chunk:
    yield xb,np.asarray(ts),np.asarray(ys,np.uint8),np.asarray(types),np.asarray(ids,np.uint64),np.asarray(durs)
    xb=[];ts=[];ys=[];types=[];ids=[];durs=[]
  if xb:yield xb,np.asarray(ts),np.asarray(ys,np.uint8),np.asarray(types),np.asarray(ids,np.uint64),np.asarray(durs)

def prepare_data(sources,protocol,out,subset=False):
 db=sqlite3.connect(out/'test_vectors.sqlite');db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA cache_size=-65536');db.execute('PRAGMA temp_store=FILE')
 db.executescript('CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER) WITHOUT ROWID; CREATE TABLE groups(key BLOB,day TEXT,kind TEXT,label INTEGER,n INTEGER,PRIMARY KEY(key,day,kind,label)) WITHOUT ROWID; CREATE TABLE exposure(key BLOB PRIMARY KEY,mask INTEGER NOT NULL) WITHOUT ROWID;')
 samples={r:{} for r in ROLES if r!='common_test'};counts={r:Counter() for r in ROLES};bounds=effective_intervals(protocol);totals=Counter();last=time.monotonic()
 for source in sources:
  progress('scan_source',file=source['file']);filecounts=Counter();db.execute('BEGIN')
  for tokens,ts,y,types,ids,duration in batches(source):
   raw,valid,_,_=valid_numeric(tokens)
   filecounts['invalid_raw_contract']+=int((~valid).sum())
   flowvalid=np.isfinite(ts)&np.isfinite(duration)&(duration>=0)
   filecounts['invalid_flow_metadata_with_valid_raw']+=int((valid&~flowvalid).sum())
   valid&=flowvalid
   filecounts['source']+=len(y);filecounts['invalid']+=int((~valid).sum())
   raw,ts,y,types,ids,duration=(z[valid] for z in (raw,ts,y,types,ids,duration))
   roles=masks_for_intervals(ts,duration,bounds);assigned=np.zeros(len(y),bool)
   for role,mask in roles.items():
    assigned|=mask
    for c,k in set(zip(y[mask].tolist(),types[mask].tolist())):
     chosen=mask&(y==c)&(types==k);n=int(chosen.sum());counts[role][(c,k)]+=n
     if role=='common_test':continue
     cap=(CONFIG['cal_cap_per_label_type'] if 'cal' in role else (CONFIG['fit_cap_normal'] if c==0 else CONFIG['fit_cap_per_attack_type']))
     sampler=samples[role].setdefault((c,k),BottomK(cap));sampler.add(raw[chosen],ids[chosen])
    if role!='common_test':
     bit=1<<ROLES.index(role);unique_keys={r.tobytes() for r in raw[mask]}
     db.executemany('INSERT INTO exposure VALUES(?,?) ON CONFLICT(key) DO UPDATE SET mask=mask|excluded.mask',[(k,bit) for k in unique_keys])
   mask=roles['common_test'];vectors={};groups=Counter()
   for x,t,c,k in zip(raw[mask],ts[mask],y[mask],types[mask]):
    key=x.tobytes();v=vectors.setdefault(key,[0,0]);v[int(c)]+=1
    day=datetime.fromtimestamp(float(t),timezone.utc).date().isoformat();groups[(key,day,str(k),int(c))]+=1
   db.executemany('INSERT INTO vectors VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET n0=n0+excluded.n0,n1=n1+excluded.n1',[(k,*v) for k,v in vectors.items()])
   db.executemany('INSERT INTO groups VALUES(?,?,?,?,?) ON CONFLICT(key,day,kind,label) DO UPDATE SET n=n+excluded.n',[(key,day,kind,label,n) for (key,day,kind,label),n in groups.items()])
   start_inside_original=np.zeros(len(ts),bool);start_inside_effective=np.zeros(len(ts),bool)
   for role in ROLES:
    for lo,hi in protocol['intervals'][role]:start_inside_original|=(ts>=epoch(lo))&(ts<epoch(hi))
    for lo,hi in bounds[role]:start_inside_effective|=(ts>=lo)&(ts<hi)
   filecounts['outside_original_role_intervals']+=int((~start_inside_original).sum())
   filecounts['boundary_time_margin_excluded']+=int((start_inside_original&~start_inside_effective).sum())
   filecounts['flow_crossing_effective_end_excluded']+=int((start_inside_effective&~assigned).sum())
   filecounts['outside_roles_or_boundary_purged']+=int((~assigned).sum())
   if time.monotonic()-last>=20:progress('scan_progress',file=source['file'],rows=filecounts['source']);last=time.monotonic()
  db.commit();totals.update(filecounts)
  if (Path(source['path']).stat().st_size,Path(source['path']).stat().st_mtime_ns)!=(source['bytes'],source['mtime_ns']):raise ValueError('Source changed during scan')
  progress('scan_complete',file=source['file'],**filecounts)
 support={r:{'class_counts':[sum(n for (c,k),n in counts[r].items() if c==j) for j in (0,1)],'types':{str(k):int(n) for (c,k),n in sorted(counts[r].items())}} for r in ROLES}
 dump(out/'temporal_support_after_purge.json',{'roles':support,'source_totals':dict(totals),'effective_intervals_epoch':bounds,'flow_containment_only':True,'session_independence_established':False})
 if not subset:
  for role in ROLES:
   if min(support[role]['class_counts'])<1000:raise ValueError('Frozen support gate failed after purge: '+role+'; do not relax dates or gap')
 # Merge disjoint A fit and B added samples with matching deterministic priority;
 # population weights compensate stratified sampling and balance the two classes.
 merged={}
 for role in ('A_fit','B_fit_added'):
  for key,sampler in samples[role].items():
   target=merged.setdefault(key,BottomK(sampler.k));x,ids=sampler.arrays();target.add(x,ids)
 for key,t in merged.items():t.n=sum(samples[r][key].n for r in ('A_fit','B_fit_added') if key in samples[r])
 samples['B_fit']=merged
 manifests={};arrays={}
 for role,bytype in samples.items():
  xx=[];yy=[];ww=[];rr=[];rowmeta=[]
  cls=[sum(s.n for (c,k),s in bytype.items() if c==j) for j in (0,1)];total=sum(cls)
  for (c,k),s in sorted(bytype.items()):
   x,ids=s.arrays();xx.append(x);yy.extend([c]*len(x));rr.append(ids)
   w=s.n/len(x)*(total/(2*cls[c]) if 'fit' in role else 1.);ww.extend([w]*len(x))
   rowmeta.append({'label':c,'type':k,'population_rows':s.n,'sample_rows':len(x),'row_ids_sha256':hashlib.sha256(ids.tobytes()).hexdigest()})
  if not xx:continue
  x=np.concatenate(xx);y=np.asarray(yy,np.uint8);w=np.asarray(ww,np.float64);ids=np.concatenate(rr);order=np.argsort(ids)
  x,y,w,ids=x[order],y[order],w[order],ids[order]
  w=w/w.mean();arrays[role]=(x,y,w);np.savez_compressed(out/'samples'/f'{role}.npz',raw=x,labels=y,weights=w,row_ids=ids)
  manifests[role]={'strata':rowmeta,'rows':len(y),'file_sha256':sha(out/'samples'/f'{role}.npz')}
 dump(out/'sampling.json',manifests)
 db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.close()
 return arrays,support

def common_model(kind):return {'schema':'030_model_v1','kind':kind,'feature_count':8,'feature_names':FEATURES,'transform':'raw' if kind=='dt' else 'log1p_standardize','threshold':0.5}

def fit_scaler(raw,weights):
 x=np.log1p(raw).astype(np.float32).astype(np.float64)
 mean=np.average(x,axis=0,weights=weights);var=np.average((x-mean)**2,axis=0,weights=weights)
 scale=np.sqrt(var);scale[scale<1e-8]=1.
 return mean.astype(np.float32).tolist(),scale.astype(np.float32).tolist()

def fit_mlp(raw,y,weights,mean,scale,seed):
 rng=np.random.default_rng(seed);m=common_model('mlp_float');m.update(mean=mean,scale=scale)
 x=preprocess(m,raw);sizes=CONFIG['MLP']['shape'];ww=[(rng.normal(size=(a,b))*np.sqrt(2/a)).astype(np.float32) for a,b in zip(sizes[:-1],sizes[1:])];bb=[np.zeros(b,np.float32) for b in sizes[1:]]
 params=ww+bb;mom=[np.zeros_like(p) for p in params];vel=[np.zeros_like(p) for p in params];step=0;history=[]
 batch=CONFIG['MLP']['batch_size'];lr=CONFIG['MLP']['learning_rate'];l2=CONFIG['MLP']['l2']
 for ep in range(CONFIG['MLP']['epochs']):
  order=rng.permutation(len(y));loss=0.
  for start in range(0,len(y),batch):
   ids=order[start:start+batch];a0=x[ids];a1=np.maximum(a0@ww[0]+bb[0],0);a2=np.maximum(a1@ww[1]+bb[1],0);z=(a2@ww[2]+bb[2])[:,0];p=sigmoid(z);sw=weights[ids].astype(np.float32)
   loss+=float(np.sum(sw*(np.logaddexp(0,z)-y[ids]*z)))
   d3=((p-y[ids])*sw/len(ids))[:,None];d2=(d3@ww[2].T)*(a2>0);d1=(d2@ww[1].T)*(a1>0)
   grads=[a0.T@d1+l2*ww[0],a1.T@d2+l2*ww[1],a2.T@d3+l2*ww[2],d1.sum(0),d2.sum(0),d3.sum(0)]
   step+=1
   for j,(param,g) in enumerate(zip(params,grads)):
    mom[j]*=.9;mom[j]+=.1*g;vel[j]*=.999;vel[j]+=.001*g*g
    param-=lr*(mom[j]/(1-.9**step))/(np.sqrt(vel[j]/(1-.999**step))+1e-8)
  history.append(loss/len(y));progress('fit_mlp',epoch=ep+1,epochs=CONFIG['MLP']['epochs'],weighted_loss=history[-1])
 if not all(np.isfinite(p).all() for p in params):raise ValueError('MLP fitting produced nonfinite values')
 m['layers']=[{'weights':w.tolist(),'bias':b.tolist()} for w,b in zip(ww,bb)];m['fit_history_weighted_loss']=history;return m

def fit_models(arrays,out):
 from sklearn.linear_model import LogisticRegression
 from sklearn.tree import DecisionTreeClassifier
 models={};calibration={};fit_reports={}
 for vi,version in enumerate(('A','B')):
  raw,y,weights=arrays[version+'_fit'];cal,cy,cw=arrays[version+'_cal']
  # Scaler population weights undo only stratified sampling; class balancing
  # is an explicit model-training choice and also defines the scaler here.
  mean,scale=fit_scaler(raw,weights)
  lr=common_model('lr');lr.update(mean=mean,scale=scale)
  est=LogisticRegression(**CONFIG['LR'],random_state=SEED)
  with warnings.catch_warnings(record=True) as caught:
   warnings.simplefilter('always');est.fit(preprocess(lr,raw),y,sample_weight=weights)
  lr.update(weights=est.coef_[0].astype(np.float32).tolist(),bias=float(np.float32(est.intercept_[0])))
  fit_reports[version+'_lr']={'iterations':est.n_iter_.tolist(),'warnings':[str(w.message) for w in caught]}
  tree=DecisionTreeClassifier(**CONFIG['DT'],random_state=SEED);tree.fit(raw,y,sample_weight=weights);t=tree.tree_
  dt=common_model('dt');dt['nodes']=[]
  for j in range(t.node_count):
   values=t.value[j,0];prob=float(values[1]/values.sum());leaf=t.children_left[j]<0
   dt['nodes'].append({'feature':-1 if leaf else int(t.feature[j]),'threshold':0. if leaf else float(np.float32(t.threshold[j])),
    'left':-1 if leaf else int(t.children_left[j]),'right':-1 if leaf else int(t.children_right[j]),'probability':float(np.float32(prob))})
  mlp=fit_mlp(raw,y,weights,mean,scale,SEED)
  qi=quantize(mlp,raw)
  for family,m in [('lr',lr),('dt',dt),('mlp_float',mlp),('mlp_int8',qi)]:
   name=version+'_'+family;m['model_id']=name;m['training_version']=version
   calibration[name]=calibrate(m,cal,cy)
   calibration[name]['estimation_population']='deterministic calibration sample; all normal rows retained if <=100000 per type'
   models[name]=m;dump(out/'models'/f'{name}.json',m)
   progress('model_ready',model=name,calibration_FPR=calibration[name]['achieved_empirical_FPR'],calibration_recall=calibration[name]['attack_recall'])
 dump(out/'calibration.json',calibration);dump(out/'fit_reports.json',fit_reports)
 # Stale components are explicit deployment-error ablations, not claimed
 # representations of all model-only OTA tools or quality baselines.
 variants={};variant_status={}
 for family in ('lr','mlp_float','mlp_int8','dt'):
  a=models['A_'+family];b=models['B_'+family]
  stale=copy.deepcopy(b);stale['threshold']=a['threshold']
  if family=='mlp_int8':stale['q_threshold']=transfer_qthreshold(a,stale)
  variants[family+'_stale_threshold']=stale
  if family!='dt':
   stale=copy.deepcopy(b);stale['mean']=a['mean'];stale['scale']=a['scale'];variants[family+'_stale_scaler']=stale
   both=copy.deepcopy(stale);both['threshold']=a['threshold']
   if family=='mlp_int8':both['q_threshold']=transfer_qthreshold(a,both)
   variants[family+'_stale_scaler_threshold']=both
  if family=='mlp_int8':
   stale=copy.deepcopy(b);stale['input_scale']=a['input_scale'];variants['mlp_int8_stale_input_quantization']=stale
   stale=copy.deepcopy(b);stale['q_threshold']=a['q_threshold'];variants['mlp_int8_stale_integer_threshold_code']=stale
 variants['lr_compatible_probability']=compatible_lr(models['A_lr'],models['B_lr'])
 c=compatible_lr(models['A_lr'],models['B_lr'],True)
 if c is not None:variants['lr_compatible_decision']=c
 else:variant_status['lr_compatible_decision']={'status':'not_defined','reason':'A or B threshold is an endpoint; finite logit translation is undefined, not an accuracy-based omission'}
 cm=compatible_mlp(models['A_mlp_float'],models['B_mlp_float']);variants['mlp_float_compatible_first_layer']=cm
 cq=quantize(cm,arrays['B_fit'][0]);cq['q_threshold']=models['B_mlp_int8']['q_threshold'];cq['threshold']=models['B_mlp_int8']['threshold']
 # A fresh output scale changes the meaning of B's q threshold. Preserve the
 # B decision boundary in logit units, not its raw integer code.
 old=models['B_mlp_int8'];cq['q_threshold']=transfer_qthreshold(old,cq)
 variants['mlp_int8_compatible_requantized']=cq
 for name,m in variants.items():m['model_id']=name;dump(out/'models'/f'{name}.json',m)
 for name in variants:variant_status[name]={'status':'evaluated','role':'explicit component ablation or compatible export, never hyperparameter selection'}
 dump(out/'variant_status.json',variant_status)
 models.update(variants);return models

def mass_metrics(v):
 tn,fp,fn,tp,changed=map(float,v);n=tn+fp+fn+tp
 recall=tp/(tp+fn) if tp+fn else None;fpr=fp/(tn+fp) if tn+fp else None
 return {'confusion_mass':[[tn,fp],[fn,tp]],'recall':recall,'FPR':fpr,'balanced_accuracy':(recall+1-fpr)/2 if recall is not None and fpr is not None else None,'decision_disagreement':changed/n if n else None,'mass':n}

def family_of(name):
 for family in ('mlp_int8','mlp_float','lr','dt'):
  if family in name:return family
 raise ValueError('Unknown family')

def evaluate(models,support,out):
 db=sqlite3.connect(out/'test_vectors.sqlite');names=list(models);refs=np.array([names.index('B_'+family_of(n)) for n in names]);nm=len(names)
 top=db.execute('SELECT key FROM vectors ORDER BY n0+n1 DESC,key LIMIT 20').fetchall();topkeys={r[0] for r in top}
 cohorts=('all','top20','remainder','seen_fit_vector','unseen_fit_vector','seen_fit_or_cal_vector','unseen_fit_or_cal_vector','attack_type_seen_in_A_fit','attack_type_added_in_B_fit','attack_type_unseen_in_all_fit_calibration','normal_traffic')
 masses={c:{w:np.zeros((nm,5),np.float64) for w in ('rows','vector_balanced','frequency_cap100')} for c in cohorts}
 byday={};bytype={};maxdiff=np.zeros(nm);sumdiff=np.zeros(nm);nall=0
 knownA={k for k in support['A_fit']['types'] if k.lower() not in ('normal','benign')}
 knownB={k for role in ('A_fit','B_fit_added') for k in support[role]['types'] if k.lower() not in ('normal','benign')}
 exposed={k for role in ('A_fit','A_cal','B_fit_added','B_cal') for k in support[role]['types']}
 # Byte-sorted fixed vectors are chosen before predictions, not hardest cases.
 golden_rows=db.execute('SELECT key FROM vectors ORDER BY key LIMIT 258').fetchall()
 golden=np.asarray([np.frombuffer(r[0],'<f4') for r in golden_rows],np.float32)
 if not len(golden):raise ValueError('No future-test vectors')
 for name,m in models.items():
  p,y=predict(m,golden);dump(out/'hardware_vectors'/f'{name}.json',{'model_id':name,'data_origin':'TON_IoT_temporal_common_test','selection':'first258 unique raw float32 vectors by little-endian byte order, selected without predictions','raw':golden.tolist(),'probabilities':p.tolist(),'labels':y.tolist(),'model_sha256':sha(out/'models'/f'{name}.json')})
 cursor=db.execute('SELECT v.key,v.n0,v.n1,COALESCE(e.mask,0) FROM vectors v LEFT JOIN exposure e ON v.key=e.key ORDER BY v.key');done=0
 while True:
  rows=cursor.fetchmany(2048)
  if not rows:break
  keys=[r[0] for r in rows];raw=np.asarray([np.frombuffer(k,'<f4') for k in keys],np.float32)
  n0=np.array([r[1] for r in rows],np.float64);n1=np.array([r[2] for r in rows],np.float64);total=n0+n1
  pairs=[predict(models[n],raw) for n in names];probs=np.column_stack([p[0] for p in pairs]);pred=np.column_stack([p[1] for p in pairs]);changed=pred!=pred[:,refs]
  delta=np.abs(probs.astype(np.float64)-probs[:,refs]);maxdiff=np.maximum(maxdiff,delta.max(0));sumdiff+=(delta*total[:,None]).sum(0);nall+=int(total.sum())
  atom=np.stack((n0[:,None]*(pred==0),n0[:,None]*(pred==1),n1[:,None]*(pred==0),n1[:,None]*(pred==1),total[:,None]*changed),axis=2)
  topmask=np.array([k in topkeys for k in keys])
  exposure=np.array([r[3] for r in rows],np.uint8);seenfit=(exposure&5)!=0;seenany=exposure!=0
  for cohort,mask in [('all',np.ones(len(keys),bool)),('top20',topmask),('remainder',~topmask),('seen_fit_vector',seenfit),('unseen_fit_vector',~seenfit),('seen_fit_or_cal_vector',seenany),('unseen_fit_or_cal_vector',~seenany)]:
   for weight,mult in [('rows',np.ones(len(keys))),('vector_balanced',1/total),('frequency_cap100',np.minimum(total,100)/total)]:masses[cohort][weight]+=(atom[mask]*mult[mask,None,None]).sum(0)
  lookup={k:i for i,k in enumerate(keys)}
  # At most 2048 parameters; chunk at 500 for older Windows SQLite limits.
  for begin in range(0,len(keys),500):
   ks=keys[begin:begin+500];placeholders=','.join('?' for _ in ks)
   for key,day,kind,label,n in db.execute('SELECT key,day,kind,label,n FROM groups WHERE key IN ('+placeholders+')',ks):
    i=lookup[key];v=np.zeros((nm,5));v[:,label*2]=n*(pred[i]==0);v[:,label*2+1]=n*(pred[i]==1);v[:,4]=n*changed[i]
    byday.setdefault(day,np.zeros((nm,5)))[:]+=v;bytype.setdefault(kind,np.zeros((nm,5)))[:]+=v
    group='normal_traffic' if label==0 else ('attack_type_seen_in_A_fit' if kind in knownA else ('attack_type_added_in_B_fit' if kind in knownB else ('attack_type_unseen_in_all_fit_calibration' if kind not in exposed else None)))
    if group:
     for w,mult in [('rows',1.),('vector_balanced',1/total[i]),('frequency_cap100',min(total[i],100)/total[i])]:masses[group][w]+=v*mult
  done+=len(rows)
  if done%32768==0:progress('evaluate_future',unique_vectors=done)
 overall={c:{w:{n:mass_metrics(m[i]) for i,n in enumerate(names)} for w,m in weights.items()} for c,weights in masses.items()}
 for cohort,weightings in overall.items():
  for weighting,records in weightings.items():
   for i,n in enumerate(names):
    reference=records[names[refs[i]]]
    records[n]['paired_delta_vs_family_B']={k:records[n][k]-reference[k] if records[n][k] is not None and reference[k] is not None else None for k in ('recall','FPR','balanced_accuracy','decision_disagreement')}
 days={d:{n:mass_metrics(m[i]) for i,n in enumerate(names)} for d,m in byday.items()}
 types={d:{n:mass_metrics(m[i]) for i,n in enumerate(names)} for d,m in bytype.items()}
 sensitivity={d:{n:mass_metrics((masses['all']['rows']-m)[i]) for i,n in enumerate(names)} for d,m in byday.items()}
 uncertainty={'method':'descriptive leave-one-UTC-day-out; not confidence intervals','observed_days':len(byday),'CI_suppressed':True,'reason':'Fewer than eight observed UTC days; days are not established independent draws','leave_one_day_out':sensitivity}
 if len(byday)>=CONFIG['ci_minimum_days']:
  # Paired block bootstrap: same drawn days for every model. Interpretation
  # remains conditional on exchangeable days; temporal attacks violate iid rows.
  rng=np.random.default_rng(SEED);stack=np.stack(list(byday.values()));draw=rng.integers(0,len(stack),(CONFIG['bootstrap_repeats'],len(stack)))
  values={n:{k:[] for k in ('recall','FPR','balanced_accuracy')} for n in names}
  for selection in draw:
   block=stack[selection].sum(0);metrics=[mass_metrics(v) for v in block]
   for i,n in enumerate(names):
    for k in values[n]:
     a,b=metrics[i][k],metrics[refs[i]][k]
     if a is not None and b is not None:values[n][k].append(a-b)
  uncertainty={'method':'paired UTC-day block percentile bootstrap','observed_days':len(byday),'CI_suppressed':False,'draws':len(draw),'assumption':'exchangeable observed days; no claim of independent rows','paired_delta_vs_B_95CI':{n:{k:np.quantile(v,[.025,.975]).tolist() if v else None for k,v in ks.items()} for n,ks in values.items()},'leave_one_day_out':sensitivity}
 dump(out/'evaluation.json',{'model_names':names,'reference_by_model':{n:names[refs[i]] for i,n in enumerate(names)},'cohorts':overall,'frequency_weight_definition':'each vector gets total weight1 (cap100: min(n,100)); conflicting labels retain proportional shares, never majority relabeled; subgroup weights use full-test vector frequency','raw_vector_exposure_definition':'exact 8-feature float32 vectors in full eligible fit/calibration populations, including rows not sampled for fitting; primary test retains all repetitions','unique_vectors':done,'rows':nall,'probability_difference_vs_B':{n:{'max':float(maxdiff[i]),'row_weighted_mean':float(sumdiff[i]/nall)} for i,n in enumerate(names)}})
 dump(out/'by_day.json',days);dump(out/'by_attack_type.json',types);dump(out/'uncertainty.json',uncertainty)
 db.close();return {'test_rows':nall,'test_unique_vectors':done,'test_days':len(byday),'CI_suppressed':uncertainty['CI_suppressed'],'models_evaluated':len(names),'hardware_goldens_per_model':len(golden)}

def run(args):
 out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False)
 for d in ('samples','models','hardware_vectors'):(out/d).mkdir()
 protocolpath=Path(args.protocol).resolve();protocol=json.loads(protocolpath.read_text(encoding='utf-8'))
 import sklearn
 lock={'created_utc':now(),'config':CONFIG,'temporal_protocol':protocol,'protocol_sha256':sha(protocolpath),'python':sys.version,'platform':platform.platform(),'numpy':np.__version__,'sklearn':sklearn.__version__,'code_sha256':{p.name:sha(p) for p in (Path(__file__),ROOT/'model030.py',ROOT/'vendor/audit_ton_full.py')},'full_data_run':not args.subset_smoke}
 dump(out/'protocol_lock_before_data_and_predictions.json',lock)
 try:
  sources=find_sources(Path(args.root).resolve(),args.data_root,args.subset_smoke);dump(out/'sources.json',sources)
  arrays,support=prepare_data(sources,protocol,out,args.subset_smoke)
  if args.subset_smoke:
   result={'status':'complete_subset_data_smoke','hardware_access_attempted':False,'source_files':len(sources),'scientific_full_result':False,'models_trained':False}
  else:
   models=fit_models(arrays,out);result=evaluate(models,support,out)
   result.update(status='complete',hardware_access_attempted=False,source_files=len(sources),energy_measured=False,physical_power_loss_tested=False,measurement_origin='host_offline',study_status=CONFIG['study_status'])
  result['finished_utc']=now();dump(out/'summary.json',result)
  hashes={str(p.relative_to(out)).replace('\\','/'):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='result_manifest.json'}
  dump(out/'result_manifest.json',{'sha256':hashes,'summary':result});print(json.dumps(result),flush=True)
 except BaseException as exc:
  dump(out/'summary.json',{'status':'failed','error':str(exc),'finished_utc':now(),'hardware_access_attempted':False});raise

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);p.add_argument('--data-root');p.add_argument('--output',required=True)
 p.add_argument('--protocol',default=str(ROOT.parent/'protocol/coverage_selection.json'));p.add_argument('--subset-smoke',action='store_true',help='Developer validation only: never trains or reports full results')
 a=p.parse_args();run(a)
if __name__=='__main__':main()
