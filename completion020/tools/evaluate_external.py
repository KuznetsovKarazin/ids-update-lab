#!/usr/bin/env python3
"""Frozen-model external evaluation; never trains/selects thresholds or opens MCU."""
from __future__ import annotations
import argparse, csv, hashlib, json, platform, sys
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
from ids_update_lab import package as lr
from ids_update_lab import tree_package as dt
LR_IDS = ('A','B','stale_scale','stale_threshold','stale_both','compatible_probability','compatible_decision','restored_B')
METRICS = ('attack_recall','FPR','balanced_accuracy','decision_disagreement_vs_LR_B')

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for x in iter(lambda:f.read(1<<20),b''): h.update(x)
    return h.hexdigest()
def dump(path, x): Path(path).write_text(json.dumps(x,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def fingerprints(raw):
    x=np.array(raw,dtype='<f4',copy=True); x[x==0]=0 # signed zero has identical model meaning
    return np.array([hashlib.sha256(row.tobytes()).digest() for row in x],dtype='V32')
def read_csv(path,names,with_labels=True):
    raw=[]; labels=[]
    with Path(path).open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames or len(set(reader.fieldnames))!=len(reader.fieldnames): raise ValueError('Missing/duplicate CSV header')
        if not all(k in reader.fieldnames for k in names): raise ValueError('Missing required feature column')
        if with_labels and 'label' not in reader.fieldnames: raise ValueError('Missing label column')
        for i,row in enumerate(reader,2):
            try:
                with np.errstate(over='raise',invalid='raise'): values=np.array([float(row[n]) for n in names],dtype=np.float32)
                if not np.isfinite(values).all() or (values<0).any(): raise ValueError('nonfinite/negative')
                raw.append(values)
                if with_labels:
                    if row['label'] not in ('0','1'): raise ValueError('label must be exactly 0 or 1')
                    labels.append(int(row['label']))
            except (ValueError,TypeError,OverflowError,FloatingPointError) as e: raise ValueError(f'Invalid CSV row {i}: {e}') from e
    if not raw: raise ValueError('Empty CSV')
    return np.stack(raw),np.asarray(labels,dtype=np.int64)
def build_known(source,output):
    protocol=json.loads((ROOT/'external_protocol.json').read_text())
    if sha(source)!=protocol['known_source_sha256']: raise ValueError('Wrong known source CSV')
    raw,_=read_csv(source,protocol['feature_names'],False)
    keys=np.unique(fingerprints(raw))
    with Path(output).open('xb') as f: np.savez_compressed(f,fingerprints=keys,source_sha256=protocol['known_source_sha256'],source_rows=len(raw))
    return {'source_rows':len(raw),'unique_fingerprints':len(keys),'npz_sha256':sha(output)}
def metric(counts):
    tn,fp,fn,tp,changed=np.moveaxis(counts,-1,0)
    with np.errstate(divide='ignore',invalid='ignore'):
        recall=tp/(tp+fn); fpr=fp/(fp+tn)
        return np.stack((recall,fpr,(recall+1-fpr)/2,changed/(tn+fp+fn+tp)),axis=-1)
def bootstrap(predictions,labels,groups,base,replicates,seed):
    pos=labels[:,None]==1; neg=~pos
    row=np.stack((neg&(predictions==0),neg&(predictions==1),pos&(predictions==0),pos&(predictions==1),predictions!=predictions[:,[base]]),axis=-1).astype(np.int64)
    counts=row.sum(axis=0); point=metric(counts)
    n=int(groups.max())+1; grouped=np.zeros((n,predictions.shape[1],5),dtype=np.int64);np.add.at(grouped,groups,row)
    rng=np.random.default_rng(seed); draws=np.empty((replicates,predictions.shape[1],4))
    for k in range(replicates):
        mult=np.bincount(rng.integers(n,size=n),minlength=n);draws[k]=metric(np.tensordot(mult,grouped,axes=(0,0)))
    finite=np.isfinite(draws).all(axis=(1,2))
    if not finite.all():
        # No silent rejection/resampling of draws to make an interval look regular.
        return counts,point,None,None,int((~finite).sum())
    return counts,point,np.percentile(draws,[2.5,97.5],axis=0),np.percentile(draws-draws[:,[base],:],[2.5,97.5],axis=0),0

def load_models():
    ref=ROOT/'references/artifacts019'; con=json.loads((ref/'feature_contract.json').read_text()); key=lr.load_public(ref/'public.pem')
    models={name:lr.verify((ref/('release-'+name+'.sids')).read_bytes(),key,lr.contract_hash(con),8,2) for name in LR_IDS}
    predictors={name:lr.infer_many for name in models}
    tree=ROOT/'artifacts/dt';tc=json.loads((tree/'feature_contract.json').read_text())
    # Tree and LR contracts share raw feature names/units, while transform and ABI differ.
    if tc['feature_names']!=con['feature_names'] or tc['input_units']!=con['input_units']: raise ValueError('DT raw input contract differs')
    for phase in ('A','B'):
        name='DT_'+phase;models[name]=dt.verify((tree/('release-'+phase+'.sids')).read_bytes(),key,dt.contract_hash(tc),8,3);predictors[name]=dt.infer_many
    return models,predictors

def evaluate(source,provenance,output):
    protocol_path=ROOT/'external_protocol.json';p=json.loads(protocol_path.read_text()); prov=json.loads(Path(provenance).read_text(encoding='utf-8-sig'))
    digest=sha(source)
    if digest==p['known_source_sha256']: raise ValueError('Previously exposed source cannot be a new external dataset')
    required=('source_name','source_url_or_accession','collection_session','acquisition_date','feature_extraction_description','source_sha256')
    if any(not isinstance(prov.get(k),str) or not prov[k].strip() or 'FILL' in prov[k] for k in required): raise ValueError('Complete factual provenance before evaluation')
    if prov['source_sha256'].strip().lower()!=digest: raise ValueError('Source SHA-256 does not match provenance')
    if prov.get('feature_names')!=p['feature_names'] or prov.get('input_units')!=p['input_units']: raise ValueError('Feature names/order/units differ from frozen contract')
    if prov.get('label_semantics')!={'0':'normal','1':'attack'}: raise ValueError('Unknown label semantics')
    for flag in ('used_to_fit_any_model','used_to_select_threshold_or_protocol','same_collection_session_as_development'):
        if prov.get(flag) is not False: raise ValueError('External independence not declared: '+flag)
    if prov.get('feature_semantics_verified') is not True: raise ValueError('Raw feature semantics must be checked; column names alone are insufficient')
    known_path=ROOT/'artifacts/known_input_fingerprints.npz'
    expected=(ROOT/'artifacts/known_input_fingerprints.sha256').read_text().split()[0]
    if sha(known_path)!=expected: raise ValueError('Known-input fingerprints integrity failure')
    raw,labels=read_csv(source,p['feature_names']); fp=fingerprints(raw)
    with np.load(known_path,allow_pickle=False) as known:
        if str(known['source_sha256'])!=p['known_source_sha256']: raise ValueError('Fingerprint source mismatch')
        overlap=np.isin(fp,known['fingerprints'])
    keep=~overlap; out=Path(output);out.mkdir(parents=True,exist_ok=False)
    # Freeze actual input/model/protocol bindings before inference. No excluded-row predictions.
    models,predictors=load_models(); names=list(models)
    bindings={'script_sha256':sha(__file__),'protocol_sha256':sha(protocol_path),'source_sha256':digest,'provenance_sha256':sha(provenance),'known_inputs_sha256':expected,'model_payload_sha256':{n:hashlib.sha256(m.payload()).hexdigest() for n,m in models.items()},'python':platform.python_version(),'numpy':np.__version__}
    dump(out/'input_bindings_before_predictions.json',bindings);dump(out/'provenance.json',prov);dump(out/'protocol.json',p)
    info={'status':'blocked','measurement_origin':'host_frozen_models','source_rows':len(raw),'excluded_exact_known_input_rows':int(overlap.sum()),'retained_rows':int(keep.sum()),'excluded_row_indices_zero_based':np.flatnonzero(overlap).tolist(),'retained_class_counts_0_1':np.bincount(labels[keep],minlength=2).tolist(),'new_source_independence':'author_declared_not_verified_by_exact_overlap_audit','test_set_used_for_tuning':False,'hardware_inference_measured':False}
    if not keep.any() or (np.bincount(labels[keep],minlength=2)==0).any():
        info['reason']='New-only subset must include both classes; do not change protocol after looking at labels';dump(out/'summary.json',info);return info
    raw=raw[keep];labels=labels[keep]
    group_column=prov.get('bootstrap_group_column')
    if group_column is not None:
        if not isinstance(group_column,str) or not group_column or group_column=='label' or group_column in p['feature_names']:raise ValueError('Invalid independent-group column')
        if not isinstance(prov.get('bootstrap_group_description'),str) or len(prov['bootstrap_group_description'].strip())<10:raise ValueError('Describe how independent groups were defined before evaluation')
        with Path(source).open(newline='',encoding='utf-8-sig') as f:
            reader=csv.DictReader(f)
            if group_column not in reader.fieldnames:raise ValueError('Missing declared bootstrap group column')
            group_values=[row[group_column] for row in reader]
        if any(not isinstance(v,str) or not v.strip() for v in group_values):raise ValueError('Empty group identifier')
        _,groups=np.unique(np.asarray(group_values)[keep],return_inverse=True)
        group_kind='declared_'+group_column
    else:
        _,groups=np.unique(fp[keep],return_inverse=True);group_kind='exact_float32_input_descriptive_only'
    info['bootstrap_grouping']=group_kind
    info['bootstrap_independence']='author_declared_unverified' if group_column else 'not_established_by_exact_input_groups'
    pairs=[predictors[n](models[n],raw) for n in names]; probs=np.stack([v[0] for v in pairs],axis=1);pred=np.stack([v[1] for v in pairs],axis=1)
    counts,point,ci,dci,undefined=bootstrap(pred,labels,groups,names.index('B'),p['bootstrap_replicates'],p['bootstrap_seed'])
    result={}
    for i,name in enumerate(names):
        tn,fp_,fn,tp,chg=map(int,counts[i]);result[name]={'confusion_matrix_0_1':[[tn,fp_],[fn,tp]],'threshold':models[name].threshold,'decision_disagreement_count_vs_LR_B':chg,'metrics':dict(zip(METRICS,map(float,point[i]))),'cluster_percentile95':None if ci is None else {k:ci[:,i,j].tolist() for j,k in enumerate(METRICS)},'paired_delta_vs_LR_B_percentile95':None if dci is None else {k:dci[:,i,j].tolist() for j,k in enumerate(METRICS)}}
    info.update(status='complete',unique_exact_input_vectors=int(len(np.unique(fp[keep]))),bootstrap_clusters=int(groups.max())+1,undefined_bootstrap_draws=undefined,models=result,limitations=['Exact-vector exclusion does not establish session/device/time independence.','Intervals condition on the stated grouping and frozen models. Exact-vector fallback does not account for session/device/time dependence; declared group independence still requires provenance.','DT export thresholds are float32; results evaluate the exported model.','No new threshold/model choice is permitted using these results.'])
    np.savez_compressed(out/'predictions.npz',source_row_indices=np.flatnonzero(keep),labels=labels,probabilities=probs,predictions=pred,model_ids=np.asarray(names),input_cluster=groups)
    dump(out/'summary.json',info);return info

def main():
    a=argparse.ArgumentParser(description=__doc__);s=a.add_subparsers(dest='command',required=True)
    b=s.add_parser('build-known');b.add_argument('--csv',type=Path,required=True);b.add_argument('--output',type=Path,required=True)
    b=s.add_parser('evaluate');b.add_argument('--csv',type=Path,required=True);b.add_argument('--provenance',type=Path,required=True);b.add_argument('--output',type=Path,required=True)
    args=a.parse_args()
    try:
        result=build_known(args.csv,args.output) if args.command=='build-known' else evaluate(args.csv,args.provenance,args.output)
        print(json.dumps({k:v for k,v in result.items() if k not in ('models','excluded_row_indices_zero_based')},ensure_ascii=False));return 0 if result.get('status','complete')=='complete' else 2
    except (ValueError,OSError,KeyError) as e: print('error: '+str(e),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
