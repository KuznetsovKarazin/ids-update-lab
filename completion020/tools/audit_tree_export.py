#!/usr/bin/env python3
"""Compare frozen DT64 and exported DT32 on the pre-existing development rows.

Only the fixed validation row IDs are converted to inputs. No training, test
evaluation, model choice, or threshold selection is performed.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'))
import numpy as np
from ids_update_lab import package as lr
from ids_update_lab import tree_package as tree

SOURCE_SHA='26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974'

def original_predict(model,raw):
    result=[]
    for row in np.asarray(raw,dtype=np.float32):
        i=0
        for _ in range(model['node_count']):
            if model['children_left'][i]==-1:
                result.append(model['node_attack_probability_float64'][i]);break
            feature=model['feature'][i]
            i=model['children_left'][i] if float(row[feature])<=model['split_thresholds_float64'][i] else model['children_right'][i]
        else: raise ValueError('frozen source tree invalid')
    return np.asarray(result,dtype=np.float64)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source-csv',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    with args.source_csv.open('rb') as fh:
        h=hashlib.file_digest(fh,'sha256').hexdigest()
    if h!=SOURCE_SHA:raise ValueError('CSV differs from frozen source')
    args.output.mkdir(parents=True,exist_ok=False)
    frozen=ROOT/'references/frozen_development'
    with np.load(frozen/'development_indices.npz',allow_pickle=False) as data:
        ids=data['validation_source_row_id'].astype(np.int64)
    wanted=set(ids.tolist());rows={};labels={}
    contract=json.loads((ROOT/'artifacts/dt/feature_contract.json').read_text())
    with args.source_csv.open(encoding='utf-8-sig',newline='') as fh:
        for index,row in enumerate(csv.DictReader(fh)):
            if index in wanted:
                rows[index]=[float(row[k]) for k in contract['feature_names']];labels[index]=int(row['label'])
    if set(rows)!=wanted:raise ValueError('source validation IDs missing')
    raw=np.asarray([rows[int(i)] for i in ids],dtype=np.float32);y=np.asarray([labels[int(i)] for i in ids],dtype=np.int64)
    result={'status':'complete','measurement_origin':'host_reference_audit','data_origin':'TON_IoT_development',
        'source_csv_sha256':h,'validation_rows':len(ids),'independent_test':False,'training_performed':False,
        'threshold_selection_performed':False,'old_test_evaluated':False,'results':{}}
    pub=lr.load_public(ROOT/'artifacts/dt/public.pem')
    for phase in ('A','B'):
        original=json.loads((frozen/('DT5_raw_'+phase)/'model.json').read_text())
        model=tree.verify((ROOT/'artifacts/dt'/('release-'+phase+'.sids')).read_bytes(),pub)
        p_old=original_predict(original,raw);p_new,y_new=tree.infer_many(model,raw)
        y_old=(p_old>model.threshold).astype(np.int64)
        p_round=p_old.astype(np.float32)
        same=np.array_equal(p_round,p_new)
        if not same:raise ValueError('float32 tree differs from rounded original probabilities')
        recall=float(np.mean(y_new[y==1]));fpr=float(np.mean(y_new[y==0]));ba=(recall+1-fpr)/2
        result['results'][phase]={'node_count':len(model.nodes),'probabilities_exactly_equal_to_rounded_original':same,
            'max_probability_abs_error':float(np.max(abs(p_old-p_new.astype(np.float64)))),
            'label_mismatches':int(np.sum(y_old!=y_new)),'attack_recall':recall,'FPR':fpr,'balanced_accuracy':ba,
            'threshold':model.threshold,'branch_rounding':'largest_float32_not_greater_than_original_float64_split'}
    (args.output/'tree_export_audit.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result))
if __name__=='__main__':main()
