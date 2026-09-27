"""Independent consistency checks of uploaded stage 028 aggregates.

Does not reproduce all raw CSV predictions: only first-source CSV is local.
Run from project root: python review028_actual/audit028.py.
"""
from pathlib import Path
import csv, hashlib, importlib.util, json, math
from collections import Counter
import numpy as np

BASE = Path(__file__).resolve().parents[1]
R = BASE / 'review028_actual/input/ton-diagnostics-028'
checks = []
def read(p): return json.loads(Path(p).read_text(encoding='utf-8'))
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(x, name):
    if not x: raise AssertionError(name)
    checks.append(name)
def near(a, b): return math.isclose(float(a), float(b), rel_tol=1e-11, abs_tol=1e-7)

def main():
    man=read(R/'evidence_manifest.json')
    for p,h in man['sha256'].items(): require(sha(R/p)==h,'evidence:'+p)
    lock=read(R/'protocol_lock_before_predictions.json')
    kit=BASE/'research028'
    require(sha(kit/'KIT_MANIFEST.json')==lock['kit_manifest_sha256'],'kit manifest pinned')
    for p,h in read(kit/'KIT_MANIFEST.json')['sha256'].items():
        require(sha(kit/p)==h,'kit:'+p)
    prior=read(BASE/'review023/input/ton-frozen-eval-023/provenance.json')
    src={x['file']:x['sha256'] for x in lock['sources']}
    require(src==prior['source_sha256'],'all 23 sources match stage023 hashes')
    require(len(src)==23,'23 distinct source files')
    d=read(R/'diagnostics.json'); summary=read(R/'summary.json'); per=read(R/'per_file.json')
    require(summary['status']=='complete','reported complete')
    require(not any(summary[k] for k in ('training_performed','threshold_selection_performed','hardware_accessed')),'scope diagnostic only')
    for a,b in [('rows','source_rows'),('valid_rows','valid_rows'),('invalid_rows','invalid_rows')]:
        require(sum(x[a] for x in per)==summary[b], 'per file sum '+a)
    require({x['file']:x['sha256'] for x in per}==src,'per file source binding')
    stages=read(BASE/'review023/input/ton-frozen-eval-023/summary.json')['rows_by_stage']
    for cohort,stage in [('all_valid','valid_raw_contract'),('known_vectors','known_input_overlap'),('retained_vectors','candidate_unseen_input')]:
        count=d['cohorts'][cohort]['counts']; prev=stages[stage]
        require(count['rows']==prev['rows'],'prior rows '+cohort)
        require([count['normal_rows'],count['attack_rows']]==[prev['label_counts']['0'],prev['label_counts']['1']],'prior class counts '+cohort)
    for cohort,c in d['cohorts'].items():
        for weight,models in c['weighted_metrics'].items():
            for name,m in models.items():
                (tn,fp),(fn,tp)=m['confusion_mass_truth_pred_0_1']; total=tn+fp+fn+tp
                require(all(near(a,b) for a,b in [(m['total_mass'],total),(m['recall'],tp/(tp+fn)),(m['FPR'],fp/(tn+fp)),(m['balanced_accuracy'],(tp/(tp+fn)+tn/(tn+fp))/2),(m['accuracy'],(tn+tp)/total)]),'metric arithmetic '+cohort+'/'+weight+'/'+name)
                if weight=='rows':
                    require(near(tn+fp,c['counts']['normal_rows']) and near(fn+tp,c['counts']['attack_rows']),'class denominators '+cohort+'/'+name)
                if weight=='vector_balanced':require(near(total,c['counts']['vectors']),'vector mass '+cohort+'/'+name)
            trans=np.array(c['DT_A_B_transition_mass_truth_A_B'][weight])
            for model,axis in [('DT_A',2),('DT_B',1)]:
                require(np.allclose(trans.sum(axis=axis),models[model]['confusion_mass_truth_pred_0_1'],rtol=1e-11,atol=1e-7),'transition marginals '+cohort+'/'+weight+'/'+model)
            off=trans[:,0,1].sum()+trans[:,1,0].sum()
            require(near(off/models['DT_A']['total_mass'],models['DT_A']['decision_disagreement_vs_family_B']),'transition disagreement '+cohort+'/'+weight)
            for model in ('compatible_probability','compatible_decision','restored_B'):
                require(models[model]['confusion_mass_truth_pred_0_1']==models['B']['confusion_mass_truth_pred_0_1'] and models[model]['decision_disagreement_vs_family_B']==0,'LR compatible label agreement '+cohort+'/'+weight+'/'+model)
    old=read(BASE/'review023/input/ton-frozen-eval-023/metrics.json')
    for name,m in old.items():
        got=d['cohorts']['retained_vectors']['weighted_metrics']['rows'][name]
        require(got['confusion_mass_truth_pred_0_1']==m['confusion_matrix_0_1'],'stage023 exact confusion '+name)
        require(near(got['decision_disagreement_vs_family_B'],m['metrics']['decision_disagreement']),'stage023 exact disagreement '+name)
    hourly=Counter()
    with (R/'hourly_counts.csv').open(newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):hourly[(row['stage'],row['label'],row['type'])]+=int(row['rows'])
    for stage in ('all_source','valid_raw_contract'):
        expected=stages[stage]
        for typ,n in expected['type_counts'].items():require(sum(v for (s,l,t),v in hourly.items() if s==stage and t==typ)==n,'hourly type '+stage+'/'+typ)
    spec=importlib.util.spec_from_file_location('audit028_frozen_loader',kit/'tools/diagnose_ton028.py'); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    _,_,models,predictors,binding=mod.load_runtime()
    require(binding==lock['models_and_known_inputs'],'frozen models and known source bindings')
    records=d['top20_frequency']+d['top20_DT_A_B_changed_frequency']+d['requested_probe_vectors']
    unique={x['sha256_float32']:x for x in records}
    for h,x in unique.items():
        raw=np.array(x['vector'],dtype='<f4').reshape(1,-1)
        require(hashlib.sha256(raw.tobytes()).hexdigest()==h,'vector hash '+h)
        for name,p in x['predictions'].items():
            prob,pred=predictors[name](models[name],raw)
            require(int(pred[0])==p['label'] and abs(float(prob[0])-p['probability'])<=2e-6,'rescored vector '+h+'/'+name)
        meta=x['source_metadata']; n=x['normal_rows']+x['attack_rows']
        require(meta['rows']==n,'metadata rows '+h)
        for field,counts in meta['marginal_counts'].items():require(sum(counts.values())==n,'metadata marginals '+h+'/'+field)
        require(sum(v['rows'] for v in meta['joint_counts'])==n,'metadata joint '+h)
    allc=d['cohorts']['all_valid']['counts']; top3=d['requested_probe_vectors']
    out={'status':'pass','checks_passed':len(checks),'source_zip_sha256':sha(BASE/'upload/ton-diagnostics-028-results.zip'),
         'summary':summary,'cohort_counts':{k:v['counts'] for k,v in d['cohorts'].items()},
         'top3_rows':sum(x['normal_rows']+x['attack_rows'] for x in top3),
         'top3_share_DT_changed_rows':sum(x['normal_rows']+x['attack_rows'] for x in top3)/allc['changed_DT_A_B_rows'],
         'unique_top_metadata_vectors_rescored':len(unique),
         'metrics':{k:{w:{m:{kk:vv for kk,vv in x.items() if kk!='confusion_mass_truth_pred_0_1'} for m,x in vv.items()} for w,vv in v['weighted_metrics'].items()} for k,v in d['cohorts'].items()},
         'limitations':['No full 23-source raw re-execution: full files remain on user PC.','Raw SQLite aggregation cache intentionally absent from uploaded archive; its digest recorded only.','Checks establish aggregate consistency, exact repeated retained-cohort results and frozen top-vector predictions; they do not independently establish every raw-row prediction.'],
         'checks':checks}
    (BASE/'review028_actual/audit.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:out[k] for k in ('status','checks_passed','top3_rows','top3_share_DT_changed_rows','unique_top_metadata_vectors_rescored')}))
if __name__=='__main__':main()
