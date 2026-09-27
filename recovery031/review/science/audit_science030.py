#!/usr/bin/env python3
"""Independent consistency/calibration audit of uploaded 030 evidence.
No source CSV/full SQLite access; no new training; no MCU access.
"""
import sys,json,hashlib,math,copy
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'research030/training'))
from model030 import predict,calibrate
P=ROOT/'review030/input/ids-completion-030/training'
O=Path(__file__).parent
checks=[]
def check(name,good,**detail):
 checks.append({'name':name,'passed':bool(good),**detail})
def load(f):return json.loads((P/f).read_text())
def close(a,b):return a is None and b is None or a is not None and b is not None and math.isclose(a,b,rel_tol=2e-11,abs_tol=1e-8)
e=load('evaluation.json');s=load('summary.json');sup=load('temporal_support_after_purge.json');sampling=load('sampling.json');cal=load('calibration.json');manifest=load('result_manifest.json')
missing=[]
for f,h in manifest['sha256'].items():
 if not(P/f).exists():missing.append(f);continue
 check('sha256:'+f,hashlib.sha256((P/f).read_bytes()).hexdigest()==h)
check('only_full_SQLite_missing',missing==['test_vectors.sqlite'],missing=missing)
def audit_metric(m,path):
 a=np.array(m['confusion_mass']);tn,fp,fn,tp=a.ravel();rec=tp/(tp+fn) if tp+fn else None;fpr=fp/(tn+fp) if tn+fp else None
 ba=(1-fpr+rec)/2 if fpr is not None and rec is not None else None
 for k,v in [('mass',a.sum()),('recall',rec),('FPR',fpr),('balanced_accuracy',ba)]:check(path+':'+k,close(m[k],v))
check('source_conservation',sup['source_totals']['source']==sum(sum(r['class_counts']) for r in sup['roles'].values())+sup['source_totals']['invalid']+sup['source_totals']['outside_roles_or_boundary_purged'])
for r,v in sup['roles'].items():check('support:'+r,min(v['class_counts'])>=1000)
for c,ws in e['cohorts'].items():
 for w,rs in ws.items():
  for n,m in rs.items():
   path=f'{c}:{w}:{n}';audit_metric(m,path)
   ref=rs[e['reference_by_model'][n]]
   for k,delta in m['paired_delta_vs_family_B'].items():check(path+':delta:'+k,close(delta,m[k]-ref[k] if m[k] is not None and ref[k] is not None else None))
for n in e['model_names']:
 for w in ('rows','vector_balanced','frequency_cap100'):
  allm=e['cohorts']['all'][w][n]
  for pair in [('top20','remainder'),('seen_fit_vector','unseen_fit_vector'),('seen_fit_or_cal_vector','unseen_fit_or_cal_vector')]:
   a,b=(e['cohorts'][c][w][n] for c in pair)
   check(f'partition:{pair}:{w}:{n}',np.allclose(np.array(a['confusion_mass'])+b['confusion_mass'],allm['confusion_mass'],rtol=2e-11,atol=1e-8))
for f in ['by_day.json','by_attack_type.json']:
 d=load(f)
 for g,rs in d.items():
  for n,m in rs.items():audit_metric(m,f+':'+g+':'+n)
 for n in e['model_names']:
  check(f'{f}:sum:{n}',np.allclose(sum(np.array(v[n]['confusion_mass']) for v in d.values()),e['cohorts']['all']['rows'][n]['confusion_mass']))
# Calibration samples and row identity disjointness.
arr={role:np.load(P/'samples'/f'{role}.npz') for role in sampling}
roles=['A_fit','A_cal','B_fit_added','B_cal']
ids={r:set(map(int,arr[r]['row_ids'])) for r in arr}
for i,a in enumerate(roles):
 for b in roles[i+1:]:check('row_ID_disjoint:'+a+':'+b,not(ids[a]&ids[b]))
check('B_fit_subset_of_A_plus_added',ids['B_fit']<=ids['A_fit']|ids['B_fit_added'])
check('B_fit_not_calibration',not(ids['B_fit']&(ids['A_cal']|ids['B_cal'])))
cal_audits={}
for name,c in cal.items():
 m=load('models/'+name+'.json');x=arr[name[0]+'_cal'];mm=copy.deepcopy(m)
 got=calibrate(mm,x['raw'],x['labels']);cal_audits[name]=got
 for k in ('threshold','q_threshold','achieved_empirical_FPR','attack_recall','probability_max'):
  check('calibration_recomputed:'+name+':'+k,close(c[k],got[k]),reported=c[k],recomputed=got[k])
 print('calibration checked',name,flush=True)
# Golden vectors recomputed independently from archived model files.
golden_results={}
for name in e['model_names']:
 m=load('models/'+name+'.json');g=load('hardware_vectors/'+name+'.json');p,y=predict(m,np.asarray(g['raw'],np.float32))
 err=float(np.max(np.abs(p.astype(float)-g['probabilities'])));mismatch=int(np.count_nonzero(y!=g['labels']));golden_results[name]={'rows':len(y),'label_mismatches':mismatch,'max_probability_abs_error':err}
 check('golden_recomputed:'+name,mismatch==0 and err<1e-5,**golden_results[name])
summary={'status':'passed' if all(c['passed'] for c in checks) else 'failed','checks':len(checks),'failures':[x for x in checks if not x['passed']],'source_files':23,'full_source_csv_recomputed':False,'full_test_inference_recomputed':False,'calibration_recomputed':True,'host_goldens_recomputed':True,'hardware_access_attempted':False,'missing_from_archive':missing,'training_summary':s,'models_reference_sha256':hashlib.sha256((ROOT/'research030/training/model030.py').read_bytes()).hexdigest(),'calibration_audit':cal_audits,'golden_audit':golden_results}
(O/'audit.json').write_text(json.dumps(summary,indent=2)+'\n');(O/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k not in ['calibration_audit','golden_audit','training_summary']},indent=2))
