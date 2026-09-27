#!/usr/bin/env python3
"""Generate small SYNTHETIC fitted models for developer-only integration validation.

Usage: python generate_synthetic_fixture030.py NEW_OUTPUT_DIRECTORY
Never scientific TON results; never permitted for hardware campaign.
"""
from pathlib import Path
import sys,json,sqlite3
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import run_training030 as r
root=Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=False)
for n in ('models','hardware_vectors'): (root/n).mkdir()
rng=np.random.default_rng(123);arrays={}
for version in ('A','B'):
 for role in ('fit','cal'):
  x=rng.lognormal(2,1,(1800 if role=='fit' else 500,8)).astype(np.float32)
  z=np.log1p(x);y=((z[:,0]+z[:,1]*z[:,2]>.0+np.median(z[:,0]+z[:,1]*z[:,2]))).astype(np.uint8)
  arrays[version+'_'+role]=(x,y,np.ones(len(y)))
models=r.fit_models(arrays,root)
db=sqlite3.connect(root/'test_vectors.sqlite');db.executescript('CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER) WITHOUT ROWID;CREATE TABLE exposure(key BLOB PRIMARY KEY,mask INTEGER);CREATE TABLE groups(key BLOB,day TEXT,kind TEXT,label INTEGER,n INTEGER,PRIMARY KEY(key,day,kind,label)) WITHOUT ROWID;')
for i,x in enumerate(arrays['B_cal'][0]):
 y=int(arrays['B_cal'][1][i]);key=x.tobytes();day='2019-04-'+str(26+i%4);kind='normal' if y==0 else ('ddos' if i%2 else 'password');counts=[0,0];counts[y]=i%17+1
 db.execute('INSERT INTO vectors VALUES(?,?,?)',(key,*counts));db.execute('INSERT INTO groups VALUES(?,?,?,?,?)',(key,day,kind,y,sum(counts)))
db.commit();db.close()
support={'A_fit':{'types':{'normal':1,'scanning':1}},'A_cal':{'types':{'normal':1}},'B_fit_added':{'types':{'normal':1,'ddos':1}},'B_cal':{'types':{'normal':1,'ddos':1}}}
result=r.evaluate(models,support,root);result['validation_only_synthetic']=True;result['scientific_full_result']=False
r.dump(root/'summary.json',result)
print(json.dumps(result))
