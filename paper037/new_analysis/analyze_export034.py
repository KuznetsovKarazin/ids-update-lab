#!/usr/bin/env python3
"""Reproduce fixed post-hoc export diagnostics without modifying frozen inputs."""
from __future__ import annotations
import argparse,copy,csv,hashlib,json,math,sys
from pathlib import Path
from fractions import Fraction as F
import numpy as np
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE/'vendor'))
DEFAULT_SOURCE=HERE.parent/'evidence_inputs/training'
import model030 as ref

def jsonload(p):return json.loads(p.read_text())
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def perchannel_quantize(m,raw,activation_grids):
 q=copy.deepcopy(m);q['kind']='mlp_int8_per_channel';q['q_threshold']=0
 x=ref.preprocess(m,raw);sx=np.float32(max(float(np.max(np.abs(x)))/127,1e-8));sx=np.float32(activation_grids['input_scale']);q['input_scale']=float(sx);layers=[]
 for j,layer in enumerate(m['layers']):
  w=np.asarray(layer['weights'],np.float32);b=np.asarray(layer['bias'],np.float32)
  sw=np.maximum(np.max(np.abs(w),axis=0)/np.float32(127),np.float32(1e-8)).astype(np.float32)
  y=ref.dense(x,w,b)
  if j<2:y=np.maximum(y,np.float32(0))
  sy=np.float32(activation_grids['layers'][j]['output_scale'])
  qw=np.clip(ref.round_away(w/sw),-127,127).astype(np.int64);qb=ref.round_away(b/np.asarray(sx*sw,np.float32)).astype(np.int64)
  if (np.abs(qb)+127*np.abs(qw).sum(axis=0)>2147483647).any():raise ValueError('int32 bound')
  mult=[];sh=[]
  for s in sw:
   mant,exponent=math.frexp(float(sx)*float(s)/float(sy));mul=int(ref.round_away(mant*(1<<31)))
   if mul==(1<<31):mul>>=1;exponent+=1
   shift=31-exponent
   if not 1<=shift<=62:raise ValueError('shift bound')
   mult.append(mul);sh.append(shift)
  layers.append({'weights':qw.tolist(),'bias':qb.tolist(),'weight_scale':sw.tolist(),'output_scale':float(sy),'multiplier':mult,'shift':sh})
  x=y;sx=sy
 q['layers']=layers;q['host_only']=True;q['quantization']='symmetric per-output-channel weights; scalar layer activations; ties away; Q31'
 return q

def predq(m,raw):
 if m['kind']=='mlp_int8':return ref.predict(m,raw,True)
 proxy=dict(m,kind='mlp_float');x=ref.preprocess(proxy,raw)
 q=np.clip(ref.round_away(np.asarray(x/np.float32(m['input_scale']),np.float32)),-127,127).astype(np.int64)
 for j,l in enumerate(m['layers']):
  acc=q@np.asarray(l['weights'],np.int64)+np.asarray(l['bias'],np.int64)
  if np.max(np.abs(acc),initial=0)>2147483647:raise ValueError('int32 overflow')
  q=np.column_stack([np.clip(ref.round_shift_away(acc[:,k]*mul,shift),-127,127) for k,(mul,shift) in enumerate(zip(l['multiplier'],l['shift']))])
  if j<2:q=np.maximum(q,0)
 scores=q[:,0];return ref.sigmoid(np.asarray(scores,np.float32)*np.float32(m['layers'][-1]['output_scale'])),(scores>=m['q_threshold']).astype(np.uint8),scores

def recalibrate(q,raw,y):
 _,_,score=predq(q,raw);normal=score[y==0];allowed=int(math.floor(.01*len(normal)));q['q_threshold']=int(np.sort(normal)[len(normal)-allowed-1])+1
 q['threshold']=float(ref.sigmoid(np.array([q['q_threshold']*q['layers'][-1]['output_scale']],np.float32))[0]);return q

def f(v):return F(float(v))
def rational_bound(float_model,quant_model,raw):
 """Exact rational forward ideal centre and conservative dequantized error.

 Reference weights/biases are exact dyadic values stored in JSON. Preprocessing
 is frozen host float32. The target is the integer graph fed by its computed
 host input codes. At each layer: coefficient/bias error + Q31 approximation +
 half-grid rounding; clipping and ReLU are non-expansive. No empirical target
 output differences enter the error bound.
 """
 assert float_model['mean']==quant_model['mean'] and float_model['scale']==quant_model['scale'], 'Bound requires identical preprocessing parameters'
 z=ref.preprocess(float_model,np.asarray(raw,np.float32)[None,:])[0]
 initial_q=np.clip(ref.round_away(np.asarray(z/np.float32(quant_model['input_scale']),np.float32)),-127,127).astype(int)
 sx=f(quant_model['input_scale']);centres=[f(x) for x in z];errors=[abs(F(int(a))*sx-b) for a,b in zip(initial_q,centres)]
 for j,(l,ql) in enumerate(zip(float_model['layers'],quant_model['layers'])):
  w=[[f(v) for v in row] for row in l['weights']];b=[f(v) for v in l['bias']]
  sw=f(ql['weight_scale']);sy=f(ql['output_scale']);qw=ql['weights'];qb=ql['bias'];ratio=F(int(ql['multiplier']),1<<int(ql['shift']))
  out=[];err=[]
  for k in range(len(b)):
   t=b[k]+sum(centres[i]*w[i][k] for i in range(len(centres)))
   e=abs(F(qb[k])*sx*sw-b[k])
   e+=sum(abs(w[i][k])*errors[i]+abs(F(qw[i][k])*sw-w[i][k])*(abs(centres[i])+errors[i]) for i in range(len(centres)))
   # q itself is clipped; magnitude is bounded by 127 and the centre+radius.
   qmax=[min(127,math.floor((abs(c)+a)/sx)) for c,a in zip(centres,errors)]
   accmax=abs(qb[k])+sum(qmax[i]*abs(qw[i][k]) for i in range(len(qmax)))
   e+=abs(sy*ratio-sx*sw)*accmax+sy/2
   low=F(0) if j<2 else -127*sy;high=127*sy
   # Applying the same clip to the reference contracts the radius. Its
   # discrepancy from the unclipped ideal output is explicit.
   ideal=max(F(0),t) if j<2 else t
   clipped=min(high,max(low,ideal));e+=abs(clipped-ideal)
   out.append(ideal);err.append(e)
  centres,errors=out,err;sx=sy
 return centres[0],errors[0]

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,default=DEFAULT_SOURCE);a=ap.parse_args();s=a.source
 fit=np.load(s/'samples/B_fit.npz');cal=np.load(s/'samples/B_cal.npz');raw=cal['raw'];y=cal['labels'];gold=jsonload(s/'hardware_vectors/B_mlp_int8.json');gx=np.asarray(gold['raw'],np.float32)
 models={n:jsonload(s/'models'/f'{n}.json') for n in ['B_mlp_int8','B_mlp_float','mlp_float_compatible_first_layer','mlp_int8_compatible_requantized']}
 b=models['B_mlp_int8'];cm=models['mlp_float_compatible_first_layer'];existing=models['mlp_int8_compatible_requantized'];check=ref.quantize(cm,fit['raw'])
 reproduction={'input_scale_recomputed':check['input_scale'],'input_scale_frozen':existing['input_scale'],'weights_biases_match':all(check['layers'][j][k]==existing['layers'][j][k] for j in range(3) for k in ['weights','bias'])};assert reproduction['weights_biases_match']
 pc=perchannel_quantize(cm,fit['raw'],existing);pc['q_threshold']=ref.transfer_qthreshold(b,pc);pc['threshold']=b['threshold']
 variants={'B_original':copy.deepcopy(b),'export_per_tensor_transferred':copy.deepcopy(existing),'export_per_tensor_recalibrated':recalibrate(copy.deepcopy(existing),raw,y),'export_per_channel_transferred':pc,'export_per_channel_recalibrated':recalibrate(copy.deepcopy(pc),raw,y)}
 _,basegold,_=predq(b,gx);_,basecal,_=predq(b,raw);rows=[]
 for name,m in variants.items():
  _,p,score=predq(m,raw);_,pg,sg=predq(m,gx);n=int((y==0).sum());atk=int((y==1).sum());fp=int(p[y==0].sum());tp=int(p[y==1].sum())
  rows.append({'variant':name,'q_threshold':m['q_threshold'],'normal_n':n,'attack_n':atk,'false_positives':fp,'true_positives':tp,'calibration_FPR':fp/n,'calibration_recall':tp/atk,'calibration_changed_vs_B':int((p!=basecal).sum()),'check_vector_n':len(gx),'check_changed_vs_B':int((pg!=basegold).sum()),'check_q_min':int(sg.min()),'check_q_max':int(sg.max())})
  (HERE/f'{name}.json').write_text(json.dumps(m,indent=2)+'\n')
 cert=[];_,targetpred,targetcode=predq(existing,gx);qt=int(existing['q_threshold']);sy=f(existing['layers'][-1]['output_scale'])
 for index,x in enumerate(gx):
  centre,error=rational_bound(cm,existing,x)
  lower=max(-127,math.ceil((centre-error)/sy));upper=min(127,math.floor((centre+error)/sy));actual=int(targetcode[index])
  assert lower<=actual<=upper,(index,lower,actual,upper)
  certified=(lower>=qt) if basegold[index] else (upper<qt)
  assert not certified or basegold[index]==targetpred[index]
  cert.append({'index':index,'B_decision':int(basegold[index]),'export_decision':int(targetpred[index]),'exact_ideal_logit':float(centre),'rigorous_error_bound':float(error),'code_lower':lower,'code_upper':upper,'export_code':actual,'certified_agreement':bool(certified)})
 out={'analysis':'posthoc_host_only_fixed_protocol','source_root':str(s),'full_test_evaluated':False,'range_reproduction':reproduction,'per_channel_activation_grid':'frozen 030 input and output grids retained; only weight scales per output channel change','calibration_estimand':'resubstitution diagnostics on threshold-selection data; no independent generalization estimate','check_vector_selection':gold['selection'],'rows':rows,'certificate':{'scope':'exact rational error bound around real-arithmetic converted network; host-frozen float32 preprocessing and integer reference graph; 258 check inputs only','certified':sum(v['certified_agreement'] for v in cert),'inputs':len(cert),'all_bounds_validated':True,'method':'layerwise weight/bias/input/Q31/rounding/clipping error propagation','floating_vs_hardware_scope':'This does not certify MCU libm preprocessing or unspecified input neighborhoods'},'hashes':{str(p.relative_to(s)):digest(p) for p in [s/'samples/B_fit.npz',s/'samples/B_cal.npz',s/'hardware_vectors/B_mlp_int8.json',*[s/'models'/f'{n}.json' for n in models]]}}
 (HERE/'export_diagnostics034.json').write_text(json.dumps(out,indent=2)+'\n')
 for file,records in [('export_diagnostics034.csv',rows),('pointwise_certificate034.csv',cert)]:
  with (HERE/file).open('w',newline='') as h:w=csv.DictWriter(h,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
 print(json.dumps(out,indent=2))
if __name__=='__main__':main()
