"""Numerical checks for the post-hoc host implementation, not detection tests."""
import copy,json,sys
from pathlib import Path
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parent))
import analyze_export034 as a

def test_scalar_and_channel_reduction():
 rng=np.random.default_rng(3401)
 # Equal max-absolute weight in every output channel: channel quantization
 # must reduce to the existing scalar quantizer exactly.
 m={'kind':'mlp_float','mean':[0.]*8,'scale':[1.]*8,'threshold':.5,'layers':[
  {'weights':[[.125*(-1 if (i+j)%2 else 1) for j in range(2)] for i in range(8)],'bias':[.02,-.02]},
  {'weights':[[.25,-.25],[-.25,.25]],'bias':[.02,-.02]},
  {'weights':[[.5],[-.5]],'bias':[.03]}]}
 fit=rng.uniform(0,10,(100,8)).astype(np.float32)
 scalar=a.ref.quantize(m,fit);scalar['q_threshold']=3
 channel=a.perchannel_quantize(m,fit,scalar);channel['q_threshold']=3
 x=rng.uniform(0,1000,(4096,8)).astype(np.float32)
 ps,ys,ss=a.predq(scalar,x);pc,yc,sc=a.predq(channel,x)
 assert np.array_equal(ss,sc) and np.array_equal(ys,yc) and np.array_equal(ps,pc)
 for l,c in zip(scalar['layers'],channel['layers']):
  assert l['weights']==c['weights'] and l['bias']==c['bias']
  assert all(k==l['multiplier'] for k in c['multiplier'])
  assert all(k==l['shift'] for k in c['shift'])

def test_rational_error_enclosure_and_recalibration():
 source=a.DEFAULT_SOURCE
 fm=a.jsonload(source/'models/mlp_float_compatible_first_layer.json');q=a.jsonload(source/'models/mlp_int8_compatible_requantized.json')
 rng=np.random.default_rng(3402)
 x=np.exp(rng.uniform(-20,30,(64,8))).astype(np.float32)
 x[0]=0;x[1]=np.finfo(np.float32).max/2
 _,_,scores=a.predq(q,x);sy=a.f(q['layers'][-1]['output_scale'])
 for row,score in zip(x,scores):
  centre,error=a.rational_bound(fm,q,row)
  assert abs(a.F(int(score))*sy-centre)<=error
 d=np.load(source/'samples/B_cal.npz');r=a.recalibrate(copy.deepcopy(q),d['raw'],d['labels']);_,p,s=a.predq(r,d['raw']);normal=s[d['labels']==0]
 assert p[d['labels']==0].sum()<=int(np.floor(.01*len(normal)))
 assert (normal>=r['q_threshold']-1).sum()>int(np.floor(.01*len(normal)))
 # The frozen artifact remains intact; calibration creates a distinct model.
 assert q['q_threshold']==10 and r['q_threshold']==22

if __name__=='__main__':
 test_scalar_and_channel_reduction();test_rational_error_enclosure_and_recalibration();print('PASS: channel-to-scalar reduction (4096 inputs), rational enclosure (64 broad-range inputs), calibration tie and immutability checks')
