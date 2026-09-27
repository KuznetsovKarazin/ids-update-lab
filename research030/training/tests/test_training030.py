import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import numpy as np

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import model030 as model
import run_training030 as run

class Tests(unittest.TestCase):
 def test_bottomk_chunk_invariance(self):
  x=np.arange(8000,dtype=np.float32).reshape(1000,8);ids=np.arange(1000,dtype=np.uint64)
  one=run.BottomK(27);one.add(x,ids);two=run.BottomK(27)
  for a in range(0,1000,13):two.add(x[a:a+13],ids[a:a+13])
  self.assertTrue(np.array_equal(one.arrays()[1],two.arrays()[1]));self.assertEqual(two.n,1000)
 def test_bottomk_merge_consistent(self):
  x=np.arange(8000,dtype=np.float32).reshape(1000,8);ids=np.arange(1000,dtype=np.uint64)
  whole=run.BottomK(31);whole.add(x,ids);parts=[]
  for lo,hi in [(0,333),(333,1000)]:
   s=run.BottomK(31);s.add(x[lo:hi],ids[lo:hi]);parts.append(s)
  merged=run.BottomK(31)
  for s in parts:merged.add(*s.arrays())
  self.assertTrue(np.array_equal(whole.arrays()[1],merged.arrays()[1]))
 def test_flow_spill_gap(self):
  t=np.array([100.,159.,160.,199.,200.]);d=np.array([0.,40.,0.,0.,0.])
  masks=run.masks_for_intervals(t,d,{'fit':[(100,200)],'cal':[(260,300)]})
  self.assertEqual(masks['fit'].tolist(),[True,True,True,True,False])
  masks=run.masks_for_intervals(np.array([159.]),np.array([41.]),{'fit':[(100,200)]})
  self.assertFalse(masks['fit'][0])
 def test_overlap_rejected(self):
  with self.assertRaises(ValueError):run.masks_for_intervals(np.array([5.]),np.array([0.]),{'a':[(0,10)],'b':[(0,10)]})
 def test_rounding(self):
  self.assertEqual(model.round_away(np.array([-1.5,-.5,.5,1.5])).tolist(),[-2.,-1.,1.,2.])
  self.assertEqual(model.round_shift_away(np.array([-3,-1,1,3]),1).tolist(),[-2,-1,1,2])
 def test_calibration_ties_and_saturation(self):
  m={'kind':'dt','threshold':.5,'nodes':[{'feature':-1,'probability':1.}]}
  x=np.zeros((200,8),np.float32);y=np.r_[np.zeros(100,np.uint8),np.ones(100,np.uint8)]
  report=model.calibrate(m,x,y);self.assertEqual(m['threshold'],1.);self.assertEqual(report['achieved_empirical_FPR'],0.)
  self.assertFalse(model.predict(m,x)[1].any())
 def test_strict_float_boundary(self):
  m={'kind':'dt','threshold':.5,'nodes':[{'feature':-1,'probability':.5}]}
  self.assertEqual(model.predict(m,np.zeros((1,8),np.float32))[1].tolist(),[0])
 def test_compatible_lr(self):
  a={'kind':'lr','mean':[0.]*8,'scale':[1.]*8,'weights':[.1]*8,'bias':-.5,'threshold':.5}
  b=copy.deepcopy(a);b.update(mean=[.3]*8,scale=[2.]*8,weights=[.4]*8,bias=-.1,threshold=.7)
  x=np.arange(80,dtype=np.float32).reshape(10,8)/10
  c=model.compatible_lr(a,b);p,y=model.predict(b,x);pc,yc=model.predict(c,x)
  np.testing.assert_allclose(p,pc,atol=1e-6);np.testing.assert_array_equal(y,yc)
  d=model.compatible_lr(a,b,True);np.testing.assert_array_equal(y,model.predict(d,x)[1])
  b['threshold']=1.;self.assertIsNone(model.compatible_lr(a,b,True))
 def test_compatible_mlp_float(self):
  rng=np.random.default_rng(2);m={'kind':'mlp_float','mean':[.3]*8,'scale':[2.]*8,'threshold':.5,'layers':[]}
  for a,b in ((8,16),(16,8),(8,1)):m['layers'].append({'weights':(rng.normal(size=(a,b))*.1).astype(np.float32).tolist(),'bias':np.zeros(b,np.float32).tolist()})
  a=copy.deepcopy(m);a['mean']=[-.2]*8;a['scale']=[1.1]*8
  x=rng.uniform(0,100,(100,8)).astype(np.float32);c=model.compatible_mlp(a,m)
  np.testing.assert_allclose(model.predict(m,x)[0],model.predict(c,x)[0],atol=1e-6)
 def test_int8_reference_independent_scalar(self):
  rng=np.random.default_rng(3);m={'kind':'mlp_float','mean':[.3]*8,'scale':[2.]*8,'threshold':.5,'layers':[]}
  for a,b in ((8,16),(16,8),(8,1)):m['layers'].append({'weights':(rng.normal(size=(a,b))*.2).astype(np.float32).tolist(),'bias':(rng.normal(size=b)*.1).astype(np.float32).tolist()})
  x=rng.uniform(0,100,(100,8)).astype(np.float32);q=model.quantize(m,x)
  actual=model.predict(q,x,True)[2]
  expected=[]
  for row in model.preprocess(q,x):
   v=[max(-127,min(127,int(np.sign(z)*np.floor(abs(float(z))+.5)))) for z in (row/np.float32(q['input_scale']))]
   for j,l in enumerate(q['layers']):
    vv=[]
    for o,bias in enumerate(l['bias']):
     acc=int(bias)+sum(v[i]*int(l['weights'][i][o]) for i in range(len(v)));prod=acc*l['multiplier'];value=(abs(prod)+(1<<(l['shift']-1)))>>l['shift']
     value=value if prod>=0 else -value;value=max(-127,min(127,value));vv.append(max(0,value) if j<2 else value)
    v=vv
   expected.append(v[0])
  np.testing.assert_array_equal(actual,expected)
 def test_frequency_conflicting_labels(self):
  # One vector with labels 0 x90, 1 x10, prediction attack retains both labels.
  m=run.mass_metrics(np.array([0.,.9,0.,.1,0.]));self.assertEqual(m['FPR'],1.);self.assertEqual(m['recall'],1.)
 def test_flow_effective_boundaries(self):
  p={'intervals':{r:[[f'2019-04-25T0{i}:00:00Z',f'2019-04-25T0{i+1}:00:00Z']] for i,r in enumerate(run.ROLES)}}
  eff=run.effective_intervals(p)
  self.assertEqual(eff['A_fit'][0][0],run.epoch('2019-04-25T00:00:00Z'))
  self.assertEqual(eff['A_fit'][0][1],run.epoch('2019-04-25T01:00:00Z')-60)
  self.assertEqual(eff['common_test'][0][1],run.epoch('2019-04-25T05:00:00Z'))

if __name__=='__main__':unittest.main()
