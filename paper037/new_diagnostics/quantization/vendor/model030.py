"""Version 030 portable numerical reference (float32 and integer MLP).

Floating point dot products deliberately accumulate in source-index order to
match the C runtime; BLAS order is used for fitting only. No pickle is loaded.
"""
import copy
import math
import numpy as np

FEATURES = ['duration','src_bytes','dst_bytes','missed_bytes','src_pkts','src_ip_bytes','dst_pkts','dst_ip_bytes']

def round_away(x):
    x=np.asarray(x,dtype=np.float64)
    return np.copysign(np.floor(np.abs(x)+0.5),x)

def round_shift_away(x,shift):
    if not 1<=int(shift)<=62: raise ValueError('shift out of range')
    x=np.asarray(x,dtype=np.int64)
    return np.sign(x)*((np.abs(x)+(1<<(int(shift)-1)))>>int(shift))

def sigmoid(x):
    # Each exponential has a nonpositive argument; no clipping is required.
    x=np.asarray(x,dtype=np.float32)
    if not np.isfinite(x).all():raise ValueError('Nonfinite inference logit')
    out=np.empty_like(x);positive=x>=0
    out[positive]=np.float32(1)/(np.float32(1)+np.exp(-x[positive]).astype(np.float32))
    e=np.exp(x[~positive]).astype(np.float32)
    out[~positive]=e/(np.float32(1)+e)
    return out

def preprocess(m,raw):
    x=np.asarray(raw,dtype=np.float32)
    if x.ndim!=2 or x.shape[1]!=8 or not np.isfinite(x).all() or (x<0).any():raise ValueError('Invalid raw features')
    if m['kind']=='dt':return x
    return (np.log1p(x).astype(np.float32)-np.asarray(m['mean'],np.float32))/np.asarray(m['scale'],np.float32)

def dense(x,w,b):
    w=np.asarray(w,np.float32);b=np.asarray(b,np.float32)
    y=np.broadcast_to(b,(len(x),len(b))).copy()
    for i in range(w.shape[0]):y=np.asarray(y+x[:,i,None]*w[i],dtype=np.float32)
    return y

def predict(m,raw,return_score=False):
    x=preprocess(m,raw);kind=m['kind']
    if kind=='lr':
        z=dense(x,np.asarray(m['weights'],np.float32)[:,None],[m['bias']])[:,0]
        p=sigmoid(z);score=p;pred=p>np.float32(m['threshold'])
    elif kind=='dt':
        nodes=m['nodes'];idx=np.zeros(len(x),np.int32)
        # Fixed tree depth is at most five; defensive limit catches malformed trees.
        for _ in range(64):
            active=np.array([nodes[int(j)]['feature']>=0 for j in idx])
            if not active.any():break
            for j in np.unique(idx[active]):
                n=nodes[int(j)];sel=np.flatnonzero(active&(idx==j))
                idx[sel]=np.where(x[sel,n['feature']]<=np.float32(n['threshold']),n['left'],n['right'])
        else:raise ValueError('Cyclic or excessive tree')
        p=np.array([nodes[int(j)]['probability'] for j in idx],np.float32);score=p;pred=p>np.float32(m['threshold'])
    elif kind=='mlp_float':
        for j,layer in enumerate(m['layers']):
            x=dense(x,layer['weights'],layer['bias'])
            if j<2:x=np.maximum(x,np.float32(0))
        p=sigmoid(x[:,0]);score=p;pred=p>np.float32(m['threshold'])
    elif kind=='mlp_int8':
        # The division itself is float32, matching the MCU.
        q=np.clip(round_away(np.asarray(x/np.float32(m['input_scale']),np.float32)),-127,127).astype(np.int64)
        for j,layer in enumerate(m['layers']):
            w=np.asarray(layer['weights'],np.int64);b=np.asarray(layer['bias'],np.int64)
            acc=q@w+b
            if np.max(np.abs(acc),initial=0)>2147483647:raise ValueError('int32 accumulator overflow')
            prod=acc*int(layer['multiplier'])
            q=np.clip(round_shift_away(prod,int(layer['shift'])),-127,127)
            if j<2:q=np.maximum(q,0)
        score=q[:,0];p=sigmoid(np.asarray(score,np.float32)*np.float32(m['layers'][-1]['output_scale']))
        pred=score>=int(m['q_threshold'])
    else:raise ValueError('Unknown model kind: '+kind)
    return (p,pred.astype(np.uint8),score) if return_score else (p,pred.astype(np.uint8))

def calibrate(m,raw,labels,target_fpr=.01):
    """Most permissive threshold with empirical normal FPR <= target.

    Ties are kept together. The rule uses only normal calibration scores;
    attacks are reported but do not choose the operating point.
    """
    _,_,scores=predict(m,raw,True);normal=scores[np.asarray(labels)==0]
    if not len(normal):raise ValueError('Calibration has no normal examples')
    allowed=int(math.floor(target_fpr*len(normal)))
    ordered=np.sort(normal)
    boundary=ordered[len(normal)-allowed-1]
    if m['kind']=='mlp_int8':
        m['q_threshold']=int(boundary)+1
        m['threshold']=float(sigmoid(np.array([m['q_threshold']*m['layers'][-1]['output_scale']],np.float32))[0])
    else:m['threshold']=float(np.float32(boundary))
    p,y=predict(m,raw)
    fpr=float(np.mean(y[np.asarray(labels)==0]))
    if fpr>target_fpr+1e-15:raise AssertionError('FPR calibration rule violated')
    return {'normal_rows':len(normal),'attack_rows':int(np.sum(np.asarray(labels)==1)),
            'target_empirical_FPR':target_fpr,'achieved_empirical_FPR':fpr,
            'attack_recall':float(np.mean(y[np.asarray(labels)==1])) if np.any(np.asarray(labels)==1) else None,
            'threshold':m.get('threshold'),'q_threshold':m.get('q_threshold'),
            'rule':'strictly above order statistic; ties excluded; no test tuning',
            'all_predictions_normal_on_calibration':bool(not y.any()),'probability_max':float(p.max())}

def quantize(m,training_raw):
    """Post-training quantization ranges are derived from fitting rows only."""
    q=copy.deepcopy(m);q['kind']='mlp_int8';q['q_threshold']=0
    x=preprocess(m,training_raw)
    sx=np.float32(max(float(np.max(np.abs(x),initial=0))/127.,1e-8));q['input_scale']=float(sx)
    layers=[]
    for j,layer in enumerate(m['layers']):
        w=np.asarray(layer['weights'],np.float32);b=np.asarray(layer['bias'],np.float32)
        sw=np.float32(max(float(np.max(np.abs(w),initial=0))/127.,1e-8))
        y=dense(x,w,b)
        if j<2:y=np.maximum(y,np.float32(0))
        sy=np.float32(max(float(np.max(np.abs(y),initial=0))/127.,1e-8))
        qw=np.clip(round_away(w/sw),-127,127).astype(np.int64)
        qb=round_away(b/np.float32(sx*sw)).astype(np.int64)
        if (np.abs(qb)+127*np.abs(qw).sum(axis=0)>2147483647).any():raise ValueError('Quantized accumulator bound exceeds int32')
        ratio=float(sx)*float(sw)/float(sy);mantissa,exponent=math.frexp(ratio)
        multiplier=int(round_away(mantissa*(1<<31)))
        if multiplier==(1<<31):multiplier>>=1;exponent+=1
        shift=31-exponent
        if not 1<=shift<=62:raise ValueError('Unsupported quantized scale ratio')
        layers.append({'weights':qw.tolist(),'bias':qb.tolist(),'multiplier':multiplier,'shift':shift,
                       'weight_scale':float(sw),'output_scale':float(sy)})
        x=y;sx=sy
    q['layers']=layers
    q['quantization']={'weights':'symmetric int8','activation':'symmetric int8, hidden ReLU',
        'range_source':'fitting sample only, maximum absolute activation','rounding':'nearest ties away from zero',
        'accumulator':'int32 bounded; requantization int64 positive Q31 multiplier/right shift',
        'output':'int8 logit; q_threshold may be 128, representing always normal'}
    return q

def compatible_lr(a,b,decision=False):
    m=copy.deepcopy(b);wa=np.asarray(b['weights'],np.float64)
    m['weights']=(wa*np.asarray(a['scale'])/np.asarray(b['scale'])).astype(np.float32).tolist()
    bias=float(b['bias'])+float(np.sum(wa*(np.asarray(a['mean'])-np.asarray(b['mean']))/np.asarray(b['scale'])))
    if decision:
        ta,tb=float(a['threshold']),float(b['threshold'])
        if not 0<ta<1 or not 0<tb<1:return None
        bias+=math.log(ta/(1-ta))-math.log(tb/(1-tb));m['threshold']=ta
    m['bias']=float(np.float32(bias));m['mean']=a['mean'];m['scale']=a['scale']
    return m

def compatible_mlp(a,b):
    """Affine first-layer conversion; floating-point agreement is measured."""
    m=copy.deepcopy(b);w=np.asarray(b['layers'][0]['weights'],np.float64)
    m['layers'][0]['weights']=(w*(np.asarray(a['scale'])/np.asarray(b['scale']))[:,None]).astype(np.float32).tolist()
    m['layers'][0]['bias']=(np.asarray(b['layers'][0]['bias'],np.float64)+((np.asarray(a['mean'])-np.asarray(b['mean']))/np.asarray(b['scale']))@w).astype(np.float32).tolist()
    m['mean']=a['mean'];m['scale']=a['scale'];return m

def transfer_qthreshold(source,target):
    """Preserve a post-quantization logit cut when output grid scale changes.

    This conversion is approximate across grids, and is evaluated explicitly.
    Endpoint codes mean always-normal/always-attack and retain that meaning.
    """
    cut=int(source['q_threshold'])
    if cut==128:return 128
    if cut==-127:return -127
    value=cut*source['layers'][-1]['output_scale']/target['layers'][-1]['output_scale']
    return int(np.clip(np.ceil(value),-127,128))
