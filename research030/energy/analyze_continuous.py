#!/usr/bin/env python3
"""Align continuous FNB58 CFN to four frozen load patterns; integrate long blocks.

Alignment uses only the two calibration patterns. Two distinct patterns are
held out to check the fitted affine clock mapping. No NRG factor correction.
If marker contrast/uniqueness/clock consistency fail, no energy result is made.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
import numpy as np
from scipy.ndimage import median_filter
from scipy.signal import find_peaks, fftconvolve

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'vendor'))
from cfn_parser import decode, analyze as analyze_cfn
from energy_analysis import Curve, shifted_bounds

def require(condition, message):
    if not condition:
        raise ValueError(message)

def midpoint(interval):
    require(len(interval)==2 and all(math.isfinite(v) for v in interval)
            and interval[0]<=interval[1], 'Invalid host marker bracket')
    return sum(interval)*.5

def edges(pattern):
    return [edge for pulse in pattern['pulses']
            for edge in (pulse['start_host_s'],pulse['end_host_s'])]

def match_pattern(t,p,pattern):
    """Coarse global matched-filter search, then sub-sample edges refine it.

    Search range is deliberately broad (0.2--5 CFN s / host s). A peak
    merely proposes alignment; measured edges and holdout patterns gate it.
    """
    host=np.array([midpoint(e) for e in edges(pattern)])
    relative=host-host[0]
    dt=max(.08,(t[-1]-t[0])/2_000_000)
    grid=np.arange(t[0],t[-1]+dt*.1,dt)
    y=np.interp(grid,t,p)
    candidates=[]
    for scale in np.geomspace(.20,5.,161):
        pad=2*scale
        tt=np.arange(0,(relative[-1]+4)*scale,dt)
        if len(tt)>=len(y) or len(tt)<16:
            continue
        template=np.zeros(len(tt))
        for a,b in zip(relative[::2],relative[1::2]):
            template[(tt>=pad+a*scale)&(tt<pad+b*scale)]=1
        template-=template.mean()
        template_norm=np.linalg.norm(template)
        if not template_norm:
            continue
        length=len(tt)
        c1=np.r_[0.,np.cumsum(y)];c2=np.r_[0.,np.cumsum(y*y)]
        sy=c1[length:]-c1[:-length]
        variance=np.maximum(0.,c2[length:]-c2[:-length]-sy*sy/length)
        denominator=np.sqrt(variance)*template_norm
        dot=fftconvolve(y,template[::-1],mode='valid')
        score=np.divide(dot,denominator,out=np.zeros_like(dot),where=denominator>1e-10)
        peaks,_=find_peaks(score,distance=max(1,int(length*.6)))
        if len(score):
            peaks=np.unique(np.r_[peaks,int(np.argmax(score))])
        for j in sorted(peaks,key=lambda i:score[i],reverse=True)[:4]:
            if score[j]>=.70:
                candidates.append(dict(score=float(score[j]),scale=float(scale),
                                       first_edge_cfn_s=float(grid[j]+pad)))
    require(candidates,'No sufficiently clear synchronization pattern: '+pattern['marker_id'])
    candidates.sort(key=lambda c:c['score'],reverse=True)
    best=candidates[0]
    other=[c for c in candidates if abs(c['first_edge_cfn_s']-best['first_edge_cfn_s'])>
           max(1.,best['scale']*2)]
    require(best['score']>=.78,'Marker waveform too noisy: '+pattern['marker_id'])
    require(not other or best['score']-other[0]['score']>=.035,
            'Ambiguous synchronization pattern: '+pattern['marker_id'])
    best['runner_up_score']=other[0]['score'] if other else None
    return best

def measure_edges(t,p,pattern,scale,offset,search_host_s=.7):
    host=np.array([midpoint(e) for e in edges(pattern)])
    predicted=offset+scale*host
    dt=float(np.median(np.diff(t)))
    # Robust median removes isolated reporting spikes, not operation energy.
    # The original, unsmoothed UI curve is used for every energy integral.
    kernel=max(1,round(.06*scale/dt));kernel+=1-kernel%2
    left=np.searchsorted(t,predicted[0]-2*scale)
    right=np.searchsorted(t,predicted[-1]+2*scale)
    require(left>0 and right<len(t),'Marker touches recording boundary')
    tt=t[left:right]; raw=p[left:right]
    yy=median_filter(raw,size=kernel,mode='nearest')
    high=np.zeros(len(tt),dtype=bool);low=np.ones(len(tt),dtype=bool)
    for a,b in zip(predicted[::2],predicted[1::2]):
        high|=(tt>=a+.25*scale)&(tt<=b-.25*scale)
        low&=~((tt>=a-.25*scale)&(tt<=b+.25*scale))
    require(high.sum()>=8 and low.sum()>=8,'Insufficient samples in marker')
    lo=float(np.median(yy[low]));hi=float(np.median(yy[high]));contrast=hi-lo
    noise=float(1.4826*np.median(abs(yy[low]-lo)))
    require(contrast>=max(.003,6*noise),'MCU load marker is not resolved by meter')
    threshold=(lo+hi)*.5
    measured=[]
    for i,expected in enumerate(predicted):
        crossing=(yy[:-1]<threshold)&(yy[1:]>=threshold) if i%2==0 else (yy[:-1]>threshold)&(yy[1:]<=threshold)
        indices=np.flatnonzero(crossing & (abs(tt[:-1]-expected)<=search_host_s*scale))
        require(len(indices)>0,'Missing marker edge; no clock alignment accepted')
        j=min(indices,key=lambda j:abs(tt[j]-expected))
        frac=(threshold-yy[j])/(yy[j+1]-yy[j])
        observed=float(tt[j]+frac*(tt[j+1]-tt[j]))
        measured.append(observed)
    return np.array(measured),dict(contrast_W=contrast,baseline_noise_MAD_W=noise,
                                   median_filter_samples=kernel)

def auto_align(t,p,spec):
    patterns={x['marker_id']:x for x in spec['marker_patterns']}
    expected=['calibration_before','validation_before','validation_after','calibration_after']
    require(list(patterns)==expected,'Four frozen patterns in expected order required')
    calibration=[];quality={}
    for key in ('calibration_before','calibration_after'):
        pat=patterns[key];proposal=match_pattern(t,p,pat)
        host=np.array([midpoint(e) for e in edges(pat)])
        offset=proposal['first_edge_cfn_s']-proposal['scale']*host[0]
        observed,detail=measure_edges(t,p,pat,proposal['scale'],offset)
        calibration.extend(zip(host,observed,edges(pat)))
        quality[key]={**proposal,**detail}
    x=np.array([v[0] for v in calibration]);y=np.array([v[1] for v in calibration])
    scale,offset=np.polyfit(x,y,1)
    require(.20<=scale<=4.8,'Unsupported CFN clock-scale estimate')
    residuals=abs((y-offset)/scale-x)
    bracket_half=np.array([(v[2][1]-v[2][0])/2 for v in calibration])
    physical_dt=float(np.median(np.diff(t))/scale)
    threshold=max(.20,3*physical_dt+float(max(bracket_half)))
    require(float(max(residuals))<=threshold,'Calibration markers disagree with a single affine clock')
    holdout=[]
    for key in ('validation_before','validation_after'):
        pat=patterns[key]
        observed,detail=measure_edges(t,p,pat,scale,offset)
        host=np.array([midpoint(e) for e in edges(pat)])
        error=abs((observed-offset)/scale-host)
        require(float(max(error))<=threshold,'Independent validation marker failed: '+key)
        quality[key]={**detail,'max_host_residual_s':float(max(error)),
                      'used_to_fit_alignment':False}
        holdout.extend(error.tolist())
    uncertainty=float(max([*residuals,*holdout])+max(bracket_half)+physical_dt+.05)
    require(uncertainty<=.6,'Synchronization uncertainty exceeds protocol limit')
    return dict(method='affine_two_calibration_patterns_two_independent_validation_patterns',
                cfn_seconds_per_host_second=float(scale),cfn_offset_s=float(offset),
                host_boundary_uncertainty_s=uncertainty,
                max_calibration_residual_host_s=float(max(residuals)),
                max_validation_residual_host_s=max(holdout),
                allowed_host_interval_s=[float(min(x)),float(max(x))],
                pattern_quality=quality,
                uncertainty_kind='empirical envelope of marker residuals, transport brackets and one sample; not metrological bound',
                clock_mapping_verified_by_holdout_markers=True)

def manual_align(path):
    d=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    required=['cfn_seconds_per_host_second','cfn_offset_s','host_boundary_uncertainty_s',
              'allowed_host_interval_s','observed_evidence','independent_check_evidence']
    require(all(k in d for k in required),'Manual alignment is missing fields')
    require(all(math.isfinite(float(d[k])) for k in required[:3]),'Nonfinite manual alignment')
    require(.2<=d['cfn_seconds_per_host_second']<=4.8 and d['host_boundary_uncertainty_s']>0,
            'Invalid manual scale/uncertainty')
    require(all(isinstance(d[k],str) and len(d[k].strip())>=30 and 'FILL' not in d[k]
                for k in required[-2:]),'Actual observed evidence and independent check required')
    return dict(d,method='manual_observed_marker_mapping',
                clock_mapping_verified_by_holdout_markers=False,
                uncertainty_kind='investigator-declared interval; automatically unverified')

def validate_windows(spec):
    require(spec.get('status')=='host_capture_complete','Incomplete host energy capture')
    require(spec.get('blocks'),'No update blocks')
    baselines={b['id']:b for b in spec['baselines']}
    require(len(baselines)==len(spec['baselines']),'Duplicate baseline ID')
    ids=set();segments=[]
    for b in spec['baselines']:
        require(b['end_host_s']-b['start_host_s']>=9.99,'Baseline shorter than ten seconds')
        segments.append((b['start_host_s'],b['end_host_s']))
    for event in spec['blocks']:
        require(event['id'] not in ids,'Duplicate block ID');ids.add(event['id'])
        require(type(event['accepted_updates']) is int and event['accepted_updates']>0,'Unverified accepted-update count')
        require(event['end_host_s']-event['start_host_s']>=20,'Energy block shorter than 20 s: collect a long block, do not infer millisecond energy')
        require(len(event['baseline_ids'])==2 and len(set(event['baseline_ids']))==2,'Two surrounding idle baselines required')
        before,after=[baselines[i] for i in event['baseline_ids']]
        require(before['end_host_s']<=event['start_host_s'] and after['start_host_s']>=event['end_host_s'],
                'Baseline pair must bracket its block')
        segments.append((event['start_host_s'],event['end_host_s']))
    require(all(math.isfinite(a+b) and a<b for a,b in segments),'Invalid window bounds')
    for i,(a,b) in enumerate(segments):
        for c,d in segments[i+1:]:
            require(max(a,c)>=min(b,d),'Energy/baseline windows overlap')
    return baselines,segments

def analyze(cfn,windows,output,manual_alignment=None):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    report=dict(status='failed',energy_measured=False)
    try:
        raw=Path(cfn).read_bytes();header,rows=decode(raw)
        raw_windows=Path(windows).read_bytes();spec=json.loads(raw_windows)
        # Link frozen windows back to the append-only host capture when present.
        timeline=Path(windows).with_name('timeline.jsonl')
        require(timeline.exists(),'Original timeline.jsonl required beside windows')
        raw_timeline=timeline.read_bytes()
        require(hashlib.sha256(raw_timeline).hexdigest()==spec['source_sha256'],'Host timeline hash mismatch')
        records=[json.loads(line) for line in raw_timeline.splitlines() if line.strip()]
        require(records and records[-1]['event']=='complete','Host capture did not complete')
        require(spec['marker_patterns']==[r for r in records if r['event']=='marker_pattern'] and
                spec['baselines']==[r for r in records if r['event']=='baseline'] and
                spec['blocks']==[r for r in records if r['event']=='update_block'],
                'Energy windows differ from original timeline')
        baselines,segments=validate_windows(spec)
        require(all(k in rows[0] for k in ('voltage_V','current_A')),'CFN must include VBUS and IBUS')
        tc=np.array([r['relative_time_s'] for r in rows]);p=np.array([r['voltage_V']*r['current_A'] for r in rows])
        require(np.all(p>=0),'Negative measured UI power; inspect wiring/format')
        alignment=manual_align(manual_alignment) if manual_alignment else auto_align(tc,p,spec)
        scale=alignment['cfn_seconds_per_host_second'];offset=alignment['cfn_offset_s'];u=alignment['host_boundary_uncertainty_s']
        th=(tc-offset)/scale;dt=np.diff(th)
        require(float(max(dt))<=max(.15,5*float(np.median(dt))),'Large CFN sample gap; interpolation would hide missing data')
        left,right=alignment['allowed_host_interval_s']
        require(min(a for a,b in segments)-u>=left and max(b for a,b in segments)+u<=right,
                'Energy window outside interval spanned by calibration markers')
        curve=Curve(th,p);results=[]
        for event in spec['blocks']:
            a,b=event['start_host_s'],event['end_host_s'];duration=b-a;n=event['accepted_updates']
            require(u/duration<=.025,'Synchronization uncertainty exceeds 2.5% of block duration')
            gross=shifted_bounds(curve,[(a,b,1)],-u,u)
            selected=[baselines[k] for k in event['baseline_ids']]
            baseline_total=sum(x['end_host_s']-x['start_host_s'] for x in selected)
            average=[(x['start_host_s'],x['end_host_s'],-duration/baseline_total) for x in selected]
            net=shifted_bounds(curve,[(a,b,1)]+average,-u,u)
            individual=[]
            for x in selected:
                aa,bb=x['start_host_s'],x['end_host_s']
                individual.append(shifted_bounds(curve,[(a,b,1),(aa,bb,-duration/(bb-aa))],-u,u))
            lower=min(x['min_J'] for x in individual+[net]);upper=max(x['max_J'] for x in individual+[net])
            resolved=lower>0
            results.append(dict(event,elapsed_host_s=duration,gross_UI_energy_J=gross,
                                net_UI_energy_J=net,
                                net_timing_and_baseline_sensitivity_J=[lower,upper],
                                gross_J_per_accepted_update=[gross['min_J']/n,gross['max_J']/n],
                                net_J_per_accepted_update_sensitivity=[lower/n,upper/n],
                                additional_energy_resolved=resolved,
                                interpretation='Mean energy of the recorded paced update scenario; includes host/USB transport, verification and fixed waiting inside block'))
        report=dict(status='complete',energy_measured=True,
                    measurement_origin='actual_FNB58_UI_recording',
                    cfn_sha256=hashlib.sha256(raw).hexdigest(),windows_sha256=hashlib.sha256(raw_windows).hexdigest(),
                    alignment=alignment,decoder_diagnostics=analyze_cfn(header,rows),
            physical_time_scale_from_markers=not bool(manual_alignment),
                    interpretation_gate='marker_alignment_validated' if not manual_alignment else 'conditional_on_investigator_declared_alignment',
                    host_mapped_sample_dt_s=dict(min=float(min(dt)),median=float(np.median(dt)),max=float(max(dt))),
                    adjacent_identical_UI_fraction=sum((a['voltage_V'],a['current_A'])==(b['voltage_V'],b['current_A']) for a,b in zip(rows,rows[1:]))/(len(rows)-1),
                    blocks=results,energy_NRG_factor_corrected=False,
                    measurement_accuracy_calibrated=False,independent_sampling_rate_verified=False,
                    limitations=[
                        'Marker alignment does not calibrate voltage/current, analog bandwidth, filtering or meter self-consumption.',
                        'Bounds describe sensitivity of the recorded trace to stated alignment uncertainty and adjacent idle baselines; they are not statistical confidence intervals.',
                        'Affine clock fit cannot exclude unobserved nonlinear drift or missing/duplicated physical samples.',
                        'Integral uses raw VBUS*IBUS samples, with time mapped to host seconds. Raw CFN/NRG channels are never changed.',
                        'Net energy compatible with zero is unresolved, never clipped to zero or used to claim a percentage saving.',
                        'One board; repeated blocks are technical repetitions. Whole-firmware energy includes reboot; provisioning outside the block is excluded.'])
    except BaseException as exc:
        report.update(error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        (output/'summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cfn',type=Path,required=True);p.add_argument('--windows',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--manual-alignment',type=Path)
    a=p.parse_args()
    try:
        r=analyze(a.cfn,a.windows,a.output,a.manual_alignment)
        print(json.dumps(dict(status=r['status'],blocks=len(r['blocks']),output=str(a.output))))
        return 0
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print('error: '+str(exc),file=sys.stderr);return 2
if __name__=='__main__':
    raise SystemExit(main())
