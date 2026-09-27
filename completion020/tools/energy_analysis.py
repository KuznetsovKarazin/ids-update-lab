#!/usr/bin/env python3
"""Integrate FNB58 CFN with an explicit uncertain host-to-CFN time offset.
Intervals are sensitivity bounds for the recorded piecewise-linear trace only;
not confidence intervals, physical sampling-rate verification, or calibration.
"""
from __future__ import annotations
import argparse, hashlib, json, math, sys
from pathlib import Path
import numpy as np
from cfn_parser import decode, analyze
from generate_energy_windows import binding

class Curve:
    def __init__(self,t,y):
        self.t=np.asarray(t,float);self.y=np.asarray(y,float)
        self.c=np.r_[0,np.cumsum((self.y[1:]+self.y[:-1])*.5*np.diff(self.t))]
    def value(self,x):
        if np.any(np.asarray(x)<self.t[0]) or np.any(np.asarray(x)>self.t[-1]): raise ValueError('Window outside recorded trace')
        return np.interp(x,self.t,self.y)
    def primitive(self,x):
        self.value(x); j=np.clip(np.searchsorted(self.t,x,side='right')-1,0,len(self.t)-2); dx=x-self.t[j]
        slope=(self.y[j+1]-self.y[j])/(self.t[j+1]-self.t[j])
        return self.c[j]+self.y[j]*dx+.5*slope*dx*dx
    def integral(self,a,b):
        if not a<b: raise ValueError('Empty/decreasing window')
        return float(self.primitive(b)-self.primitive(a))

def shifted_bounds(curve,terms,lo,hi):
    """Exact extrema of sum(weight * integral(a+s,b+s)) for linear trace."""
    if not lo<=hi: raise ValueError('Bad offset range')
    edges=[edge for a,b,w in terms for edge in (a,b)]
    curve.value(min(edges)+lo);curve.value(max(edges)+hi)
    knots=np.unique(np.r_[lo,hi,*[curve.t[(curve.t-edge>lo)&(curve.t-edge<hi)]-edge for edge in edges]])
    def value(s):return math.fsum(w*curve.integral(a+s,b+s) for a,b,w in terms)
    def derivative(s):return math.fsum(w*(curve.value(b+s)-curve.value(a+s)) for a,b,w in terms)
    candidates=knots.tolist()
    for a,b in zip(knots,knots[1:]):
        da,db=derivative(a),derivative(b)
        if da*db<0: candidates.append(float(a+(b-a)*(-da)/(db-da)))
    values=np.array([value(x) for x in candidates]); i,j=int(values.argmin()),int(values.argmax())
    return {'min_J':float(values[i]),'max_J':float(values[j]),'at_offset_min_s':float(candidates[i]),'at_offset_max_s':float(candidates[j]),'mid_offset_J':value((lo+hi)/2)}

def validate_windows(spec):
    if spec.get('generated_intervals_must_not_be_edited') and spec.get('host_window_binding_sha256')!=binding(spec):raise ValueError('Generated host windows were changed')
    if not isinstance(spec.get('cfn_time_minus_host_relative_time_s'),list) or len(spec['cfn_time_minus_host_relative_time_s'])!=2:raise ValueError('Measured CFN-to-host offset range required')
    baseline=spec['baseline_windows_host_s'];events=spec['events'];lo,hi=spec['cfn_time_minus_host_relative_time_s']
    if not baseline or not events or not math.isfinite(lo+hi) or lo>hi:raise ValueError('Missing baseline/events/finite offset range')
    if spec.get('alignment_method') not in ('observed_marker_interval','manual_record_start_interval'):raise ValueError('State how the time-offset interval was measured')
    if not isinstance(spec.get('alignment_evidence'),str) or len(spec['alignment_evidence'].strip())<10 or 'FILL' in spec['alignment_evidence']:raise ValueError('Describe observed alignment evidence and uncertainty')
    segments=[(float(a),float(b)) for a,b in baseline]
    names=set()
    for event in events:
        if not isinstance(event['id'],str) or event['id'] in names:raise ValueError('Event IDs must be distinct')
        names.add(event['id']); a,b=event['host_start_s'],event['host_end_s'];n=event.get('accepted_updates')
        if 'baseline_indices' in event and (not event['baseline_indices'] or any(type(i)is not int or not 0<=i<len(baseline) for i in event['baseline_indices']) or len(set(event['baseline_indices']))!=len(event['baseline_indices'])):raise ValueError('Invalid per-event baseline selection')
        if n is not None and (type(n)is not int or n<=0):raise ValueError('accepted_updates must be independently verified positive integer')
        segments.append((a,b))
    if any(not math.isfinite(a+b) or a>=b for a,b in segments):raise ValueError('Invalid interval')
    for i,(a,b) in enumerate(segments):
        for c,d in segments[i+1:]:
            if max(a,c)<min(b,d):raise ValueError('Baseline/event intervals overlap')
    return baseline,events,float(lo),float(hi)

def evaluate(cfn,windows,output):
    data=Path(cfn).read_bytes();header,rows=decode(data);spec=json.loads(Path(windows).read_text(encoding='utf-8-sig'));base,events,lo,hi=validate_windows(spec)
    t=np.array([r['relative_time_s'] for r in rows]);ui=np.array([r['voltage_V']*r['current_A'] for r in rows]);curve=Curve(t,ui)
    baseline_duration=sum(b-a for a,b in base); reports=[]
    counter=None
    if 'reported_energy_Wh' in rows[0]:counter=Curve(t,[r['reported_energy_Wh']*3600 for r in rows])
    for event in events:
        a,b=float(event['host_start_s']),float(event['host_end_s']);duration=b-a
        selected_base=[base[i] for i in event['baseline_indices']] if 'baseline_indices' in event else base
        baseline_duration=sum(y-x for x,y in selected_base)
        gross=shifted_bounds(curve,[(a,b,1)],lo,hi)
        net=shifted_bounds(curve,[(a,b,1)]+[(x,y,-duration/baseline_duration) for x,y in selected_base],lo,hi)
        result=dict(event,elapsed_s=duration,gross_UI_energy=gross,baseline_subtracted_UI_energy=net)
        if event.get('accepted_updates'):
            n=event['accepted_updates'];result['gross_UI_J_per_accepted_update']=[gross['min_J']/n,gross['max_J']/n];result['net_UI_J_per_accepted_update']=[net['min_J']/n,net['max_J']/n]
            result['per_update_interpretation']='Block average includes protocol, inter-update waiting and baseline uncertainty; not isolated flash energy'
        if counter:
            offsets=np.unique(np.r_[lo,hi,*[t[(t-e>lo)&(t-e<hi)]-e for e in (a,b)]])
            values=np.array([counter.value(b+s)-counter.value(a+s) for s in offsets])
            result['unchanged_NRG_channel_delta_J']={'min':float(values.min()),'max':float(values.max()),'mid':float(counter.value(b+(lo+hi)/2)-counter.value(a+(lo+hi)/2))}
            result['NRG_factor_corrected']=False
        reports.append(result)
    repeated=sum((a['voltage_V'],a['current_A'])==(b['voltage_V'],b['current_A']) for a,b in zip(rows,rows[1:]))
    report={'status':'complete','measurement_origin':'FNB58_recorded_channels','source_sha256':hashlib.sha256(data).hexdigest(),'windows_sha256':hashlib.sha256(Path(windows).read_bytes()).hexdigest(),'decoder_summary':analyze(header,rows),'windows_and_alignment':spec,'adjacent_identical_UI_fraction':repeated/(len(rows)-1),'events':reports,'measurement_accuracy_calibrated':False,'physical_sampling_rate_verified':False,'offset_bounds_are_statistical_CI':False,'limitations':['Bounds cover only declared time-offset uncertainty for the recorded piecewise-linear trace.','Voltage/current accuracy, analog bandwidth, sample filtering and timing-scale error are not bounded here.','NRG is never multiplied/divided by an empirical factor. UI and NRG disagreement must remain visible.','Do not infer single 35 ms operation energy from a sparse trace: use long predeclared blocks and independent repeats.','Compare identical protocol/wiring/baseline conditions; block averages include host/USB transport delays.']}
    out=Path(output);out.mkdir(parents=True,exist_ok=False);(out/'summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    print(json.dumps({'status':'complete','events':len(events),'output':str(out),'energy_counter_consistent_with_UI':report['decoder_summary'].get('energy_counter_consistent_with_UI')},ensure_ascii=False));return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cfn',type=Path,required=True);p.add_argument('--windows',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:evaluate(a.cfn,a.windows,a.output);return 0
    except (ValueError,OSError,KeyError) as e:print('error: '+str(e),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
