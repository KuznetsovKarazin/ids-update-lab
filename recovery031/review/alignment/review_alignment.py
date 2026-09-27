#!/usr/bin/env python3
"""Independent alignment review; deliberately does not integrate energy."""
import hashlib, inspect, json, sys
from pathlib import Path
import numpy as np
from scipy.ndimage import uniform_filter1d
from scipy.signal import periodogram
BASE=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(BASE/'research030/energy'))
import analyze_continuous as orig
D=BASE/'review030/energy_diagnosis'; O=Path(__file__).resolve().parent
z=np.load(D/'samples.npz');t=z['relative_time_s'];p=z['voltage_V']*z['current_A']
spec=json.loads((BASE/'review030/input/ids-completion-030/hardware/energy/energy_windows.json').read_text())
# Candidate-only prefilter, frozen from diagnosed coarse-grid interval, not energy.
source=inspect.getsource(orig.match_pattern).replace('y=np.interp(grid,t,p)',
'raw_dt=float(np.median(np.diff(t)))\n    n=max(1,int(round(dt/raw_dt))); n += 1-n%2\n    y=np.interp(grid,t,uniform_filter1d(p,size=n,mode="nearest"))')
ns=vars(orig).copy();ns['uniform_filter1d']=uniform_filter1d;exec(source,ns);fixed=ns['match_pattern']
orig.match_pattern=fixed
r=orig.auto_align(t,p,spec)
scale=r['cfn_seconds_per_host_second'];offset=r['cfn_offset_s']
checks=[]; patterns=[]
for m in spec['marker_patterns']:
 obs, detail=orig.measure_edges(t,p,m,scale,offset)
 host=np.array([orig.midpoint(e) for e in orig.edges(m)])
 durations=(obs[1::2]-obs[::2])/scale
 expected=np.array([x['duration_device_s'] for x in m['pulses']])
 brackets=np.array(orig.edges(m)); mapped=(obs-offset)/scale
 outside=np.maximum(brackets[:,0]-mapped,np.maximum(mapped-brackets[:,1],0))
 patterns.append(dict(id=m['marker_id'],contrast_W=detail['contrast_W'],
   observed_edge_cfn_s=obs.tolist(),host_edge_s=host.tolist(),
   pulse_duration_error_s=(durations-expected).tolist(),
   max_absolute_pulse_duration_error_s=float(np.max(abs(durations-expected))),
   max_edge_outside_host_transport_bracket_s=float(np.max(outside))))
 # Deliberate coarse grid phase changes (0/10/20/30 ms); earliest marker
 # edges and final affine fit should not materially drift under them.
phase=[]
for shift in (1,2,3):
 rr=orig.auto_align(t[shift:],p[shift:],spec)
 phase.append(dict(raw_samples_omitted=shift,offset_delta_s=rr['cfn_offset_s']-offset,
   scale_delta_ppm=(rr['cfn_seconds_per_host_second']-scale)*1e6,
   max_holdout_error_s=rr['max_validation_residual_host_s']))
# Record durations of repeated numeric UI values; duplicates are not proof
# that every distinct report is statistically independent.
idx=np.r_[0,np.flatnonzero(np.diff(p)!=0)+1,len(p)]
lens=np.diff(idx); q=np.quantile(lens,[0,.5,.9,.99,1])
busy=(t>22)&(t<27)
freq,spectral_density=periodogram(p[busy],fs=1/np.median(np.diff(t)))
peak_frequency=float(freq[np.argmax(spectral_density[1:])+1])
# Guard tests retain actual marker waveform. An isolated snippet has 2s
# of padding around both ends. These are tests, not altered experimental CFN.
pat=spec['marker_patterns'][0]
start=np.searchsorted(t,0.);end=np.searchsorted(t,30.);tt=t[start:end].copy();pp=p[start:end].copy()
def gate(tt,yy,pat):
 c=fixed(tt,yy,pat);host=np.array([orig.midpoint(e) for e in orig.edges(pat)])
 off=c['first_edge_cfn_s']-c['scale']*host[0]
 ob,det=orig.measure_edges(tt,yy,pat,c['scale'],off)
 res=(ob-off)/c['scale']-host
 if np.max(abs(res))>.2: raise ValueError('measured pulse edges do not match candidate')
 return c
for name,yy,expect in [('actual_isolated_marker',pp,True),('flat_trace',np.full_like(pp,.17),False)]:
 try:detail=gate(tt,yy,pat);passed=True
 except Exception as e: detail=str(e);passed=False
 checks.append(dict(test=name,expected_accept=expect,accepted=passed,pass_=passed==expect,detail=detail))
# Duplicate same actual code, equal amplitudes: ambiguity must reject.
dt=np.median(np.diff(tt)); td=np.arange(0,65,dt);pd=np.full(len(td),.17)
for off in (0.,35.):
 mask=(td>=off)&(td<off+tt[-1]);pd[mask]=np.interp(td[mask]-off,tt,pp)
try:detail=gate(td,pd,pat);passed=True
except Exception as e: detail=str(e);passed=False
checks.append(dict(test='duplicate_equal_markers',expected_accept=False,accepted=passed,pass_=not passed,detail=detail))
# Remove one full marker pulse from actual recorded waveform.
for i in range(4):
 yy=pp.copy();a=patterns[0]['observed_edge_cfn_s'][2*i];b=patterns[0]['observed_edge_cfn_s'][2*i+1]
 yy[(tt>=a-.10)&(tt<=b+.25)]=.17
 try:detail=gate(tt,yy,pat);passed=True
 except Exception as e:detail=str(e);passed=False
 checks.append(dict(test=f'missing_pulse_{i}',expected_accept=False,accepted=passed,pass_=not passed,detail=detail))
result=dict(status='pass' if all(x['pass_'] for x in checks) else 'failed',
 scope='Independent skeptical alignment review only; no energy integrals or method comparisons inspected',
 cfn_sha256=hashlib.sha256((BASE/'upload/fnb58-idle-030.cfn').read_bytes()).hexdigest(),
 clock=r,pattern_duration_checks=patterns,candidate_grid_phase_sensitivity=phase,
 duplicate_UI_fraction=float(np.mean(np.diff(p)==0)),
 first_busy_plateau_22_to_27s_dominant_frequency_Hz=peak_frequency,
 repeated_value_run_length_samples_quantiles=q.tolist(),
 guard_tests=checks,
 limitations=['Post hoc candidate-search bug fix; original prespecified energy gate failed.',
 'All four marker patterns are near run endpoints; interior clock linearity is an assumption, not directly checked.',
 'Finite empirical timing envelope is not a calibrated metrological uncertainty bound.',
 'Repeated numeric readings prevent treating nominal 100 samples/s as independent readings.',
 'Guard tests cover specific missing and duplicate patterns, not all possible false positives.'])
(O/'alignment_review.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
