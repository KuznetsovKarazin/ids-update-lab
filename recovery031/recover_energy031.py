#!/usr/bin/env python3
"""Post hoc repair of marker localization; never contacts or modifies the MCU.

The 030 gates and unsmoothed energy integrals are reused unchanged. Only the
coarse search trace is averaged before downsampling. Original results and CFN
remain read-only; output must be a fresh directory.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import numpy as np
from scipy.ndimage import uniform_filter1d
from scipy.signal import fftconvolve, find_peaks

PINNED = {
    'energy/analyze_continuous.py': '575a19d2fd5c9caadde42d81b1b7f2748d0768797888c8705892124ce057f546',
    'energy/vendor/cfn_parser.py': 'dd706afbddc92d58f41fc51a3dcc81e1ba685aed801e9a304604f81dc2260123',
    'energy/vendor/energy_analysis.py': '8f31e9de2622e37bdbf8d54df8e9a87723d150eb1bd4053d6d116bf13f6659af',
    'energy/vendor/generate_energy_windows.py': '4cc5bf8dcfde5f42fb49cba98962ba0219e08a586bd0912224d3067bc69b34f7',
}

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def load_frozen(kit):
    kit=Path(kit).resolve()
    for name, expected in PINNED.items():
        if sha256(kit/name) != expected:
            raise ValueError('Frozen analyzer dependency differs: '+name)
    spec=importlib.util.spec_from_file_location('frozen_energy030',kit/'energy/analyze_continuous.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def verify_hardware_binding(run):
    """Bind windows and update divisors to preserved successful MCU receipts."""
    hardware=Path(run)/'hardware'
    manifest_path=hardware/'evidence_manifest.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8-sig'))['sha256']
    verified=[]
    def read(name):
        path=hardware/name
        if name not in manifest or sha256(path)!=manifest[name]:
            raise ValueError('Hardware evidence hash mismatch: '+name)
        verified.append(name)
        return path.read_text(encoding='utf-8-sig')
    summary=json.loads(read('summary.json'))
    if not (summary.get('status')=='complete' and summary.get('measurement_origin')=='actual_mcu'
            and summary.get('label_mismatches')==0):
        raise ValueError('Hardware campaign did not complete with verified MCU agreement')
    spec=json.loads(read('energy/energy_windows.json'))
    read('energy/timeline.jsonl')
    campaign=json.loads(read('campaign_before_hardware.json'))
    blocks=spec['blocks'];plan=campaign['cost_plan']
    fields=lambda b:(b['id'],b['family'],b['policy'],b['block'])
    if [fields(b)for b in blocks]!=[fields(b)for b in plan]:
        raise ValueError('Recorded energy blocks differ from frozen campaign plan')
    receipts_total=0
    for block,planned in zip(blocks,plan):
        if block['accepted_updates']!=planned['updates']:
            raise ValueError('Energy divisor differs from planned accepted update count')
        records=[json.loads(line)for line in read('costs/'+block['id']+'/events.jsonl').splitlines()if line.strip()]
        costs=[r for r in records if r.get('event')=='cost' and r.get('phase')==block['id']
               and not r.get('unmeasured_warmup')]
        if len(costs)!=block['accepted_updates']:
            raise ValueError('Energy divisor differs from actual accepted update receipts')
        if len({c['version']for c in costs})!=len(costs):
            raise ValueError('Repeated version in measured update receipts')
        for c in costs:
            if c['family']!=block['family'] or c['policy']!=block['policy']:
                raise ValueError('Update receipt family/policy differs from energy block')
            if block['policy']=='bundle':
                if c.get('response',{}).get('accepted') is not True:
                    raise ValueError('Unaccepted bundle update receipt')
            elif block['policy']=='whole':
                if c.get('ready',{}).get('ok') is not True:
                    raise ValueError('Unaccepted whole-firmware update receipt')
                if not any(r.get('event')=='reboot_verified' and r.get('phase')==block['id']
                           and r.get('version')==c['version'] for r in records):
                    raise ValueError('Whole-firmware update has no verified reboot')
            else: raise ValueError('Unsupported measured policy')
        receipts_total+=len(costs)
    return dict(hardware_manifest_sha256=sha256(manifest_path),
                verified_files=verified,measured_accepted_update_receipts=receipts_total,
                block_count=len(blocks),board_id=summary['board_id'])

def antialias_width(coarse_dt, raw_dt):
    """Smallest odd sample count at least one coarse-grid interval wide."""
    # Tolerance avoids adding two samples for a floating representation of an
    # exact odd integer. This changes no threshold or time-window choice.
    n=max(1,math.ceil(coarse_dt/raw_dt-1e-9))
    return n if n%2 else n+1

def match_pattern_antialias(t,p,pattern):
    """Original 030 coarse search, with only pre-decimation averaging added."""
    def require(ok,message):
        if not ok: raise ValueError(message)
    host=np.array([sum(edge)/2 for pulse in pattern['pulses']
                   for edge in (pulse['start_host_s'],pulse['end_host_s'])])
    relative=host-host[0]
    dt=max(.08,(t[-1]-t[0])/2_000_000)
    grid=np.arange(t[0],t[-1]+dt*.1,dt)
    raw_dt=float(np.median(np.diff(t)))
    width=antialias_width(dt,raw_dt)
    # ONLY candidate localization uses this trace. Edge refinement and every
    # energy integral still receive original t,p from the unmodified analyzer.
    y=np.interp(grid,t,uniform_filter1d(p,size=width,mode='nearest'))
    candidates=[]
    for scale in np.geomspace(.20,5.,161):
        pad=2*scale
        tt=np.arange(0,(relative[-1]+4)*scale,dt)
        if len(tt)>=len(y) or len(tt)<16: continue
        template=np.zeros(len(tt))
        for a,b in zip(relative[::2],relative[1::2]):
            template[(tt>=pad+a*scale)&(tt<pad+b*scale)]=1
        template-=template.mean()
        template_norm=np.linalg.norm(template)
        if not template_norm: continue
        length=len(tt)
        c1=np.r_[0.,np.cumsum(y)];c2=np.r_[0.,np.cumsum(y*y)]
        sy=c1[length:]-c1[:-length]
        variance=np.maximum(0.,c2[length:]-c2[:-length]-sy*sy/length)
        denominator=np.sqrt(variance)*template_norm
        dot=fftconvolve(y,template[::-1],mode='valid')
        score=np.divide(dot,denominator,out=np.zeros_like(dot),where=denominator>1e-10)
        peaks,_=find_peaks(score,distance=max(1,int(length*.6)))
        if len(score): peaks=np.unique(np.r_[peaks,int(np.argmax(score))])
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
    best['coarse_antialias_filter']=dict(kind='centered_uniform_mean',samples=width,
        nominal_width_s=width*raw_dt,coarse_grid_dt_s=dt,
        purpose='candidate_localization_only; original trace used for edges and integration')
    return best

def recover(kit,run,cfn,output):
    run=Path(run).resolve();cfn=Path(cfn).resolve();output=Path(output).resolve()
    if output.exists(): raise ValueError('Output must be a fresh directory: '+str(output))
    if output==run or run in output.parents:
        raise ValueError('Write recovery beside the original run, not inside it')
    module=load_frozen(kit)
    hardware_binding=verify_hardware_binding(run)
    module.match_pattern=match_pattern_antialias
    windows=run/'hardware/energy/energy_windows.json'
    provenance=dict(
        stage='031',analysis_kind='posthoc_repair_of_coarse_marker_localization',
        original_prespecified_030_analysis_passed=False,
        original_030_gate_thresholds_unchanged=True,
        raw_CFN_unchanged=True,raw_UI_used_for_energy=True,
        hardware_access_attempted=False,
        repair_source_sha256=sha256(__file__),frozen_dependencies_sha256=PINNED,
        original_cfn_sha256=sha256(cfn),original_windows_sha256=sha256(windows),
        original_timeline_sha256=sha256(windows.with_name('timeline.jsonl')),
        hardware_binding=hardware_binding,
        rationale='Average before coarse 80ms point sampling to suppress intra-pulse periodic troughs. The width follows sampling intervals, not energy differences. Calibration, independent validation, uncertainty and energy formulas are unchanged.')
    try:
        report=module.analyze(cfn,windows,output)
        report['posthoc_repair']=provenance
        report['interpretation_gate']='posthoc_marker_localization_repair_with_unchanged_holdout_gates'
        report['limitations'].append('Marker localization was repaired after seeing the failed 030 trace; this is not a successful prespecified energy analysis.')
        (output/'summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')
        return report
    finally:
        if output.exists():
            (output/'repair_provenance.json').write_text(json.dumps(provenance,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kit',type=Path,default=Path(__file__).resolve().parent.parent/'research030')
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--cfn',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        r=recover(a.kit,a.run,a.cfn,a.output)
        print(json.dumps(dict(status=r['status'],energy_blocks=len(r['blocks']),
                             analysis_kind=r['posthoc_repair']['analysis_kind'],output=str(a.output))))
        return 0
    except Exception as e:
        print('error: '+type(e).__name__+': '+str(e),file=sys.stderr);return 2

if __name__=='__main__': raise SystemExit(main())
