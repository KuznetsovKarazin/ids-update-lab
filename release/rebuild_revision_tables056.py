#!/usr/bin/env python3
"""Rebuild six later numeric table fragments from published evidence, offline.

No fitting or MCU acquisition. Original captions/colours are presentation, not
computed data. Probability-by-category counts require restored raw observations.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
COMPACT=ROOT/'revision_evidence054'
FAMILIES=['lr','dt','mlp_float','mlp_int8']
NAMES=dict(lr='LR',dt='DT',mlp_float='MLP-F32',mlp_int8='MLP-I8')
def read(p): return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rows(name): return list(csv.DictReader((COMPACT/'tables'/name).open(encoding='utf-8-sig')))
def table(out,name,headers,body):
    spec='l'+'r'*(len(headers)-1)
    lines=[r'\begin{tabular}{'+spec+'}',r'\toprule',' & '.join(headers)+r'\\',r'\midrule']
    lines += [' & '.join(str(x) for x in row)+r'\\' for row in body]
    lines += [r'\bottomrule',r'\end{tabular}']
    (out/(name+'.tex')).write_text('\n'.join(lines)+'\n')
    with (out/(name+'.csv')).open('w',newline='') as f:
        w=csv.writer(f);w.writerow(headers);w.writerows(body)
def rebuild(out,evidence):
    out.mkdir(parents=True,exist_ok=False)
    a=rows('temporal041_compatible_exports.csv');overview={r['scenario']:r for r in rows('temporal041_overview.csv')}
    body=[]
    for index,name in enumerate(['original030','window_C0038','window_C0083'],1):
        v={r['model']:r for r in a if r['scenario']==name and r['weighting']=='rows'};o=overview[name]
        f32=round(float(v['mlp_float_compatible_first_layer']['decision_disagreement_percent'])*int(o['test_rows'])/100)
        body.append([f'S{index}',int(o['test_rows']),int(o['test_days']),
                     f"{float(v['lr_compatible_probability']['decision_disagreement_percent']):.3f}",
                     f"{float(v['lr_compatible_decision']['decision_disagreement_percent']):.3f}",f32,
                     f"{float(v['mlp_int8_compatible_requantized']['decision_disagreement_percent']):.3f}"])
    table(out,'revision_science_temporal',['Scenario','Test rows','Days','LR-P (percent)','LR-D (percent)','F32 (count)','I8 (percent)'],body)
    a=rows('threshold041_windows.csv');body=[]
    for f in FAMILIES:
        vals={int(x['calibration_hours']):x for x in a if x['model']==f}
        body.append([NAMES[f]]+[f"{float(vals[h]['future_FPR_percent']):.3f} / {float(vals[h]['future_recall_percent']):.3f}" for h in [6,12,24]])
    table(out,'revision_science_threshold',['Model','6 h FPR/recall','12 h FPR/recall','24 h FPR/recall'],body)
    a=rows('future043_all_weightings.csv');body=[]
    variants=['B_mlp_float','B_mlp_int8','mlp_int8_compatible_requantized','export_per_tensor_recalibrated',
              'export_per_channel_transferred','export_per_channel_recalibrated','percentile999_transferred','percentile999_recalibrated']
    for n in variants:
        r=next(x for x in a if x['model']==n and x['weighting']=='rows')
        body.append([n.replace('_',r'\_')]+[f"{float(r[k]):.3f}" for k in ['recall_percent','FPR_percent','disagreement_vs_B_I8_percent','disagreement_vs_B_F32_percent']])
    table(out,'revision_science_future',['Variant','Recall','FPR','Disagree B-I8','Disagree B-F32'],body)
    a=rows('mcu040_cost_medians.csv');body=[]
    for opt in ['Og','O2']:
        for f in FAMILIES:
            for transition in ['A_to_B_reused','B_to_C_same_parameters_reused']:
                vals={r['policy']:r for r in a if r['optimization']==opt and r['family']==f and r['transition']==transition}
                body.append([opt+' '+NAMES[f]+' '+('A-B' if transition.startswith('A_') else 'B-C')]+
                            [f"{float(vals[p]['handler_active_ms_median']):.3f}" for p in ['bundle','whole','compressed']])
    table(out,'revision_hardware_costs',['Build/model/transition','Package ms','Full image ms','Compressed ms'],body)
    p1=read(COMPACT/'summaries/final200_audit_independent.json')['results'];body=[]
    for phase in ['model_erase','model_body','slot_commit','selector_body','selector_commit','rotation_erase','rotation_body','rotation_commit']:
        r=p1['per_phase'][phase];states=r['state_counts'].copy()
        # All unconfirmed-cut endpoints were new_valid; retain this explicit gate.
        if r['no_cut'] and phase!='slot_commit': raise ValueError('Unexpected no-cut stratum')
        states['new_valid']=states.get('new_valid',0)-r['no_cut']
        body.append([phase.replace('_',' '),r['attempted'],r['rail_off_confirmed'],states.get('old_valid',0),states['new_valid'],states.get('no_response',0)])
    table(out,'revision_hardware_powercut',['Targeted phase','Attempts','Cuts','Old','New','Unavailable'],body)
    all_counts={}
    for opt in ['Og','O2']:
        counts={}
        for f in FAMILIES:
            path=evidence/'evidence040/revision039-recovery040/mcu/esp32s3-a0f262ebb558'/opt/'numerics'/f/'observations.jsonl'
            panel=read(evidence/'evidence040/revision039-recovery040/prepared/numerics/panel.json')['vectors']
            for line in path.read_text().splitlines():
                o=json.loads(line);c=counts.setdefault(panel[o['index']]['category'],Counter())
                c['evaluations']+=1;c['labels']+=o['response']['label']!=o['expected_label']
                c['probability']+=abs(o['response']['probability']-o['expected_probability'])>2e-6
        all_counts[opt]=counts
    if all_counts['Og']!=all_counts['O2']: raise ValueError('Do not collapse differing compiler-build counts')
    body=[]
    for category,n in [('real_stratified',512),('synthetic_random',256),('range_and_grid',128),('decision_boundary',128)]:
        c=all_counts['O2'][category];body.append([category.replace('_',' '),n,c['evaluations'],c['labels'],c['probability']])
    table(out,'revision_science_numerics',['Category','Inputs','Evaluations','Label differences','Probability exceedances'],body)
    (out/'provenance.json').write_text(json.dumps(dict(status='rebuilt',tables=6,hardware_accessed=False,
        source_compact_manifest_sha256=hashlib.sha256((COMPACT/'PROVENANCE.json').read_bytes()).hexdigest(),
        numerical_sources=str(evidence),presentation='numeric fragments; no manuscript modification'),indent=2)+'\n')
    print(json.dumps(dict(status='rebuilt',tables=6,output=str(out))))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--evidence',type=Path,default=ROOT.parent/'ids-evidence056/revision_supplement051')
    a=p.parse_args();rebuild(a.output,a.evidence)
