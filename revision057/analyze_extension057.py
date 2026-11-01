#!/usr/bin/env python3
"""Recompute the two C3 campaigns and the added manuscript tables.

Reads preserved MCU receipts and fixed CIC confusion counts. Creates no hardware
measurements, refits no model, and changes no acquisition protocol or endpoint.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'revision056/hardware'))
import analyze_boards056 as audit056

def read(p): return json.loads(Path(p).read_text())
def save(p, data): p.write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')
def rows(p):
    with Path(p).open(encoding='utf-8-sig', newline='') as f: return list(csv.DictReader(f))
def write_csv(p, data):
    with p.open('w', newline='') as f:
        w=csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
def esc(x): return str(x).replace('_', r'\_').replace('%', r'\%')
def table(path, caption, label, header, data, spec):
    wide=path.stem in ('c3_cost_details057','cic_all057','cic_types057')
    path.write_text('\n'.join([r'\begin{table}[!htbp]',r'\begin{adjustwidth}{-\extralength}{0cm}' if wide else '',r'\color{RevisionBlue}',r'\captionsetup{font+=revisionblue}',
        r'\caption{'+caption+r'}\label{'+label+'}',r'\centering\footnotesize\setlength{\tabcolsep}{4pt}' if wide else r'\centering\small',r'\begin{tabular}{'+spec+'}',
        r'\toprule '+' & '.join(header)+r'\\',r'\midrule',
        *[' & '.join(map(str,r))+r'\\' for r in data],r'\bottomrule\end{tabular}',r'\end{adjustwidth}' if wide else '',r'\end{table}','']))
def observations(d):
    result={}
    for f in ('lr','dt','mlp_float','mlp_int8'):
        obs=audit056.lines(d/f/'observations.jsonl')
        raw=[x for x in audit056.raw_messages(d/f) if x.get('event')=='inference']
        if raw != [o['response'] for o in obs]: raise ValueError('Raw numerical receipt mismatch')
        for o in obs:
            key=(o['phase'],o['index'])
            if key in result: raise ValueError('Duplicate model/input')
            result[key]=o
    if len(result)!=26624: raise ValueError('Incomplete numerical matrix')
    return result

def run(boards, historical, output):
    output.mkdir(parents=True, exist_ok=False)
    audit056.main(boards,output/'board_audit')
    tables=output/'tables'; tables.mkdir()
    costs=rows(output/'board_audit/costs_per_board.csv')
    numerical=[observations(d/'numerics') for d in boards]
    s3=observations(historical/'revision039-recovery040/mcu/esp32s3-a0f262ebb558/O2/numerics')
    comparisons=[]
    for name,left,right in [('C3-1 versus C3-2',numerical[0],numerical[1]),('C3-1 versus S3 O2',numerical[0],s3),('C3-2 versus S3 O2',numerical[1],s3)]:
        counts=dict(comparison=name,evaluations=len(left),label_differences=0,probability_differences=0,integer_code_differences=0,max_probability_abs_difference=0.0)
        for k,o in left.items():
            other=right[k]
            if o['raw']!=other['raw']: raise ValueError('Input differs between campaigns')
            a,b=o['response'],other['response']
            for field in ('bundle_sha256','runtime_abi','pretransform','version','data_origin'):
                if a.get(field)!=b.get(field): raise ValueError('Different release identity '+field)
            counts['label_differences']+=a['label']!=b['label']
            counts['probability_differences']+=a['probability']!=b['probability']
            counts['integer_code_differences']+=a.get('q_score')!=b.get('q_score')
            counts['max_probability_abs_difference']=max(counts['max_probability_abs_difference'],abs(a['probability']-b['probability']))
        comparisons.append(counts)
    write_csv(output/'numerical_cross_device.csv',comparisons)
    exceptions=[]
    panel=read(ROOT/'revision056/inputs/numerics040/panel.json')['vectors']
    gold={p.stem:read(p) for p in (ROOT/'revision056/inputs/numerics040/golden').glob('*.json')}
    for b,obs in enumerate(numerical,1):
        for (model,i),o in obs.items():
            g=gold[model]; r=o['response']; error=abs(r['probability']-g['probabilities'][i])
            lm=r['label']!=g['labels'][i]; im='q_score' in r and r['q_score']!=g['scores'][i]
            if lm or im or error>2e-6:
                exceptions.append(dict(board='C3-'+str(b),model=model,input_index=i,category=panel[i]['category'],label_mismatch=lm,probability_abs_error=error,probability_tolerance_exceeded=error>2e-6,integer_code_mismatch=im,host_label=g['labels'][i],device_label=r['label'],host_probability=g['probabilities'][i],device_probability=r['probability']))
    write_csv(output/'numerical_exceptions.csv',exceptions)
    families=('lr','dt','mlp_float','mlp_int8'); pretty=dict(lr='LR',dt='DT',mlp_float='MLP-F32',mlp_int8='MLP-I8')
    ids=[read(d/'summary.json')['board_id'] for d in boards]
    c={(r['board_id'],r['family'],r['policy']):r for r in costs}
    comparisons_cost=[]
    for f in families:
        for p in ('bundle','whole','compressed'):
            a=float(c[ids[0],f,p]['handler_active_ms_median']); b=float(c[ids[1],f,p]['handler_active_ms_median'])
            comparisons_cost.append(dict(family=f,policy=p,board1_median_ms=a,board2_median_ms=b,relative_difference_percent=100*(b-a)/a))
    write_csv(output/'cost_between_board.csv',comparisons_cost)
    detail=[];ratios=[]
    for b,bid in enumerate(ids,1):
        for f in families:
            pack=float(c[bid,f,'bundle']['handler_active_ms_median'])
            for p in ('bundle','whole','compressed'):
                r=c[bid,f,p]
                detail.append(['C3-'+str(b),pretty[f],dict(bundle='Package',whole='Raw',compressed='Compressed')[p],f"{float(r['handler_active_ms_median']):.3f}",f"{float(r['handler_active_ms_min']):.3f}--{float(r['handler_active_ms_max']):.3f}",f"{float(r['usb_total_ms_median'])/1000:.3f}",f"{float(r['artifact_bytes_median']):,.0f}"])
                if p!='bundle': ratios.append(float(r['handler_active_ms_median'])/pack)
    table(tables/'c3_cost_details057.tex','Complete C3 installation matrix. Each row has ten measured A-to-B updates. MCU processing is in milliseconds; host time is in seconds and includes transfer and full-image restart. Min--max gives observed MCU intervals. Signed bytes include the envelope or image manifest.','tab:c3-cost-details',['Board','Model','Policy','MCU median','MCU min--max','Host median','Bytes'],detail,'lllrrrr')
    main=[]
    for b,bid in enumerate(ids,1):
        for f in families: main.append(['C3-'+str(b),pretty[f],*[f"{float(c[bid,f,p]['handler_active_ms_median']):.3f}" for p in ('bundle','whole','compressed')]])
    table(tables/'c3_costs057.tex','Optimized A-to-B installation processing on the two C3 boards. Values are medians of ten observations in milliseconds; intervals exclude transport waits and reboot, as in the S3 comparison.','tab:c3-costs',['Board','Model','Package','Raw image','Compressed'],main,'llrrr')
    cic=ROOT/'revision056/results/cic'; metrics=rows(cic/'metrics.csv'); bytype=rows(cic/'by_type.csv')
    m={(r['model'],r['weighting']):r for r in metrics}; btypes={(r['model'],r['attack_type']):r for r in bytype if r['weighting']=='rows'}
    summary_cic=[]
    for f in families:
        r=m['B_'+f,'rows']; tr=[r for (name,kind),r in btypes.items() if name=='B_'+f and kind!='BenignTraffic']
        if len(tr)!=33: raise ValueError('Expected 33 attack types')
        macro=statistics.mean(float(x['recall']) for x in tr)
        summary_cic.append(dict(family=f,recall_percent=100*float(r['recall']),FPR_percent=100*float(r['FPR']),macro_attack_recall_percent=100*macro))
    write_csv(output/'cic_B_summary.csv',summary_cic)
    table(tables/'cic_summary057.tex','Complete B releases on the CICIoT2023 test subset (871,507 rows). Percentages use row weighting; macro recall gives equal weight to each of the 33 attack types and is an additional descriptive analysis.','tab:cic-summary',['Model','Recall','FPR','Macro recall'],[[pretty[r['family']],*[f"{r[k]:.3f}" for k in ('recall_percent','FPR_percent','macro_attack_recall_percent')]] for r in summary_cic],'lrrr')
    roles=read(cic/'data_audit.json')['roles']; sampling=read(cic/'sampling.json')
    role_order=('A_fit','A_cal','B_fit_added','B_cal','common_test')
    table(tables/'cic_roles057.tex','CIC role populations after the feature gate. The five atomic roles are disjoint in admitted feature vectors; B fitting is the union of the two fitting roles.','tab:cic-roles',['Atomic role','Hash bucket','Normal','Attack'],[[esc(role),bucket,f"{roles[role]['normal']:,}",f"{roles[role]['attack']:,}"] for role,bucket in zip(role_order,('0--34','35--44','45--64','65--74','75--99'))],'llrr')
    name_map={}
    for f in families:
        name_map['A_'+f]='A '+pretty[f];name_map['B_'+f]='B '+pretty[f]
    for r in metrics:
        name=r['model']
        if name in name_map:continue
        for f in sorted(families,key=len,reverse=True):
            if name.startswith(f+'_'): name_map[name]=pretty[f]+' '+name[len(f)+1:].replace('_',' ')
    allrows=[]
    for name in dict.fromkeys(r['model'] for r in metrics):
        r=m[name,'rows']
        allrows.append([name_map[name],f"{100*float(r['recall']):.3f}",f"{100*float(r['FPR']):.3f}",*[f"{100*float(m[name,w]['decision_disagreement']):.5f}" for w in ('rows','vector_balanced','frequency_cap100')]])
    table(tables/'cic_all057.tex','All 24 fixed CIC conditions. Recall and FPR use row weighting; disagreement with the complete B release of the same family is shown under row, equal-vector, and cap-100 weighting. All values are percentages. Zero changes and unfavorable conditions are retained.','tab:cic-all',['Condition','Recall','FPR',r'$\Delta_{\rm row}$',r'$\Delta_{\rm vector}$',r'$\Delta_{100}$'],allrows,'lrrrrr')
    type_rows=[]
    for kind in sorted(k for (name,k) in btypes if name=='B_lr' and k!='BenignTraffic'):
        r=btypes['B_lr',kind];n=int(float(r['tp'])+float(r['fn']))
        type_rows.append([esc(kind),f'{n:,}',*[f"{100*float(btypes['B_'+f,kind]['recall']):.2f}" for f in families]])
    table(tables/'cic_types057.tex','CIC test attack support and recall of the four complete B releases (row weighting; percentages). Each type contributes equally to macro recall regardless of its row count.','tab:cic-types',['Attack type','Rows','LR','DT','MLP-F32','MLP-I8'],type_rows,'lrrrrr')
    out=dict(status='verified',device_comparisons=comparisons,measured_installations=240,per_board_numerical_evaluations=26624,per_board_integer_comparisons=10240,
        max_between_C3_cell_median_relative_difference_percent=max(abs(r['relative_difference_percent']) for r in comparisons_cost),
        C3_image_to_package_processing_ratio_min=min(ratios),C3_image_to_package_processing_ratio_max=max(ratios),
        C3_max_host_probability_abs_error=max(e['probability_abs_error'] for e in exceptions),
        test_counts=roles['common_test'],CIC_B_results=summary_cic,
        descriptive_only=True,board_results_pooled=False,measurements_created_by_analysis=False)
    save(output/'summary.json',out)
    save(output/'manifest.json',{'sha256':{p.relative_to(output).as_posix():audit056.sha(p) for p in sorted(output.rglob('*')) if p.is_file() and p.name!='manifest.json'}})
    print(json.dumps({k:v for k,v in out.items() if k!='test_counts'},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--board',type=Path,action='append',required=True)
    p.add_argument('--historical',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.board,a.historical,a.output)
