"""Curate reported science030 results without refitting or re-evaluating raw traffic.

Run from the workspace root, or supply --training and --audit. All numeric
figures are subsequently reproducible from science_evidence.json alone.
"""
from pathlib import Path
import argparse, csv, hashlib, json

HERE = Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--training', type=Path, default=HERE.parents[1]/'review030/input/ids-completion-030/training')
    p.add_argument('--audit', type=Path, default=HERE.parents[1]/'review030/science/audit.json')
    a=p.parse_args(); base=a.training
    names=['summary.json','evaluation.json','uncertainty.json','by_day.json','by_attack_type.json',
           'protocol_lock_before_data_and_predictions.json','temporal_support_after_purge.json',
           'sampling.json','calibration.json','fit_reports.json']
    src={n:json.loads((base/n).read_text()) for n in names}
    provenance={n:hashlib.sha256((base/n).read_bytes()).hexdigest() for n in names}
    lock=src['protocol_lock_before_data_and_predictions.json']
    models={n.stem:json.loads(n.read_text()) for n in (base/'models').glob('*.json')}
    architecture={n:{'kind':m['kind'],'transform':m['transform'],
                      'node_count':len(m.get('nodes',[])),
                      'dense_shape':[8,16,8,1] if m['kind'].startswith('mlp') else None,
                      'weights_plus_biases':289 if m['kind'].startswith('mlp') else 9 if m['kind']=='lr' else None,
                      'threshold':m['threshold'],'q_threshold':m.get('q_threshold'),
                      'input_scale':m.get('input_scale'),
                      'output_scale':m['layers'][-1]['output_scale'] if m['kind']=='mlp_int8' else None}
                  for n,m in models.items() if n.startswith(('A_','B_'))}
    evidence={
        'schema':'paper033_science_evidence_v1',
        'provenance':{'source_directory':str(base),'source_file_sha256':provenance,
                      'audit':json.loads(a.audit.read_text()),
                      'scope':'Curated aggregate results; full raw-data inference was not independently rerun in this curation.'},
        'summary':src['summary.json'], 'config':lock['config'],
        'temporal_protocol':lock['temporal_protocol'],
        'support':src['temporal_support_after_purge.json'],
        'sampling':src['sampling.json'],'calibration':src['calibration.json'],
        'architecture':architecture,'evaluation':src['evaluation.json'],
        'uncertainty':src['uncertainty.json'],'by_day':src['by_day.json'],
        'by_attack_type':src['by_attack_type.json'],
    }
    (HERE/'science_evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    fields=['model','cohort','weighting','recall','FPR','balanced_accuracy','decision_disagreement','mass','TN','FP','FN','TP']
    with (HERE/'science_metrics.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for cohort,weights in evidence['evaluation']['cohorts'].items():
            for weighting,records in weights.items():
                for model,r in records.items():
                    cm=r['confusion_mass']
                    w.writerow(dict(model=model,cohort=cohort,weighting=weighting,
                                    **{k:r[k] for k in fields[3:8]}, TN=cm[0][0],FP=cm[0][1],FN=cm[1][0],TP=cm[1][1]))
    print('Curated',len(models),'models/variants; figures use this evidence only.')

if __name__=='__main__':main()
