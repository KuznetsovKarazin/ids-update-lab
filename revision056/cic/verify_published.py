#!/usr/bin/env python3
"""Verify delivered CIC files and metric arithmetic, without downloading CSVs."""
import csv
import hashlib
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'revision056/results/cic'
def sha(p):
    with Path(p).open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def verify(root=DATA):
    manifest=json.loads((root/'PUBLIC_RESULT_MANIFEST.json').read_text())
    for relative,digest in manifest['sha256'].items():
        if sha(root/relative)!=digest: raise ValueError('Published file changed: '+relative)
    report=json.loads((root/'summary.json').read_text())
    if report['protocol_sha256']!=sha(ROOT/'revision056/protocol.json'):
        raise ValueError('Frozen protocol changed')
    rows=list(csv.DictReader((root/'metrics.csv').open()))
    for r in rows:
        tn,fp,fn,tp,changed=[float(r[k]) for k in ('tn','fp','fn','tp','changed')]
        recomputed=dict(recall=tp/(tp+fn),FPR=fp/(tn+fp),
            balanced_accuracy=(tp/(tp+fn)+tn/(tn+fp))/2,
            decision_disagreement=changed/(tn+fp+fn+tp))
        for k,v in recomputed.items():
            if not math.isclose(float(r[k]),v,rel_tol=1e-12,abs_tol=1e-12):
                raise ValueError('Metric arithmetic mismatch')
    return dict(status='verified',delivered_files=len(manifest['sha256']),metric_rows=len(rows),
        source_dataset_rescanned=False,model_predictions_rerun=False,
        separate_full_source_audit='audit.json; recreate with fetch_pinned.py, run_cic.py and audit_cic.py')
if __name__=='__main__': print(json.dumps(verify(),indent=2))
