#!/usr/bin/env python3
"""Verify preserved subset bytes and cross-check saved aggregates offline.

This does not replay raw serial logs, evaluate the full traffic corpus, or test
hardware. The full Supplementary Material S1 contains the primary-log auditors.
"""
import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path, PurePosixPath
from statistics import median


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    args = p.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / 'PROVENANCE.json').read_text(encoding='utf-8'))
    checks = []
    for f in manifest['files']:
        rel = PurePosixPath(f['path'])
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('Unsafe provenance path')
        data = (root / rel).read_bytes()
        if len(data) != f['bytes'] or hashlib.sha256(data).hexdigest() != f['sha256']:
            raise ValueError('Preserved-file hash/size mismatch: ' + str(rel))
    checks.append('16 original payload files match preserved SHA-256 and size')

    def rows(name):
        with (root / 'tables' / name).open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream))

    def read(name):
        return json.loads((root / 'summaries' / name).read_text(encoding='utf-8'))

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    obs = rows('mcu040_cost_observations.csv')
    med = rows('mcu040_cost_medians.csv')
    keys = ('board_id', 'optimization', 'family', 'policy', 'transition')
    groups = defaultdict(list)
    for row in obs:
        groups[tuple(row[k] for k in keys)].append(row)
    require(len(obs) == 480 and len(med) == 48 and len(groups) == 48, 'H4 cell count')
    n_medians = 0
    for row in med:
        values = groups[tuple(row[k] for k in keys)]
        require(len(values) == int(row['n_blocks']) == 10, 'H4 block count')
        require(len({v['block'] for v in values}) == 10, 'H4 unique blocks')
        for field, saved in row.items():
            if not field.endswith('_median') or saved == '':
                continue
            original = field[:-7]
            calculated = median(float(v[original]) for v in values)
            require(math.isclose(calculated, float(saved), rel_tol=1e-10, abs_tol=1e-8), 'H4 median: ' + field)
            n_medians += 1
    checks.append(f'480 saved cost observations reproduce {n_medians} nonempty medians in 48 cells')

    numerical = rows('mcu040_numerics_models.csv')
    require(len(numerical) == 52, 'Numerical table model count')
    for build in ('Og', 'O2'):
        data = read('numerics_' + build + '.json')
        models = data['model_results']
        require(len(models) == 26 and sum(m['inferred_records'] for m in models) == data['inferred_records'] == 26624, 'Numerical inference count')
        require(sum(m['label_mismatches'] for m in models) == data['label_mismatches'] == 7, 'Numerical label count')
        require(data['integer_code_mismatches'] == 9 and data['integer_codes_compared'] == 10240, 'Saved integer-code count')
        by_model = {m['model']: m for m in models}
        for row in (r for r in numerical if r['build_optimization'] == build):
            m = by_model[row['model']]
            for field in ('inferred_records', 'label_mismatches', 'probability_tolerance_exceeded'):
                require(int(row[field]) == m[field], 'Numerical table mismatch: ' + field)
            require(float(row['max_probability_abs_error']) == m['max_probability_abs_error'], 'Numerical probability maximum')
    checks.append('52 model rows agree with saved Og/O2 summaries; seven label mismatches per build retained')

    temporal = rows('temporal041_overview.csv')
    require({r['scenario']: int(r['test_rows']) for r in temporal} == {'original030': 7462871, 'window_C0038': 11468146, 'window_C0083': 10994486}, 'Temporal scenario counts')
    require(len(rows('temporal041_compatible_exports.csv')) == 36, 'Temporal export rows')
    require(read('temporal_plan.json')['mixed_retention_scenario_available'] is False, 'Cohort limitation')
    threshold = rows('threshold041_windows.csv')
    require(len(threshold) == 12, 'Threshold table rows')
    for row in threshold:
        fpr = 100 * int(row['future_FP']) / int(row['future_normal_rows'])
        rec = 100 * int(row['future_TP']) / int(row['future_attack_rows'])
        require(math.isclose(fpr, float(row['future_FPR_percent']), rel_tol=1e-12), 'Threshold FPR')
        require(math.isclose(rec, float(row['future_recall_percent']), rel_tol=1e-12), 'Threshold recall')
    checks.append('Three temporal scenarios and twelve threshold operating points cross-checked')

    future = rows('future043_all_weightings.csv')
    require(len(future) == 24 and read('future043.json')['models_evaluated'] == 8, 'Future export count')
    for row in future:
        fpr = 100 * float(row['FP_mass']) / float(row['normal_mass'])
        rec = 100 * float(row['TP_mass']) / float(row['attack_mass'])
        ba = (rec + 100 - fpr) / 2
        for calculated, field in ((fpr, 'FPR_percent'), (rec, 'recall_percent'), (ba, 'balanced_accuracy_percent')):
            require(math.isclose(calculated, float(row[field]), rel_tol=1e-10, abs_tol=1e-8), 'Future metric: ' + field)
    checks.append('24 future weighting rows reproduce FPR, recall and balanced accuracy from saved masses')

    audit = read('final200_audit_independent.json')
    r = audit['results']
    require(r['attempted_trials'] == sum(r['state_counts'].values()) == 200, 'P1 endpoint count')
    require(r['state_counts'] == {'old_valid': 166, 'new_valid': 31, 'no_response': 3}, 'P1 original outcomes')
    require(r['rail_off_confirmed'] == sum(r['confirmed_off_state_counts'].values()) == 188, 'P1 confirmed OFF')
    require(r['valid_after_confirmed_off'] == 185 and r['phase_confirmed'] == 0, 'P1 qualified scope')
    require(r['original_no_response_trial_ids'] == [61, 113, 186] and len(r['no_cut_trial_ids']) == 12, 'P1 exclusions')
    require(len(r['per_phase']) == 8 and all(x['attempted'] == 25 and x['phase_confirmed'] == 0 for x in r['per_phase'].values()), 'P1 phases')
    require(sum(x['rail_off_confirmed'] for x in r['per_phase'].values()) == 188, 'P1 per-phase OFF')
    require(r['numeric_reference_comparisons'] == 12 * r['numeric_valid_trials'] == 2364, 'P1 controls')
    checks.append('Saved P1 audit retains 200 attempts, 188 confirmed OFF, three unavailable endpoints and zero verified exact phases')
    print(json.dumps({'status': 'verified', 'payload_files': len(manifest['files']), 'checks': checks,
        'scope': 'Hash preservation and saved-aggregate consistency only; no fresh raw-log audit, model inference or hardware measurement'}, indent=2))


if __name__ == '__main__':
    main()
