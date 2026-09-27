#!/usr/bin/env python3
"""Rebuild excluded TON-derived inputs from locally acquired, hash-pinned CSVs.

Uses the unchanged stage030 sampler and published frozen model parameters.
Does not fit models, change thresholds, contact hardware, or evaluate the full
future test. Output must be a fresh directory outside the published artifact.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import numpy as np
from export_row_identifiers import export_rows


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def require_pin(path, expected):
    if not path.is_file() or digest(path) != expected:
        raise ValueError('Original SHA-256 mismatch: ' + str(path))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release-root', type=Path, required=True,
                   help='Directory containing research030/ and runs/ids-completion-030/')
    p.add_argument('--fingerprints', type=Path, default=Path(__file__).with_name('DATA_INPUT_FINGERPRINTS037.json'))
    p.add_argument('--data-root', type=Path, required=True,
                   help='Directory containing all 23 original Network_dataset_*.csv')
    p.add_argument('--output', type=Path, required=True, help='Fresh output directory')
    a = p.parse_args()
    root, out = a.release_root.resolve(), a.output.resolve()
    if out == root or root in out.parents:
        raise ValueError('Keep the reconstruction output outside the published release')
    if out.exists():
        raise ValueError('Output must not already exist')
    fingerprints = json.loads(a.fingerprints.read_text())
    kit = root / 'research030'
    evidence = root / 'runs/ids-completion-030/training'
    kit_pins = json.loads((kit / 'KIT_MANIFEST.json').read_text())['sha256']
    pins = json.loads((evidence / 'result_manifest.json').read_text())['sha256']
    for rel in ['training/run_training030.py', 'training/model030.py',
                'training/vendor/audit_ton_full.py', 'training/vendor/source_manifest.json',
                'protocol/coverage_selection.json']:
        require_pin(kit / rel, kit_pins[rel])
    model_paths = sorted((evidence / 'models').glob('*.json'))
    if len(model_paths) != 24:
        raise ValueError('Expected the 24 published frozen models/conditions')
    for path in model_paths:
        require_pin(path, pins[path.relative_to(evidence).as_posix()])
    sys.path.insert(0, str(kit / 'training'))
    spec = importlib.util.spec_from_file_location('reconstruction_training030', kit / 'training/run_training030.py')
    training = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(training)
    sources = training.find_sources(root, a.data_root, False)
    protocol = json.loads((kit / 'protocol/coverage_selection.json').read_text())
    out.mkdir(parents=True, exist_ok=False)
    for name in ['samples', 'models', 'hardware_vectors']:
        (out / name).mkdir()
    training.dump(out / 'RECONSTRUCTION_STARTED.json', {
        'operation': 'reconstruct_saved_inputs_without_retraining',
        'source_files': [{k: s[k] for k in ['file', 'sha256', 'bytes']} for s in sources],
        'frozen_result_manifest_sha256': digest(evidence / 'result_manifest.json'),
        'hardware_access_attempted': False, 'full_future_test_evaluated': False})
    arrays, support = training.prepare_data(sources, protocol, out, False)
    del arrays
    verified = []
    for name in ['A_fit', 'A_cal', 'B_fit_added', 'B_cal', 'B_fit']:
        rel = 'samples/' + name + '.npz'
        sample = np.load(out / rel, allow_pickle=False)
        expected = fingerprints['samples'][name + '.npz']['arrays']
        if set(sample.files) != set(expected):
            raise ValueError('Sample array names differ: ' + rel)
        for field, pin in expected.items():
            value = sample[field]
            if (list(value.shape) != pin['shape'] or value.dtype.str != pin['dtype']
                    or hashlib.sha256(np.ascontiguousarray(value).tobytes()).hexdigest() != pin['sha256_c_order']):
                raise ValueError('Reconstructed sample array differs: ' + rel + ':' + field)
        verified.append(rel)
    row_references = export_rows(out / 'samples', a.fingerprints,
                                kit / 'training/vendor/source_manifest.json',
                                out / 'row_identifiers')
    for path in model_paths:
        shutil.copy2(path, out / 'models' / path.name)
    with sqlite3.connect(out / 'test_vectors.sqlite') as db:
        selected = db.execute('SELECT key FROM vectors ORDER BY key LIMIT 258').fetchall()
    golden = np.asarray([np.frombuffer(row[0], '<f4') for row in selected], np.float32)
    if golden.shape != (258, 8):
        raise ValueError('Original check-vector shape differs')
    probability_checks = []
    for path in model_paths:
        saved = fingerprints['hardware_vectors'][path.name]
        if list(golden.shape) != saved['raw_shape'] or hashlib.sha256(golden.astype('<f4').tobytes()).hexdigest() != saved['raw_sha256_c_order']:
            raise ValueError('Original hardware input content differs: ' + path.name)
        outputs = saved['authored_outputs_and_metadata']
        # Restore original authored predictions only after reconstructed input
        # bytes match. They are not presented as newly observed MCU outputs.
        result = {key: (golden.tolist() if key == 'raw' else outputs[key]) for key in
                  ['model_id', 'data_origin', 'selection', 'raw', 'probabilities', 'labels', 'model_sha256']}
        rel = 'hardware_vectors/' + path.name
        serialized = (json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + '\n').replace('\n', '\r\n').encode('utf-8')
        (out / rel).write_bytes(serialized)
        require_pin(out / rel, saved['original_json_sha256'])
        verified.append(rel)
        model = json.loads(path.read_text())
        probabilities, labels = training.predict(model, golden)
        probability_checks.append({'model': path.stem,
            'label_mismatches': int(np.sum(labels != np.asarray(outputs['labels']))),
            'max_probability_abs_error': float(np.max(np.abs(probabilities - np.asarray(outputs['probabilities']))))})
    training.dump(out / 'RECONSTRUCTION_COMPLETE.json', {
        'status': 'complete', 'verified_original_files': verified,
        'model_files_copied_without_retraining': len(model_paths),
        'sample_row_references': row_references['csv'],
        'sample_row_reference_directory': 'row_identifiers',
        'new_host_prediction_comparison': probability_checks,
        'sample_verification': 'Array dtype, shape and C-order bytes; NPZ ZIP compression/container bytes may differ across platforms',
        'golden_verification': 'Exact original JSON bytes after restoring original authored predictions to regenerated, hash-matched source vectors; this is not a new MCU run',
        'protocol_sha256': digest(kit / 'protocol/coverage_selection.json'),
        'hardware_access_attempted': False, 'full_future_test_evaluated': False,
        'cache_note': 'SQLite is regenerated; its container bytes are not required to match the original database file.'})
    print(json.dumps({'status': 'complete', 'output': str(out),
                      'original_sample_and_vector_files_verified': len(verified)}))


if __name__ == '__main__':
    main()
