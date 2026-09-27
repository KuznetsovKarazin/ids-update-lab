#!/usr/bin/env python3
"""Export source-row references from verified saved or reconstructed samples.

No traffic values, labels, or model predictions are exported. A CSV row index
counts data records parsed after the header, starting at zero; it is not a
physical text-line number. The original sampler stores
row_id = (source_manifest_ordinal << 32) + csv_data_row_index_0.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path

import numpy as np


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verified_sample(path, expected):
    """Check scientific array bytes, independently of NPZ container metadata."""
    with np.load(path, allow_pickle=False) as sample:
        if set(sample.files) != set(expected):
            raise ValueError('Sample array names differ: ' + str(path))
        values = {name: sample[name] for name in sample.files}
    for name, pin in expected.items():
        value = values[name]
        content_hash = hashlib.sha256(np.ascontiguousarray(value).tobytes()).hexdigest()
        if (list(value.shape) != pin['shape'] or value.dtype.str != pin['dtype']
                or content_hash != pin['sha256_c_order']):
            raise ValueError('Sample array differs: ' + str(path) + ':' + name)
    return values


def export_rows(samples_dir, fingerprints_path, source_manifest_path, output):
    """Write only references after every source sample passes its frozen pins."""
    samples_dir, output = Path(samples_dir), Path(output)
    if output.exists():
        raise ValueError('Output directory must not already exist')
    fingerprints = json.loads(Path(fingerprints_path).read_text(encoding='utf-8'))
    if sha256(source_manifest_path) != fingerprints['source_manifest_sha256']:
        raise ValueError('Source manifest differs from the frozen input fingerprint')
    source_manifest = json.loads(Path(source_manifest_path).read_text(encoding='utf-8'))
    sources = source_manifest['files']
    records = {}
    for name, pin in sorted(fingerprints['samples'].items()):
        values = verified_sample(samples_dir / name, pin['arrays'])
        ids = values['row_ids']
        if ids.ndim != 1 or ids.dtype.kind != 'u' or ids.dtype.itemsize != 8:
            raise ValueError('Expected unsigned 64-bit row identifiers: ' + name)
        if len(ids) > 1 and np.any(ids[1:] <= ids[:-1]):
            raise ValueError('Row identifiers must be strictly increasing: ' + name)
        if np.any(ids >> np.uint64(32) >= len(sources)):
            raise ValueError('Unknown source-file ordinal: ' + name)
        records[Path(name).stem] = ids

    output.mkdir(parents=True, exist_ok=False)
    csv_path = output / 'sample_rows.csv.gz'
    # Fix gzip metadata as well as CSV record ordering for portable comparison.
    with csv_path.open('wb') as binary:
        with gzip.GzipFile(filename='', mode='wb', fileobj=binary, mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding='utf-8', newline='') as text:
                writer = csv.writer(text, lineterminator='\n')
                writer.writerow(['role', 'sample_index_0', 'source_file',
                                 'csv_data_row_index_0', 'row_id'])
                for role, ids in records.items():
                    for sample_index, saved_id in enumerate(ids):
                        row_id = int(saved_id)
                        ordinal, data_row = row_id >> 32, row_id & 0xffffffff
                        writer.writerow([role, sample_index, sources[ordinal]['file'],
                                         data_row, row_id])
    result = {
        'schema': 'ids_sample_row_references_v1',
        'status': 'complete',
        'row_index_convention': 'Zero-based CSV data-record index after the header, not physical text-line number',
        'sample_index_convention': 'Zero-based array position in the named role NPZ',
        'row_id_encoding': '(zero-based source-manifest ordinal << 32) + csv_data_row_index_0',
        'roles': {role: len(ids) for role, ids in records.items()},
        'csv': {'file': csv_path.name, 'sha256': sha256(csv_path)},
        'frozen_input_fingerprints_sha256': sha256(fingerprints_path),
        'frozen_source_manifest_sha256': sha256(source_manifest_path),
        'source_files': [{'ordinal': i, 'file': entry['file'],
                          'sha256': entry['local_sha256'], 'bytes': entry['bytes']}
                         for i, entry in enumerate(sources)],
        'validation': 'Every array in every sample verified by frozen dtype, shape and C-order content SHA-256 before export',
        'raw_traffic_values_exported': False,
        'hardware_access_attempted': False,
    }
    (output / 'row_references.json').write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return result


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=Path, required=True,
                        help='Directory containing all five original or reconstructed sample NPZ files')
    parser.add_argument('--fingerprints', type=Path,
                        default=here / 'DATA_INPUT_FINGERPRINTS037.json')
    parser.add_argument('--source-manifest', type=Path,
                        default=here.parent / 'research030/training/vendor/source_manifest.json')
    parser.add_argument('--output', type=Path, required=True, help='Fresh output directory')
    args = parser.parse_args()
    result = export_rows(args.samples, args.fingerprints, args.source_manifest, args.output)
    print(json.dumps({'status': result['status'], 'roles': result['roles'],
                      'output': str(args.output), 'raw_traffic_values_exported': False}))


if __name__ == '__main__':
    main()
