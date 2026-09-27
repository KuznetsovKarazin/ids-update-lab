"""Source-row provenance must preserve record indices and reject changed input."""
import csv
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np
import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / 'export_row_identifiers.py'
spec = importlib.util.spec_from_file_location('row_identifiers', MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def inputs(tmp_path):
    samples = tmp_path / 'samples'
    samples.mkdir()
    # First data record in a second source file, plus a later data record.
    arrays = {'raw': np.zeros((2, 8), dtype='<f4'),
              'labels': np.array([0, 1], dtype='u1'),
              'weights': np.ones(2, dtype='<f8'),
              'row_ids': np.array([1 << 32, (1 << 32) + 7], dtype='<u8')}
    np.savez_compressed(samples / 'B_cal.npz', **arrays)
    fingerprint = tmp_path / 'fingerprint.json'
    fingerprint.write_text(json.dumps({'samples': {'B_cal.npz': {'arrays': {
        name: {'shape': list(value.shape), 'dtype': value.dtype.str,
               'sha256_c_order': hashlib.sha256(value.tobytes()).hexdigest()}
        for name, value in arrays.items()}}}}))
    sources = tmp_path / 'sources.json'
    sources.write_text(json.dumps({'files': [
        {'file': 'Network_dataset_1.csv', 'local_sha256': 'a' * 64, 'bytes': 1},
        {'file': 'Network_dataset_2.csv', 'local_sha256': 'b' * 64, 'bytes': 2}]}))
    pins = json.loads(fingerprint.read_text())
    pins['source_manifest_sha256'] = module.sha256(sources)
    fingerprint.write_text(json.dumps(pins))
    return samples, fingerprint, sources, arrays


def test_export_preserves_original_csv_record_and_array_positions(tmp_path):
    samples, fingerprint, sources, _ = inputs(tmp_path)
    result = module.export_rows(samples, fingerprint, sources, tmp_path / 'rows')
    with gzip.open(tmp_path / 'rows/sample_rows.csv.gz', 'rt', newline='') as handle:
        rows = list(csv.DictReader(handle))
    assert rows == [
        {'role': 'B_cal', 'sample_index_0': '0', 'source_file': 'Network_dataset_2.csv',
         'csv_data_row_index_0': '0', 'row_id': '4294967296'},
        {'role': 'B_cal', 'sample_index_0': '1', 'source_file': 'Network_dataset_2.csv',
         'csv_data_row_index_0': '7', 'row_id': '4294967303'}]
    assert result['raw_traffic_values_exported'] is False
    second = module.export_rows(samples, fingerprint, sources, tmp_path / 'repeat')
    assert result['csv']['sha256'] == second['csv']['sha256']


@pytest.mark.parametrize('field', ['raw', 'labels', 'weights', 'row_ids'])
def test_export_rejects_any_changed_sample_array_before_writing(tmp_path, field):
    samples, fingerprint, sources, arrays = inputs(tmp_path)
    arrays[field].flat[0] += 1
    np.savez_compressed(samples / 'B_cal.npz', **arrays)
    with pytest.raises(ValueError, match='Sample array differs'):
        module.export_rows(samples, fingerprint, sources, tmp_path / 'rows')
    assert not (tmp_path / 'rows').exists()


def test_export_rejects_changed_source_file_mapping(tmp_path):
    samples, fingerprint, sources, _ = inputs(tmp_path)
    data = json.loads(sources.read_text())
    data['files'].reverse()
    sources.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='Source manifest differs'):
        module.export_rows(samples, fingerprint, sources, tmp_path / 'rows')
    assert not (tmp_path / 'rows').exists()
