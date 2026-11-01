"""Synthetic gates only; none of these tests is a physical-board measurement."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
hw = module('hardware056_test', ROOT/'revision056/hardware/hardware056.py')
inspect = module('inspect056_test', ROOT/'revision056/hardware/inspect_c3.py')
costs = module('costs056_test', ROOT/'revision056/hardware/run_costs056.py')

@pytest.mark.parametrize('log', [
    'ESP32-S3\nMAC: 01:02:03:04:05:06\nDetected flash size: 4MB',
    'ESP32-C3\nMAC: 01:02:03:04:05:06\nDetected flash size: 2MB',
    'ESP32-C3\nDetected flash size: 4MB'])
def test_inspection_refuses_wrong_chip_or_capacity(log):
    with pytest.raises(ValueError): inspect.parse_identity(log)

@pytest.mark.parametrize('log', [
    'ESP32-S3\nMAC: 01:02:03:04:05:06\nDetected flash size: 4MB',
    'ESP32-C3\nMAC: 01:02:03:04:05:07\nDetected flash size: 4MB',
    'ESP32-C3\nMAC: 01:02:03:04:05:06\nDetected flash size: 2MB'])
def test_rom_gate_precedes_every_flash_write(tmp_path, log):
    a = SimpleNamespace(port='fake', board_id='esp32c3-010203040506')
    art = dict(root=tmp_path, families={'lr': {'policies': {'bundle': {'factory_dir': 'factory'}}}})
    with patch.object(hw, 'esptool', return_value=log) as tool:
        with pytest.raises(RuntimeError): hw.provision(a, tmp_path, art, 'lr', 'bundle')
        assert tool.call_count == 1
        assert tool.call_args.args[2] == 'rom_identity'

def test_plan_has_ten_blocks_and_every_cell_once_per_block():
    p = costs.plan(costs.FAMILIES, 10)
    assert len(p) == 120
    for block in range(1, 11):
        assert {(r['family'], r['policy']) for r in p if r['block'] == block} == {
            (f, policy) for f in costs.FAMILIES for policy in costs.POLICIES}

def test_board_identity_requires_c3_and_exact_mac():
    assert hw.board_mac('esp32c3-010203040506') == '01:02:03:04:05:06'
    with pytest.raises(ValueError): hw.board_mac('esp32s3-010203040506')


def test_combined_analysis_rejects_one_physical_board_twice():
    analysis = module('analysis056_test', ROOT/'revision056/hardware/analyze_boards056.py')
    with pytest.raises(ValueError):
        analysis.unique_board_ids([{'board_id': 'esp32c3-010203040506'}]*2)
    assert len(analysis.unique_board_ids([{'board_id': 'esp32c3-010203040506'},
                                        {'board_id': 'esp32c3-010203040507'}])) == 2
