#!/usr/bin/env python3
"""Acquire one C3 replication: installs test firmware and preserves every endpoint.

Run once per physical board, using its own inspect_c3.py identity.json. The two
boards must have distinct ROM MACs. Never overwrite or resume a failed campaign.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import zipfile
from host_awake import SleepGuard

ROOT = Path(__file__).resolve().parents[2]

def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def run(identity_path, output, port=None):
    identity = json.loads(identity_path.read_text())
    if identity.get('status') != 'passed' or identity.get('chip') != 'esp32c3' or identity.get('flash_bytes', 0) < 4194304:
        raise ValueError('Successful C3 ROM inspection required')
    if sha(identity_path.parent / 'rom.log') != identity['rom_log_sha256']:
        raise ValueError('ROM identity log changed')
    from inspect_c3 import parse_identity
    if any(identity[k] != v for k, v in parse_identity((identity_path.parent/'rom.log').read_text()).items()):
        raise ValueError('identity metadata differs from ROM log')
    port = port or identity['port']
    prebuilt = ROOT / 'revision056/build/prebuilt/O2'
    panel = ROOT / 'revision056/inputs/numerics040'
    if not (panel / 'manifest.json').is_file() or not (prebuilt / 'lr_bundle/metadata.json').is_file():
        raise ValueError('Restore the c3_prebuilt056 and c3_panel056 artifacts first; see revision056/README.md')
    output = output.resolve(); output.mkdir(parents=True, exist_ok=False)
    report = dict(status='running', board_id=identity['board_id'], port=port, stage='056',
                  protocol_sha256=sha(ROOT/'revision056/protocol.json'), identity=identity,
                  started_utc_ns=time.time_ns(), completed_steps=[])
    (output/'identity.json').write_text(json.dumps(identity, indent=2)+'\n')
    def step(name, arguments):
        command = [sys.executable, *arguments]
        (output/(name+'-command.json')).write_text(json.dumps(command, indent=2)+'\n')
        # Inherit stdout so the Windows console shows current progress.
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            raise RuntimeError(name + ' failed; preserved evidence must be investigated before any new campaign')
        report['completed_steps'].append(name)
    try:
        with SleepGuard(output/'host_power056.jsonl'):
            step('numerics', ['revision056/hardware/run_numerics056.py', 'mcu', '--root', str(ROOT),
                 '--prepared', str(panel), '--prebuilt-root', str(prebuilt), '--port', port,
                 '--board-id', identity['board_id'], '--output', str(output/'numerics'), '--provision'])
            step('prepare_costs', ['revision056/hardware/run_costs056.py', 'prepare',
                 '--prebuilt-root', str(prebuilt), '--output', str(output/'prepared_costs')])
            step('costs', ['revision056/hardware/run_costs056.py', 'run', '--artifacts', str(output/'prepared_costs'),
                 '--port', port, '--board-id', identity['board_id'], '--output', str(output/'costs')])
        report['status'] = 'complete'
    except Exception as exc:
        report.update(status='failed', error=repr(exc))
        raise
    finally:
        report['finished_utc_ns'] = time.time_ns()
        (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        pins = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob('*'))
                if p.is_file() and p.name != 'campaign_manifest.json'}
        (output/'campaign_manifest.json').write_text(json.dumps({'sha256': pins}, indent=2)+'\n')
        archive = output.with_suffix('.zip')
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as z:
            for p in sorted(output.rglob('*')):
                if p.is_file(): z.write(p, p.relative_to(output.parent))
        print(json.dumps(dict(status=report['status'], board_id=identity['board_id'], archive=str(archive),
                              archive_sha256=sha(archive))), flush=True)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--identity', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--port', help='New COM port if it changed since inspection')
    a = p.parse_args(); run(a.identity.resolve(), a.output, a.port)
