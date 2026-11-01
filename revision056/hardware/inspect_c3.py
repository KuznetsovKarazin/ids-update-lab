#!/usr/bin/env python3
"""Read ROM chip/MAC and flash capacity; no flash erase/write is issued."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

def parse_identity(log):
    macs = {m.lower() for m in re.findall(r'MAC:\s*([0-9a-fA-F:]{17})', log)}
    size = re.search(r'Detected flash size:\s*(\d+)\s*MB', log, re.I)
    if 'ESP32-C3' not in log or len(macs) != 1 or not size or int(size.group(1)) < 4:
        raise ValueError('Need one ESP32-C3 MAC and at least 4 MB detected flash')
    mac, = macs
    return dict(chip='esp32c3', mac=mac, board_id='esp32c3-' + mac.replace(':', ''),
                flash_bytes=int(size.group(1)) * 1024**2)

def inspect(port, output):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, '-m', 'esptool', '--chip', 'esp32c3', '--port', port,
               '--after', 'hard_reset', 'flash_id']
    report = dict(status='failed', port=port, command=command, flash_mutation_attempted=False,
                  board_reset_requested=True, utc_ns=time.time_ns())
    try:
        result = subprocess.run(command, text=True, encoding='utf-8', errors='replace',
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (output / 'rom.log').write_text(result.stdout, encoding='utf-8')
        report['rom_log_sha256'] = hashlib.sha256((output / 'rom.log').read_bytes()).hexdigest()
        if result.returncode:
            raise RuntimeError('ROM query failed; inspect rom.log')
        report.update(parse_identity(result.stdout), status='passed')
    except Exception as exc:
        report['error'] = repr(exc)
        raise
    finally:
        (output / 'identity.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', required=True); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); inspect(a.port, a.output)
