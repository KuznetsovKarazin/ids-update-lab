#!/usr/bin/env python3
"""Audit two C3 campaigns from raw receipts and report each board separately."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]
def read(p): return json.loads(Path(p).read_text())
def lines(p): return [json.loads(x) for x in Path(p).read_text().splitlines() if x.strip()]
def sha(p):
    with Path(p).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
def raw_messages(directory):
    raw = b''.join(bytes.fromhex(x['bytes_hex']) for x in lines(directory/'transcript.jsonl') if x.get('direction') == 'rx_bytes')
    result = []
    for line in raw.splitlines():
        try: obj = json.loads(line)
        except (ValueError, UnicodeDecodeError): continue
        if isinstance(obj, dict): result.append(obj)
    return result
def unique_board_ids(summaries):
    ids = [s['board_id'] for s in summaries]
    if len(ids) != 2 or len(set(ids)) != 2 or any(not b.startswith('esp32c3-') for b in ids):
        raise ValueError('Two distinct C3 ROM MACs required; repeated runs on one board are not two boards')
    return ids
def audit(directory):
    report = read(directory/'summary.json')
    if report.get('status') != 'complete' or report.get('protocol_sha256') != sha(ROOT/'revision056/protocol.json'):
        raise ValueError('Incomplete or different-protocol campaign')
    for relative, digest in read(directory/'campaign_manifest.json')['sha256'].items():
        path = (directory/relative).resolve()
        if not path.is_relative_to(directory.resolve()) or sha(path) != digest:
            raise ValueError('Campaign file hash mismatch: '+relative)
    from inspect_c3 import parse_identity
    rom_logs = list((directory/'numerics').glob('*/provisioning/rom_identity.log')) + list((directory/'costs').glob('*/provisioning/rom_identity.log'))
    if len(rom_logs) != 124 or any(parse_identity(p.read_text())['board_id'] != report['board_id'] for p in rom_logs):
        raise ValueError('ROM provisioning records do not bind all sessions to this board')
    panel = ROOT/'revision056/inputs/numerics040'
    vectors = read(panel/'panel.json')['vectors']
    golden = {p.stem: read(p) for p in (panel/'golden').glob('*.json')}
    numerical = Counter(); seen = set()
    category = defaultdict(Counter)
    for family in ('lr', 'dt', 'mlp_float', 'mlp_int8'):
        d = directory/'numerics'/family
        replies = [x for x in raw_messages(d) if x.get('event') == 'inference']
        observations = lines(d/'observations.jsonl')
        if replies != [x['response'] for x in observations]:
            raise ValueError('Numerical observations differ from raw serial bytes')
        for o in observations:
            name, i = o['phase'], o['index']
            if (name, i) in seen or o['raw'] != vectors[i]['raw']:
                raise ValueError('Duplicate or substituted numerical input')
            seen.add((name, i)); expected = golden[name]; got = o['response']
            error = abs(float(got['probability'])-expected['probabilities'][i])
            mismatch = got['label'] != expected['labels'][i]
            for c in (numerical, category[vectors[i]['category']]):
                c['inferred_records'] += 1; c['label_mismatches'] += mismatch
                c['probability_tolerance_exceeded'] += error > 2e-6
                if 'q_score' in got:
                    c['integer_codes_compared'] += 1
                    c['integer_code_mismatches'] += got['q_score'] != expected['scores'][i]
    ns = read(directory/'numerics/summary.json')
    if ns.get('board_id') != report['board_id'] or len(seen) != 26624 or any(ns[k] != v for k, v in numerical.items()):
        raise ValueError('Incomplete or inconsistent numerical evidence')
    costs = read(directory/'costs/summary.json')
    if costs['board_id'] != report['board_id'] or costs.get('optimization') != 'O2':
        raise ValueError('Cost board/build mismatch')
    observations = costs['cost_observations']; cells = set()
    for o in observations:
        key = (o['block'], o['family'], o['policy'])
        if key in cells or o.get('transition') != 'A_to_B_reused' or o.get('measured') is not True:
            raise ValueError('Unexpected measured cost cell')
        cells.add(key)
        d = directory/'costs'/f'b{o["block"]:02d}-{o["family"]}-{o["policy"]}'
        messages = raw_messages(d)
        if o['policy'] == 'bundle':
            reply = o['response']; value = reply['timing_us']['total']
            if reply not in messages: raise ValueError('Missing package receipt in raw bytes')
        else:
            begin, ready = o['begin'], o['ready']
            if begin not in messages or ready not in messages: raise ValueError('Missing OTA receipts in raw bytes')
            value = begin['begin_us'] + ready['chunk_sum_us'] + ready['finalize_us']
        if value != o['device_active_us'] or o['board_id'] != report['board_id']:
            raise ValueError('Cost interval or board mismatch')
    expected_cells = {(b, f, p) for b in range(1,11) for f in ('lr','dt','mlp_float','mlp_int8') for p in ('bundle','whole','compressed')}
    if cells != expected_cells or len(observations) != 120:
        raise ValueError('Incomplete cost matrix')
    return report, dict(numerical), dict(category), observations
def main(directories, output):
    ids = unique_board_ids([read(d/'summary.json') for d in directories])
    results = [audit(d) for d in directories]
    output.mkdir(parents=True, exist_ok=False)
    rows=[]; numeric=[]
    for report, counts, categories, observations in results:
        numeric.append(dict(board_id=report['board_id'], counts=counts, categories=categories))
        grouped=defaultdict(list)
        for o in observations: grouped[o['family'],o['policy']].append(o)
        for (family,policy), items in grouped.items():
            rows.append(dict(board_id=report['board_id'], family=family, policy=policy, n=10,
                handler_active_ms_median=statistics.median(o['device_active_us']/1000 for o in items),
                handler_active_ms_min=min(o['device_active_us']/1000 for o in items),
                handler_active_ms_max=max(o['device_active_us']/1000 for o in items),
                usb_total_ms_median=statistics.median(o['host_elapsed_ns']/1e6 for o in items),
                artifact_bytes_median=statistics.median(o['artifact_bytes'] for o in items)))
    with (output/'costs_per_board.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    final=dict(status='verified',board_ids=ids,numerics=numeric,measured_installations=240,
               historical_S3_reference='revision_evidence054/tables/mcu040_cost_medians.csv: O2, A_to_B_reused only',
               board_results_pooled=False, hardware_measurements_created_by_this_auditor=False,
               universal_speedup_claim=False)
    (output/'summary.json').write_text(json.dumps(final,indent=2)+'\n');print(json.dumps(final))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--board',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();main(a.board,a.output)
