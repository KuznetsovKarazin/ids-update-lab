#!/usr/bin/env python3
"""One 70-update journal-rotation pilot, with no fault or power-cut injection.

Requires current completion020 LR/bundle firmware. It preserves a preflight
STATUS, verifies ROM MAC, reprovisions LR factory A, then performs 70 updates.
The signed packages reuse frozen B parameters. Final version is 10070. A fresh
normal campaign explicitly provisions its own starting state afterward.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bootstrap():
    data = json.loads((ROOT/'KIT_MANIFEST.json').read_text(encoding='utf-8'))
    files = data.get('sha256', data.get('files', data))
    for name in ('tools/check_journal_rotation.py', 'tools/run_completion.py', 'tools/campaign_support.py'):
        if files.get(name) != hashlib.sha256((ROOT/name).read_bytes()).hexdigest():
            raise ValueError('Unpinned executable input: ' + name)
    r = load(ROOT/'tools/run_completion.py', 'rotation_campaign_runner')
    s = r.bootstrap()
    c = s.load_context(ROOT, 'lr', 'bundle')
    return r, s, c


def series(s, c):
    directory = c['root']/'artifacts/powercut'
    manifest = s.read_json(directory/'series.json')
    s.typed(manifest, {'runtime_abi':2, 'feature_count':8, 'schema_sha256':c['schema']}, 'series metadata')
    rows = manifest['trials'][:70]
    if len(rows) != 70 or [v['version'] for v in rows] != list(range(10001,10071)):
        raise ValueError('Unexpected journal pilot version allocation')
    result = []
    for row in rows:
        blob = s.confined(directory, row['package']).read_bytes()
        obj = c['package'].verify(blob, c['public'], bytes.fromhex(c['schema']), 8, expected_abi=2)
        if (hashlib.sha256(blob).hexdigest() != row['envelope_sha256'] or
                hashlib.sha256(blob[16:-256]).hexdigest() != row['model_sha256'] or
                obj.version != row['version'] or obj.release != row['release']):
            raise ValueError('Signed rotation package differs from manifest')
        for key in ('schema','means','scales','weights','bias','threshold','runtime_abi'):
            if getattr(obj,key) != getattr(c['models']['B'],key):
                raise ValueError('Rotation packages must reuse frozen B parameters: '+key)
        result.append({'version':obj.version,'release':obj.release,'digest':row['model_sha256'],
                       'package':row['package'],'blob':blob,'model':obj})
    return result


def check_state(reply, s, c, item, sequence, event='status'):
    # Native validation explicitly supplies a native identity; CLI context from
    # load_context always retains ESP32 identity. No response data are rewritten.
    expected = {'event':event,'ready':True,'reason':'ok','version':item['version'],
                'release':item['release'],'bundle_sha256':item['digest'],'selector_sequence':sequence,
                'active_slot':(sequence-1)%2,'policy':'bundle','runtime_abi':2,'pretransform':'log1p',
                'schema':c['schema'],'feature_count':8,'data_origin':'TON_IoT_development',
                'storage_layout':2,'storage_scheme':'journal_dualrail_v1','timing_schema':3,
                'chip':c.get('expected_chip','esp32s3'),
                'build':c['build']['images']['A']['expected_build']}
    s.typed(reply, expected, 'rotation status')
    return reply


def probe(link, evidence, s, c, item, summary):
    raw = c['golden'][0]['raw']
    p, label = c['package'].infer(item['model'], raw)
    reply = link.command('INFER '+','.join(format(float(v),'.9g') for v in raw), {'inference'})
    s.typed(reply, {'event':'inference','version':item['version'],'bundle_sha256':item['digest'],
                   'policy':'bundle','runtime_abi':2,'pretransform':'log1p',
                   'data_origin':'TON_IoT_development'}, 'rotation inference')
    actual = reply.get('probability')
    if type(actual) not in (int,float) or not math.isfinite(actual) or not 0 <= actual <= 1:
        raise RuntimeError('Nonfinite or invalid inference probability')
    match = type(reply.get('label')) is int and reply['label'] == label
    error = abs(actual-p)
    evidence.record({'record_id':c['golden'][0]['id'],'raw':raw,'version':item['version'],
                     'expected':{'probability':p,'label':label},'response':reply,
                     'label_match':match,'probability_abs_error':error}, 'observations')
    summary['inferred_records'] += 1
    summary['label_mismatches'] += int(not match)
    summary['max_probability_abs_error'] = max(summary['max_probability_abs_error'], error)
    if not match or error > s.TOLERANCE:
        raise RuntimeError('Rotation numeric probe differs from frozen reference')


def execute_chain(link, evidence, s, c, rows, summary, initial):
    model = c['models']['A']
    factory = {'version':model.version,'release':model.release,'digest':c['digests']['A'],'model':model}
    check_state(initial, s, c, factory, 1)
    summary['measurement_origin'] = c.get('measurement_origin','actual_mcu')
    probe(link,evidence,s,c,factory,summary)
    for index,item in enumerate(rows,1):
        evidence.phase = f'update_{index:03d}'
        summary['attempted_updates'] = index
        evidence.event('mutation_intent',command_kind='UPDATE',version=item['version'],
                       envelope_sha256=hashlib.sha256(item['blob']).hexdigest(),
                       expected_selector_sequence=index+1,
                       expected_journal_rotation=index in (32,64), physical_power_loss_tested=False)
        reply = link.command('UPDATE '+item['blob'].hex(), {'update'})
        s.typed(reply, {'event':'update','accepted':True,'reason':'ok','ready':True,
                       'version':item['version'],'policy':'bundle'}, 'rotation update')
        timing = s.bundle_timing(reply)
        summary['accepted_updates'] += 1
        status = link.command('STATUS', {'status'})
        check_state(status,s,c,item,index+1)
        evidence.event('accepted_rotation_update',update=index,response=reply,status=status,
                       expected_journal_rotation=index in (32,64),timing_us=timing)
        probe(link,evidence,s,c,item,summary)
        if index in (32,64,70):
            evidence.event('mutation_intent',command_kind='REBOOT',after_update=index,
                           physical_power_loss_tested=False)
            link.allow_reconnect = True
            try:
                reply = link.command('REBOOT', {'reboot'})
                s.typed(reply, {'event':'reboot','fault_kind':'software_restart'}, 'reboot')
                boot = link.receive({'boot'})
                check_state(boot,s,c,item,index+1,'boot')
                after = link.command('STATUS', {'status'})
                check_state(after,s,c,item,index+1)
                probe(link,evidence,s,c,item,summary)
                summary['verified_reboots'] += 1
                evidence.event('rotation_reboot_verified',after_update=index,boot=boot,status=after)
            finally:
                link.allow_reconnect = False
        if index % 10 == 0 or index in (32,64):
            print(f'journal rotation: {index}/70, selector={index+1}',flush=True)
    summary.update(status='complete',final_version=rows[-1]['version'],final_selector_sequence=71,
                   final_active_slot=0,expected_rotations_completed=2)


def fresh_summary():
    return {'stage':'020','command':'journal_rotation','status':'failed','measurement_origin':'not_measured',
            'data_origin':'TON_IoT_development','hardware_access_attempted':False,'accepted_updates':0,
            'attempted_updates':0,'inferred_records':0,'label_mismatches':0,'max_probability_abs_error':0.,
            'verified_reboots':0,'physical_power_loss_tested':False,'energy_measured':False,
            'heldout_detection_quality_measured':False,'faults_injected':False,
            'rotation_evidence_scope':'verified sequence across two capacity boundaries and reboot; erase instructions inferred from pinned firmware, not externally measured'}


def run(a, r, s, c):
    s.board_mac(a.board_id)
    rows = series(s,c)
    out = a.output.resolve(); out.mkdir(parents=True,exist_ok=False)
    summary = fresh_summary(); evidence = link = None
    s.save(out/'protocol.json', {'created_before_hardware':True,'created_utc_ns':time.time_ns(),
        'kit_manifest_sha256':c['kit_manifest_sha256'],'board_id':a.board_id,
        'planned_updates':70,'planned_reboots_after_updates':[32,64,70],
        'provisioning':'explicit factory LR/bundle flash and erase component state',
        'series':[ {k:v for k,v in row.items() if k not in ('blob','model')} for row in rows],
        'physical_power_loss_tested':False,'independent_replicates':1,
        'purpose':'both journal-page boundaries; second rotation erases a previously occupied page'})
    try:
        summary['hardware_access_attempted'] = True
        r.session_preflight(a,s,c,out/'preflight',allow_old=False)
        r.flash_factory(a,out/'provision',s,c)
        session = out/'session'; session.mkdir()
        legacy = r.legacy(c['root']); evidence = legacy.Evidence(session)
        link = legacy.Link(c['serial'],evidence,a.timeout)
        initial = link.open(a.port)
        execute_chain(link,evidence,s,c,rows,summary,initial)
    except BaseException as e:
        summary['error'] = type(e).__name__+': '+str(e)
        raise
    finally:
        if link: link.close()
        if evidence: evidence.close()
        summary['finished_utc_ns'] = time.time_ns()
        s.save(out/'summary.json',summary)
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',required=True);p.add_argument('--board-id',required=True)
    p.add_argument('--output',required=True,type=Path);p.add_argument('--timeout',type=float,default=20)
    a = p.parse_args()
    try:
        if a.timeout <= 0: raise ValueError('timeout must be positive')
        r,s,c = bootstrap(); print(json.dumps(run(a,r,s,c))); return 0
    except Exception as e:
        print('error: '+str(e),file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
