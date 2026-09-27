#!/usr/bin/env python3
"""Frozen stage030 queue: host fitting, MCU checks/costs, continuous CFN analysis.

Run starts from fresh output. Completed fitting may be reused only explicitly,
after every recorded hash is verified. Failed MCU mutations are never retried.
"""
from __future__ import annotations
import argparse
import datetime
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import zipfile

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import hardware030 as hw

def verify_kit():
    manifest=ROOT/'KIT_MANIFEST.json'
    pins=hw.verify_pins(ROOT,'KIT_MANIFEST.json')
    required=['run030.py','tools/hardware030.py','training/run_training030.py','training/model030.py','protocol/coverage_selection.json','hardware_codec/codec030.py','energy/timeline.py','energy/analyze_continuous.py']
    for family in hw.FAMILIES:
        for policy in ('bundle','whole'):required.append(f'prebuilt/{family}_{policy}/ids_update_lab.bin')
    if not set(required).issubset(pins):raise ValueError('Incomplete frozen kit manifest')
    for path in ROOT.rglob('*.py'):
        if '__pycache__' not in path.parts and path.relative_to(ROOT).as_posix() not in pins:raise ValueError('Unpinned executable source: '+str(path))
    return {'kit_manifest_sha256':hw.sha(manifest),'pinned_files':len(pins)}

def dependencies():
    if sys.version_info<(3,11):raise ValueError('Python 3.11 or later required')
    versions={}
    for name in ('numpy','scipy','scikit-learn','cryptography','pyserial','esptool'):
        try:versions[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:raise RuntimeError('Missing dependency '+name+'; install research030/requirements.txt') from exc
    if int(versions['esptool'].split('.')[0])!=4:raise RuntimeError('Frozen CLI requires esptool 4.x; use provided requirements')
    return versions

def source_locations(root,data_root):
    # Cheap discovery for inspect. Training hashes all bytes before fitting.
    entries=hw.read(ROOT/'training/vendor/source_manifest.json')['files'];names=[e['file'] for e in entries]
    roots=[Path(data_root).resolve()] if data_root else []
    if not roots:
        for directory,dirs,files in os.walk(root):
            dirs[:]=[d for d in dirs if d not in {'.venv','.git','node_modules','runs','__pycache__'}]
            if set(names).intersection(files):roots.append(Path(directory))
    matches=[p for p in roots if all((p/n).is_file() for n in names)]
    if len(matches)!=1:raise ValueError('Need exactly one directory with 23 TON CSV; specify --data-root. Found: '+str(matches))
    directory=matches[0]
    for e in entries:
        if (directory/e['file']).stat().st_size!=e['bytes']:raise ValueError('CSV size differs from pinned source: '+e['file'])
    return dict(directory=str(directory),files=len(entries),source_bytes=sum(e['bytes'] for e in entries),full_sha256_check='performed by training before any fitting')

def inspect(args):
    result=dict(status='ready',stage='030',**verify_kit(),dependencies=dependencies(),hardware_access_attempted=False,physical_power_loss_tested=False,plan=dict(families=list(hw.FAMILIES),paired_cost_blocks=hw.BLOCKS,cost_cells=len(hw.cost_plan()),bundle_updates_per_energy_block=hw.BUNDLE_UPDATES,whole_updates_per_energy_block=hw.WHOLE_UPDATES,quiet_seconds_per_update=hw.QUIET_AFTER_UPDATE_SECONDS))
    if getattr(args,'reuse_training',None):
        training=Path(args.reuse_training).resolve();hw.verify_pins(training,'result_manifest.json')
        if hw.read(training/'summary.json').get('status')!='complete':raise ValueError('Explicitly reused training is incomplete')
        lock=hw.read(training/'protocol_lock_before_data_and_predictions.json')
        if lock.get('protocol_sha256')!=hw.sha(ROOT/'protocol/coverage_selection.json'):raise ValueError('Reused training has another frozen temporal protocol')
        expected_code={p.name:hw.sha(p) for p in (ROOT/'training/run_training030.py',ROOT/'training/model030.py',ROOT/'training/vendor/audit_ton_full.py')}
        if lock.get('code_sha256')!=expected_code:raise ValueError('Reused training was produced by different source code')
        result['reused_training']=str(training)
    else:result['sources']=source_locations(Path(args.root).resolve(),args.data_root)
    return result

def run_subprocess(argv,log):
    """Tee text without shell interpolation; partial log remains after failure."""
    log=Path(log);log.parent.mkdir(parents=True,exist_ok=True)
    hw.save(log.with_suffix('.intent.json'),{'argv':argv,'utc_ns':time.time_ns()})
    with log.open('x',encoding='utf-8') as out:
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',bufsize=1)
        try:
            for line in p.stdout:print(line,end='',flush=True);out.write(line);out.flush()
            status=p.wait()
        except BaseException:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            raise
    hw.save(log.with_suffix('.result.json'),{'returncode':status,'log_sha256':hw.sha(log),'utc_ns':time.time_ns()})
    if status:raise RuntimeError('Subprocess failed; inspect '+str(log))

def pack(run,output):
    run,output=Path(run).resolve(),Path(output).resolve()
    if output.exists():raise FileExistsError('Archive already exists: '+str(output))
    if not run.is_dir():raise ValueError('Run directory not found')
    output.parent.mkdir(parents=True,exist_ok=True)
    files=[];excluded=[]
    for p in sorted(run.rglob('*')):
        if not p.is_file() or p==output:continue
        rel=p.relative_to(run).as_posix()
        if p.is_symlink():raise ValueError('Symlink is not allowed in run evidence')
        if '__pycache__' in p.parts or p.suffix in ('.pyc','.sqlite','.sqlite-wal','.sqlite-shm') or p.name.startswith('PUBLIC_DEVELOPMENT_ONLY_private') or p.name.endswith('.zip'):
            excluded.append(dict(path=rel,bytes=p.stat().st_size,reason='reproducible cache or redundant archive/private-key copy'));continue
        files.append((p,run.name+'/'+rel))
    manifest={'schema':1,'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sha256':{rel:hw.sha(p) for p,rel in files},'excluded':excluded,'note':'Original per-phase manifests may also enumerate excluded rebuildable caches; this archive manifest binds the delivered files.'}
    try:
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
            for p,rel in files:z.write(p,rel)
            z.writestr('ARCHIVE_MANIFEST.json',json.dumps(manifest,indent=2,allow_nan=False)+'\n')
        with zipfile.ZipFile(output) as z:
            if z.testzip() is not None:raise RuntimeError('ZIP CRC verification failed')
        result={'archive':str(output),'bytes':output.stat().st_size,'sha256':hw.sha(output),'files':len(files),'excluded_files':len(excluded)}
        hw.save(output.with_suffix('.sha256.json'),result);return result
    except BaseException:
        if output.exists():output.rename(output.with_suffix(output.suffix+'.incomplete'))
        raise

def analyze(run,cfn=None,output=None):
    run=Path(run).resolve();out=Path(output).resolve() if output else run/'analysis'
    out.mkdir(parents=True,exist_ok=False)
    result={'stage':'030','status':'failed','energy_measured':False,'physical_power_loss_tested':False}
    try:
        hw.analyze_costs(run/'hardware',out/'costs.json')
        if cfn:
            cfn=Path(cfn).resolve()
            if not cfn.is_file() or cfn.suffix.lower()!='.cfn':raise ValueError('Provide original FNB58 .cfn file')
            shutil.copyfile(cfn,out/'continuous.cfn')
            argv=[sys.executable,str(ROOT/'energy/analyze_continuous.py'),'--cfn',str(out/'continuous.cfn'),'--windows',str(run/'hardware/energy/energy_windows.json'),'--output',str(out/'energy')]
            run_subprocess(argv,out/'energy-analysis.log')
            report=hw.read(out/'energy/summary.json')
            result['energy_measured']=bool(report.get('energy_measured',False));result['energy_analysis']=report
        else:result['energy_analysis_pending']=bool((run/'hardware/energy/energy_windows.json').is_file())
        result['status']='complete'
    except BaseException as exc:
        result['error']=type(exc).__name__+': '+str(exc);raise
    finally:hw.save(out/'summary.json',result);hw.pins(out)
    return result

def run(args):
    preflight=inspect(args)
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False)
    result=dict(stage='030',status='failed',physical_power_loss_tested=False,energy_measured=False,started_utc_ns=time.time_ns(),hardware_access_attempted=False)
    hw.save(out/'preflight.json',preflight)
    shutil.copyfile(ROOT/'KIT_MANIFEST.json',out/'KIT_MANIFEST_at_start.json')
    shutil.copytree(ROOT/'protocol',out/'protocol')
    hw.save(out/'run_intent.json',dict(arguments=vars(args),python=sys.version,platform=platform.platform(),**result))
    try:
        if args.reuse_training:
            training=Path(args.reuse_training).resolve()
            hw.save(out/'explicit_training_reuse.json',dict(path=str(training),manifest_sha256=hw.sha(training/'result_manifest.json')))
            # Preserve reviewed scientific outputs without duplicating large DBs.
            shutil.copytree(training,out/'training',ignore=shutil.ignore_patterns('*.sqlite','*.sqlite-wal','*.sqlite-shm','__pycache__'))
            # Hardware preparation uses the original complete, hash-verified data.
        else:
            training=out/'training'
            argv=[sys.executable,str(ROOT/'training/run_training030.py'),'--root',str(Path(args.root).resolve()),'--output',str(training)]
            if args.data_root:argv+=['--data-root',str(Path(args.data_root).resolve())]
            run_subprocess(argv,out/'logs/training.log')
        print('Preparing all signed bundles and patched firmware images before measurement...',flush=True)
        hw.prepare(training,out/'artifacts')
        result['hardware_access_attempted']=True
        measured=hw.hardware(args,out/'artifacts',out/'hardware');result['hardware_summary']=measured
        cfn=args.cfn
        if not args.no_energy and not cfn and not args.defer_energy_analysis:
            print('\nСохраните непрерывную запись FNB58 в формате CFN.\nВведите полный путь к файлу для анализа сейчас; Enter — сохранить результаты и проанализировать CFN позже.',flush=True)
            cfn=input('CFN: ').strip().strip('"') or None
        analysis=analyze(out,cfn)
        result.update(status='complete',energy_measured=analysis['energy_measured'],energy_analysis_pending=analysis.get('energy_analysis_pending',False))
    except BaseException as exc:
        result['error']=type(exc).__name__+': '+str(exc)
        raise
    finally:
        result['finished_utc_ns']=time.time_ns();hw.save(out/'summary.json',result)
        # Preserve partial results too. Packing errors must not mask the original.
        try:
            archive=pack(out,out.parent/(out.name+'-results.zip'));print(json.dumps(archive),flush=True)
        except Exception as exc:print('Archive was not created: '+str(exc),file=sys.stderr)
    print(json.dumps(result),flush=True);return result

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    for name in ('inspect','run'):
        q=sub.add_parser(name);q.add_argument('--root',default=str(ROOT.parent));q.add_argument('--data-root');q.add_argument('--reuse-training')
        if name=='run':
            q.add_argument('--output',required=True);q.add_argument('--port',default='COM13');q.add_argument('--board-id',default='esp32s3-a0f262ebb558');q.add_argument('--timeout',type=float,default=20)
            q.add_argument('--no-energy',action='store_true',help='Run same paced MCU queue without FNB58 capture markers')
            q.add_argument('--energy-recording-started',action='store_true',help='Recording already started; skip the GUI readiness prompt')
            q.add_argument('--defer-energy-analysis',action='store_true',help='Do not wait for the CFN filename at the end; archive hardware results automatically for later analysis')
            q.add_argument('--cfn',help='Original recording to analyze after MCU queue')
    q=sub.add_parser('analyze');q.add_argument('--run',required=True);q.add_argument('--cfn');q.add_argument('--output')
    q=sub.add_parser('pack');q.add_argument('--run',required=True);q.add_argument('--output',required=True)
    a=p.parse_args(argv)
    try:
        if a.command=='inspect':value=inspect(a)
        elif a.command=='run':
            hw.board_mac(a.board_id)
            if not __import__('math').isfinite(a.timeout) or a.timeout<=0:raise ValueError('Positive finite timeout required')
            value=run(a)
        elif a.command=='analyze':verify_kit();value=analyze(a.run,a.cfn,a.output)
        else:value=pack(a.run,a.output)
        if a.command!='run':print(json.dumps(value,ensure_ascii=False),flush=True)
        return 0
    except (Exception,KeyboardInterrupt) as exc:p.exit(1,f'error: {type(exc).__name__}: {exc}\n')

if __name__=='__main__':raise SystemExit(main())
