#!/usr/bin/env python3
"""Resume only the failed future evaluation. Original author: Oleksandr Kuznetsov."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
COMPLETED = ('temporal-plan', 'temporal-runs', 'threshold')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(4 << 20), b''):
            h.update(block)
    return h.hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def under(base, relative):
    rel = PurePosixPath(relative)
    if rel.is_absolute() or '..' in rel.parts or '\\' in relative:
        raise ValueError('Unsafe manifest path: ' + relative)
    p = (base / relative).resolve()
    if not p.is_relative_to(base.resolve()):
        raise ValueError('Manifest path escapes directory: ' + relative)
    return p


def excluded_cache(path):
    return any(s in path.name for s in ('.sqlite', '.db-wal', '.db-shm')) or path.suffix.lower() == '.zip'


def inventory(directory):
    result, excluded = {}, []
    for base, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in {'.git', 'node_modules', '__pycache__'} and not d.startswith('.venv'))
        for name in sorted(files):
            p = Path(base) / name
            if p.is_symlink():
                raise ValueError('Symlink not allowed: ' + str(p))
            if p.suffix.lower() in {'.pyc', '.pyo'}:
                continue
            rel = p.relative_to(directory).as_posix()
            if excluded_cache(p):
                excluded.append({'path': rel, 'bytes': p.stat().st_size, 'reason': 'reconstructible_database_cache_or_nested_archive'})
            else:
                result[rel] = sha(p)
    return result, excluded


def verify_source(source, pins):
    actual, excluded = inventory(source)
    expected = pins['sha256']
    if actual != expected:
        differences = sorted(k for k in set(actual) | set(expected) if actual.get(k) != expected.get(k))
        raise ValueError('Source041 changed or incomplete: ' + ', '.join(differences[:10]))
    receipts = {}
    for name in COMPLETED:
        receipt = load(source / 'steps' / (name + '.json'))
        if receipt.get('name') != name or receipt.get('status') != 'complete' or receipt.get('returncode') != 0:
            raise ValueError('Completed source step not confirmed: ' + name)
        product = source / 'pc' / name
        for relative, digest in receipt['outputs_sha256'].items():
            p = under(product, relative)
            if not p.is_file() or sha(p) != digest:
                raise ValueError('Source step output changed: ' + name + '/' + relative)
        log = source / 'logs' / (name + '.log')
        if sha(log) != receipt['log_sha256']:
            raise ValueError('Source log changed: ' + name)
        receipts[name] = {'status': 'verified_import', 'receipt_sha256': sha(source / 'steps' / (name + '.json')),
                          'output_files': len(receipt['outputs_sha256']), 'source_product': str(product)}
    failed = load(source / 'steps/percentile-future.json')
    failure = load(source / 'pc/percentile-future/summary.json')
    if failed.get('status') != 'failed' or failed.get('returncode') == 0 or failure.get('error') != 'Python integer 453 out of bounds for uint8':
        raise ValueError('This recovery is bound to the recorded uint8 failure only')
    return actual, excluded, receipts


def verify_patch():
    manifest = load(HERE / 'PATCH042.json')
    for relative, digest in manifest['sha256'].items():
        p = under(HERE, relative)
        if not p.is_file() or sha(p) != digest:
            raise ValueError('Recovery package changed: ' + relative)
    for required in ('recover_pc042.py', 'run_numerics042.py', 'expected_source041.json'):
        if required not in manifest['sha256']:
            raise ValueError('Missing recovery package pin: ' + required)
    return manifest


def inspect_recovery(args):
    patch = verify_patch()
    source, kit, out = args.source.resolve(), args.kit.resolve(), args.output.resolve()
    if not source.is_dir() or not kit.is_dir():
        raise ValueError('Source041 and revision040-kit must already exist')
    for protected in (source, kit, HERE):
        if out == protected or out.is_relative_to(protected) or protected.is_relative_to(out):
            raise ValueError('Output must be separate from source and code directories')
    manifest_path = kit / 'revision039/DELIVERY_MANIFEST.json'
    if sha(manifest_path) != patch['original_delivery_manifest_sha256']:
        raise ValueError('Original kit delivery manifest differs')
    delivery = load(manifest_path)
    for relative, digest in delivery['sha256'].items():
        p = under(kit, relative)
        if not p.is_file() or sha(p) != digest:
            raise ValueError('Original kit changed: ' + relative)
    original_runner = kit / 'revision039/numerics/run_numerics039.py'
    coordinator = kit / 'revision039/run_revision039.py'
    if sha(original_runner) != patch['original_runner_sha256'] or sha(coordinator) != patch['coordinator_sha256']:
        raise ValueError('Original runner/coordinator differs')
    pins = load(HERE / 'expected_source041.json')
    source_hashes, excluded, receipts = verify_source(source, pins)
    campaign = load(source / 'campaign.json')
    if campaign['delivery']['manifest_sha256'] != patch['original_delivery_manifest_sha256']:
        raise ValueError('Source041 was produced by another kit')
    prior = args.prior_run.resolve() if args.prior_run else Path(campaign['prior_training'])
    data = args.data_root.resolve() if args.data_root else Path(campaign['ton_directory'])
    return {'schema': 'recovery042_inspection_v1', 'source': str(source), 'kit': str(kit), 'output': str(out),
            'source_files_sha256': source_hashes, 'excluded_source_files_present': excluded,
            'excluded_source_files_recorded_in_archive': pins.get('excluded', []), 'imports': receipts,
            'prior_training': str(prior), 'ton_directory': str(data), 'patch_manifest_sha256': sha(HERE / 'PATCH042.json'),
            'original_runner_sha256': sha(original_runner), 'patched_runner_sha256': sha(HERE / 'run_numerics042.py'),
            'original_delivery_manifest_sha256': sha(manifest_path), 'hardware_access_attempted': False,
            'original_author': 'Oleksandr Kuznetsov'}


def load_coordinator(kit):
    spec = importlib.util.spec_from_file_location('original_coordinator_for_archive042', kit / 'revision039/run_revision039.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def verify_future_binding(source, product):
    old = load(source / 'pc/percentile-future/PROTOCOL_LOCK.json')
    new = load(product / 'PROTOCOL_LOCK.json')
    fields = ('command', 'thresholds', 'percentile', 'tuning_on_future',
              'expected_future_rows', 'expected_future_unique_vectors')
    for field in fields:
        if field not in old or field not in new or old[field] != new[field]:
            raise RuntimeError('Future protocol changed: ' + field)
    old_models = {k: v['sha256'] for k, v in old['models'].items()}
    new_models = {k: v['sha256'] for k, v in new['models'].items()}
    if old_models != new_models:
        raise RuntimeError('Future model identities changed')


def launch_future(argv, log, kit):
    env = dict(os.environ, PYTHONUTF8='1', PYTHONUNBUFFERED='1', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1')
    process = None
    try:
        with log.open('x', encoding='utf-8') as handle:
            process = subprocess.Popen(argv, cwd=kit, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding='utf-8', errors='replace', bufsize=1)
            for line in process.stdout:
                print(line, end='', flush=True)
                handle.write(line)
                handle.flush()
            return process.wait()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run(args, launcher=launch_future):
    out, source, kit = args.output.resolve(), args.source.resolve(), args.kit.resolve()
    if out.exists():
        raise ValueError('Fresh output required; existing evidence will not be changed: ' + str(out))
    report = inspect_recovery(args)
    prior = Path(report['prior_training'])
    if not ((prior / 'models').is_dir() or (prior / 'training/models').is_dir()):
        raise ValueError('Original frozen training models are unavailable: ' + str(prior))
    coordinator = load_coordinator(kit)
    initialized = False
    status = {'schema': 'recovery042_status_v1', 'status': 'started', 'started_utc': utc(),
              'pc_execution_complete': False, 'imported_completed_steps': list(COMPLETED),
              'future_evaluation_complete': False, 'source_evidence_preserved': False,
              'hardware_access_attempted': False, 'all_reviewer_experiments_complete': False,
              'original_author': 'Oleksandr Kuznetsov'}
    receipt = None
    try:
        out.mkdir(parents=True, exist_ok=False)
        initialized = True
        save(out / 'RECOVERY_BINDING042.json', report)
        save(out / 'STATUS042.json', status)
        for relative, digest in report['source_files_sha256'].items():
            src = under(source, relative)
            dst = under(out / 'source_evidence041', relative)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            if sha(dst) != digest:
                raise RuntimeError('Source copy mismatch: ' + relative)
        save(out / 'imports041.json', report['imports'])
        # Bundle exactly the recovery code used, not a mutable checkout snapshot.
        for relative in load(HERE / 'PATCH042.json')['sha256']:
            dest = under(out / 'recovery_code042', relative)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(under(HERE, relative), dest)
        shutil.copy2(HERE / 'PATCH042.json', out / 'recovery_code042/PATCH042.json')
        status['source_evidence_preserved'] = True
        product = out / 'pc/percentile-future'
        log = out / 'logs/percentile-future042.log'
        log.parent.mkdir(parents=True, exist_ok=True)
        argv = [sys.executable, str(HERE / 'run_numerics042.py'), 'future', '--root', str(kit),
                '--prior-run', report['prior_training'], '--data-root', report['ton_directory'], '--output', str(product)]
        receipt = {'name': 'percentile-future042', 'status': 'started', 'started_utc': utc(), 'argv': argv,
                   'product': str(product), 'script_sha256': sha(HERE / 'run_numerics042.py')}
        save(out / 'steps/percentile-future042.json', receipt)
        print('Verified source041: ' + str(len(report['source_files_sha256'])) + ' files; three completed steps imported.', flush=True)
        print('START percentile-future042 (no retraining; no MCU access)', flush=True)
        code = launcher(argv, log, kit)
        receipt['returncode'] = code
        if code != 0:
            raise RuntimeError('Future evaluation failed; inspect ' + str(log))
        result = load(product / 'summary.json')
        if result.get('status') != 'complete' or result.get('command') != 'future' or result.get('hardware_access_attempted') is not False:
            raise RuntimeError('Future evaluation did not confirm completion')
        verify_future_binding(source, product)
        receipt['outputs_sha256'] = inventory(product)[0]
        receipt['status'] = 'complete'
        # Reverify original source after computation; originals are never written.
        verify_source(source, load(HERE / 'expected_source041.json'))
        status.update(status='complete', pc_execution_complete=True, future_evaluation_complete=True,
                      scientific_results_require_review=True)
        return status
    except BaseException as exc:
        status.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
        if receipt is not None:
            receipt.update(status='failed', error=status['error'])
        raise
    finally:
        if initialized:
            status['finished_utc'] = utc()
            if receipt is not None:
                receipt['finished_utc'] = utc()
                log = out / 'logs/percentile-future042.log'
                if log.is_file():
                    receipt['log_sha256'] = sha(log)
                save(out / 'steps/percentile-future042.json', receipt)
            save(out / 'STATUS042.json', status)
            try:
                print(json.dumps(coordinator.pack(out), ensure_ascii=False), flush=True)
            except Exception as exc:
                print('Archive error; results retained: ' + str(exc), file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path('E:/ids-update-lab'))
    parser.add_argument('--kit', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--prior-run', type=Path)
    parser.add_argument('--data-root', type=Path)
    parser.add_argument('--inspect-only', action='store_true')
    args = parser.parse_args(argv)
    args.kit = args.kit or args.workspace / 'revision040-kit'
    args.source = args.source or args.workspace / 'runs/revision039-pc-041'
    args.output = args.output or args.workspace / 'runs/revision039-pc-042'
    try:
        if args.inspect_only:
            info = inspect_recovery(args)
            result = {k: v for k, v in info.items() if k != 'source_files_sha256'}
            result.update(status='verified', source_files=len(info['source_files_sha256']))
        else:
            result = run(args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print('error: ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
