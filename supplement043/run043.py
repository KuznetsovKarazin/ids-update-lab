#!/usr/bin/env python3
"""Frozen-artifact follow-up only. Original software author: Oleksandr Kuznetsov."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ADDED = 'export_per_tensor_recalibrated'


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def under(base, relative):
    base = Path(base).resolve()
    rel = PurePosixPath(relative)
    if rel.is_absolute() or '..' in rel.parts or '\\' in relative:
        raise ValueError('Unsafe manifest path: ' + relative)
    result = (base / relative).resolve()
    if not result.is_relative_to(base):
        raise ValueError('Manifest path escapes root: ' + relative)
    return result


def verify_pins(base, pins):
    for relative, digest in pins.items():
        path = under(base, relative)
        if not path.is_file() or sha(path) != digest:
            raise ValueError('Pinned file missing or changed: ' + str(path))


def check_output(out, protected):
    out = Path(out).resolve()
    if out.exists():
        raise ValueError('Fresh output required; existing evidence is preserved: ' + str(out))
    for item in protected:
        item = Path(item).resolve()
        if out == item or out.is_relative_to(item) or item.is_relative_to(out):
            raise ValueError('Output overlaps protected source/code: ' + str(item))


def inspect(args):
    pins = load(HERE / 'SUPPLEMENT043.json')
    required = {'run043.py', 'numerics043.py'}
    if not required.issubset(pins['sha256']):
        raise ValueError('Supplement manifest omits runnable code')
    verify_pins(HERE, pins['sha256'])
    verify_pins(args.kit, pins['kit_sha256'])
    verify_pins(args.source, pins['source042_sha256'])
    status = load(args.source / 'STATUS042.json')
    if status.get('status') != 'complete' or status.get('future_evaluation_complete') is not True:
        raise ValueError('Source042 is not a completed future evaluation')
    prior = args.prior_run.resolve()
    training = prior / 'training' if (prior / 'training/models').is_dir() else prior
    if not (training / 'models').is_dir():
        raise ValueError('Frozen training models missing: ' + str(training))
    cache = training / 'test_vectors.sqlite'
    if not cache.is_file() or sha(cache) != pins['expected_cache_sha256']:
        raise ValueError('Original future cache missing or changed; no rescan or training will start: ' + str(cache))
    provenance = load(args.source / 'pc/percentile-future/input_provenance.json')
    if provenance['sha256'] != pins['expected_cache_sha256']:
        raise ValueError('Source042 future cache binding differs')
    check_output(args.output, [args.kit, args.source, prior, HERE])
    return {'pins': pins, 'cache': str(cache), 'training': str(training), 'hardware_access_attempted': False}


def compare_tree(old, new, path='root'):
    """Require every old field; permit additive diagnostics, never missing fields."""
    if isinstance(old, dict):
        if not isinstance(new, dict):
            raise ValueError('Changed structure: ' + path)
        for key, value in old.items():
            if key not in new:
                raise ValueError('Missing field: ' + path + '/' + key)
            compare_tree(value, new[key], path + '/' + key)
    elif isinstance(old, list):
        if not isinstance(new, list) or len(old) != len(new):
            raise ValueError('Changed list: ' + path)
        for index, value in enumerate(old):
            compare_tree(value, new[index], path + '/' + str(index))
    elif isinstance(old, (int, float)) and not isinstance(old, bool):
        if not isinstance(new, (int, float)) or isinstance(new, bool) or not math.isclose(old, new, rel_tol=0, abs_tol=1e-12):
            raise ValueError('Changed numeric result: ' + path)
    elif old != new:
        raise ValueError('Changed result: ' + path)


def compare_results(source, future):
    old = load(source / 'pc/percentile-future/evaluation.json')
    new = load(future / 'evaluation.json')
    op = load(source / 'pc/percentile-future/PROTOCOL_LOCK.json')
    np = load(future / 'PROTOCOL_LOCK.json')
    old_names = set(op['models'])
    if len(old_names) != 7 or set(np['models']) != old_names | {ADDED}:
        raise ValueError('Expected seven frozen042 models plus one frozen comparator')
    for name in old_names:
        if op['models'][name]['sha256'] != np['models'][name]['sha256']:
            raise ValueError('Model changed: ' + name)
        compare_tree(op['thresholds'][name], np['thresholds'][name], name + '/threshold')
    if np['thresholds'][ADDED]['q_threshold'] != 22 or np.get('tuning_on_future') is not False:
        raise ValueError('Added comparator must retain frozen q22; tuning prohibited')
    for section in ('weightings', 'by_day_rows', 'by_type_rows'):
        for group, values in new[section].items():
            if set(values) != old_names | {ADDED}:
                raise ValueError('Incomplete eight-model result: ' + section + '/' + group)
    for key in ('rows', 'unique_vectors', 'weightings', 'by_day_rows', 'by_type_rows', 'clipping_on_unique_vectors', 'thresholds_reselected'):
        compare_tree(old[key], new[key], key)
    if new['rows'] != 7462871 or new['unique_vectors'] != 3782505:
        raise ValueError('Future population changed')
    summary = load(future / 'summary.json')
    if summary.get('status') != 'complete' or summary.get('models_evaluated') != 8:
        raise ValueError('Supplement evaluation is incomplete')
    return {'status': 'verified', 'old_models_compared': 7, 'model_hashes_and_thresholds_unchanged': True,
            'old_metrics_unchanged_absolute_tolerance': 1e-12, 'old_raw_clipping_unchanged': True,
            'added_model': ADDED, 'added_frozen_q_threshold': 22,
            'models_retrained': False, 'thresholds_reselected': False}


def launch(argv, logfile, cwd):
    env = dict(os.environ, PYTHONUTF8='1', PYTHONUNBUFFERED='1', PYTHONDONTWRITEBYTECODE='1',
               OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1')
    proc = None
    try:
        with logfile.open('x', encoding='utf-8') as handle:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding='utf-8', errors='replace', bufsize=1)
            for line in proc.stdout:
                print(line, end='', flush=True)
                handle.write(line)
                handle.flush()
            return proc.wait()
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def pack(out):
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = out.parent / (out.name + '-results-' + stamp + '.zip')
    files = sorted(p for p in out.rglob('*') if p.is_file())
    entries = []
    with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in files:
            if path.is_symlink():
                raise ValueError('Refusing symlink in evidence archive')
            rel = path.relative_to(out).as_posix()
            z.write(path, out.name + '/' + rel)
            entries.append({'path': out.name + '/' + rel, 'sha256': sha(path), 'bytes': path.stat().st_size})
        z.writestr('ARCHIVE_MANIFEST.json', json.dumps({'files': entries}, indent=2))
    with zipfile.ZipFile(target) as z:
        if z.testzip() is not None:
            raise ValueError('Archive CRC failed')
    result = {'archive': str(target), 'sha256': sha(target), 'files': len(files), 'bytes': target.stat().st_size}
    save(target.with_suffix('.sha256.json'), result)
    print(json.dumps(result), flush=True)
    return result


def run(args, launcher=launch):
    report = inspect(args)
    out = args.output.resolve()
    pins = report['pins']
    out.mkdir(parents=True, exist_ok=False)
    status = {'schema': 'supplement043_status_v1', 'status': 'started', 'started_utc': utc(),
              'hardware_access_attempted': False, 'all_reviewer_experiments_complete': False,
              'original_author': 'Oleksandr Kuznetsov', 'models_retrained': False,
              'thresholds_reselected': False}
    save(out / 'STATUS043.json', status)
    try:
        for rel in pins['source042_sha256']:
            src = under(args.source, rel)
            dest = under(out / 'source042', rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
        for rel in [*pins['sha256'], 'SUPPLEMENT043.json']:
            dest = under(out / 'supplement_code043', rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(under(HERE, rel), dest)
        save(out / 'INPUT_BINDING043.json', {'source042': str(args.source.resolve()), 'kit': str(args.kit.resolve()),
             'cache': report['cache'], 'cache_sha256': pins['expected_cache_sha256'],
             'supplement_manifest_sha256': sha(HERE / 'SUPPLEMENT043.json'),
             'scope': 'One previously frozen comparator and effective clipping diagnostics; no new fitting or threshold selection'})
        argv = [sys.executable, str(HERE / 'numerics043.py'), 'future', '--root', str(args.kit.resolve()),
                '--prior-run', report['training'], '--output', str(out / 'future')]
        save(out / 'command.json', {'argv': argv})
        rc = launcher(argv, out / 'future043.log', args.kit.resolve())
        if rc:
            raise RuntimeError('Supplement failed; inspect ' + str(out / 'future043.log'))
        comparison = compare_results(args.source, out / 'future')
        verify_pins(args.source, pins['source042_sha256'])
        verify_pins(args.kit, pins['kit_sha256'])
        if sha(Path(report['cache'])) != pins['expected_cache_sha256']:
            raise ValueError('Future cache changed during evaluation')
        save(out / 'COMPARISON042.json', comparison)
        status.update(status='complete', fixed_future_evaluation_complete=True, source042_preserved=True,
                      previous_metrics_verified=True, scientific_results_require_review=True)
        code = 0
    except BaseException as exc:
        status.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
        print('error:', status['error'], file=sys.stderr, flush=True)
        code = 1
    finally:
        status['finished_utc'] = utc()
        save(out / 'STATUS043.json', status)
        try:
            pack(out)
        except Exception as exc:
            print('error: Archive could not be created; evidence remains in ' + str(out) + ': ' + str(exc), file=sys.stderr)
            code = 1
    print(json.dumps(status), flush=True)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path('E:/ids-update-lab'))
    for flag in ('kit', 'source', 'prior-run', 'output'):
        parser.add_argument('--' + flag, type=Path)
    parser.add_argument('--inspect-only', action='store_true')
    args = parser.parse_args()
    args.kit = args.kit or args.workspace / 'revision040-kit'
    args.source = args.source or args.workspace / 'runs/revision039-pc-042'
    args.prior_run = args.prior_run or args.workspace / 'runs/ids-completion-030'
    args.output = args.output or args.workspace / 'runs/revision039-pc-043'
    try:
        if args.inspect_only:
            report = inspect(args)
            print(json.dumps({'status': 'ready', 'cache': report['cache'], 'hardware_access_attempted': False}))
            return 0
        return run(args)
    except Exception as exc:
        print('error:', type(exc).__name__ + ':', str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
