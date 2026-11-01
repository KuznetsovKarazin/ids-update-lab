#!/usr/bin/env python3
"""Retrieve the outcome-independent 12-shard CICIoT2023 selection.

Raw third-party CSVs stay outside the Git repository. The saved catalog,
download receipts and file hashes identify the exact experimental input.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
BASE = 'https://www.kaggle.com/api/v1/datasets/'
MIRROR = 'akashdogra/cic-iot-2023'


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''):
            h.update(b)
    return h.hexdigest()


def get_json(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        return json.load(response)


def select_files(files, count=12):
    names = [f['name'] for f in files if f['name'].lower().endswith('.csv')]
    if len(names) != len(set(names)) or len(names) < count:
        raise ValueError('incomplete or duplicate CSV catalog')
    return sorted(names, key=lambda n: hashlib.sha256(('ids056-source-v1:' + n).encode()).hexdigest())[:count]


def acquire(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    protocol = json.loads((ROOT / 'revision056/protocol.json').read_text())
    metadata = get_json(BASE + 'view/' + MIRROR)
    version = metadata.get('currentVersionNumber', metadata.get('versionNumber'))
    if not isinstance(version, int) or version < 1:
        raise ValueError('mirror metadata does not identify a dataset version')
    files, token, seen = [], None, set()
    while True:
        query = {'datasetVersionNumber': version, 'pageSize': 1000}
        if token:
            query['pageToken'] = token
        page = get_json(BASE + 'list/' + MIRROR + '?' + urllib.parse.urlencode(query))
        files.extend(page.get('datasetFiles', []))
        token = page.get('nextPageTokenNullable', page.get('nextPageToken'))
        if not token:
            break
        if token in seen:
            raise ValueError('catalog pagination repeated a token')
        seen.add(token)
    catalog = [{'name': x['name'], 'bytes': x['totalBytes']} for x in files]
    chosen = select_files(catalog, protocol['external_data']['source_csv_shards'])
    catalog_doc = {'mirror': MIRROR, 'version': version, 'files': sorted(catalog, key=lambda x: x['name']),
                   'selection_rule': protocol['external_data']['source_selection'], 'selected': chosen,
                   'protocol_sha256': digest(ROOT / 'revision056/protocol.json'),
                   'predictions_examined_for_selection': False}
    (output / 'catalog.json').write_text(json.dumps(catalog_doc, indent=2) + '\n')
    by_name = {x['name']: x for x in catalog}

    def download(name):
        if Path(name).name != name:
            raise ValueError('expected flat CSV shard names')
        url = BASE + 'download/' + MIRROR + '/' + urllib.parse.quote(name) + '?datasetVersionNumber=' + str(version)
        temp, target = output / (name + '.download'), output / name
        with urllib.request.urlopen(url, timeout=180) as response, temp.open('xb') as stream:
            shutil.copyfileobj(response, stream, 1 << 20)
        if zipfile.is_zipfile(temp):
            with zipfile.ZipFile(temp) as z:
                members = [x for x in z.infolist() if not x.is_dir()]
                if len(members) != 1 or Path(members[0].filename).name != name:
                    raise ValueError('unexpected members in downloaded shard archive')
                with z.open(members[0]) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
            temp.unlink()
        else:
            temp.replace(target)
        if target.stat().st_size != by_name[name]['bytes']:
            raise ValueError('download size mismatch: ' + name)
        row = {'file': name, 'bytes': target.stat().st_size, 'sha256': digest(target), 'url': url}
        print(json.dumps({'downloaded': name, 'bytes': row['bytes']}), flush=True)
        return row

    with ThreadPoolExecutor(max_workers=3) as pool:
        receipts = list(pool.map(download, chosen))
    manifest = {'dataset': 'CICIoT2023', 'mirror': MIRROR, 'version': version,
                'provider_url': protocol['external_data']['provider_url'],
                'catalog_sha256': digest(output / 'catalog.json'),
                'protocol_sha256': catalog_doc['protocol_sha256'],
                'files': sorted(receipts, key=lambda x: x['file'])}
    (output / 'source_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory outside the repository')
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT):
        parser.error('store third-party raw CSVs outside the repository')
    m = acquire(args.output)
    print(json.dumps({'status': 'downloaded', 'files': len(m['files']), 'version': m['version']}))
