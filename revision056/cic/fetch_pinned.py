#!/usr/bin/env python3
"""Re-fetch the exact published 12 CSVs; never select from a newer catalog."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[2]
PUBLISHED=ROOT/'revision056/results/cic'
def sha(p):
    with Path(p).open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def fetch(output):
    output=output.resolve()
    if output.is_relative_to(ROOT): raise ValueError('Keep third-party CSVs outside this repository')
    manifest=json.loads((PUBLISHED/'source_manifest.json').read_text())
    if sha(PUBLISHED/'catalog.json')!=manifest['catalog_sha256']:
        raise ValueError('Published catalog hash mismatch')
    output.mkdir(parents=True,exist_ok=False)
    def one(row):
        name=row['file']
        if Path(name).name!=name: raise ValueError('Unexpected shard path')
        temp=output/(name+'.download');target=output/name
        with urllib.request.urlopen(row['url'],timeout=180) as response,temp.open('xb') as f:
            shutil.copyfileobj(response,f)
        if zipfile.is_zipfile(temp):
            with zipfile.ZipFile(temp) as z:
                entries=[e for e in z.infolist() if not e.is_dir()]
                if len(entries)!=1 or Path(entries[0].filename).name!=name:
                    raise ValueError('Unexpected downloaded container')
                with z.open(entries[0]) as f,target.open('xb') as out: shutil.copyfileobj(f,out)
            temp.unlink()
        else: temp.replace(target)
        if target.stat().st_size!=row['bytes'] or sha(target)!=row['sha256']:
            raise ValueError('Source bytes differ from published experiment: '+name)
        print(json.dumps(dict(verified=name,sha256=row['sha256'])),flush=True)
    with ThreadPoolExecutor(max_workers=3) as pool: list(pool.map(one,manifest['files']))
    for file in ('catalog.json','source_manifest.json'): shutil.copyfile(PUBLISHED/file,output/file)
    print(json.dumps(dict(status='verified',files=len(manifest['files']),version=manifest['version'])))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    fetch(p.parse_args().output)
