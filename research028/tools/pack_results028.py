#!/usr/bin/env python3
import argparse,hashlib,json
from pathlib import Path
import zipfile

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    root=a.run.resolve();target=a.output.resolve()
    summary=json.loads((root/'summary.json').read_text(encoding='utf-8'))
    if summary.get('stage')!='028' or summary.get('status')!='complete':raise ValueError('Completed stage028 run required')
    manifest=json.loads((root/'evidence_manifest.json').read_text(encoding='utf-8'))
    selected=[]
    for rel,digest in manifest['sha256'].items():
        source=(root/rel).resolve()
        if not source.is_relative_to(root) or sha(source)!=digest:raise ValueError('Evidence hash mismatch: '+rel)
        selected.append((source,rel))
    selected.append((root/'evidence_manifest.json','evidence_manifest.json'))
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for source,rel in selected:z.write(source,root.name+'/'+rel)
    print(json.dumps({'status':'complete','archive':str(target),'sha256':sha(target),'files':len(selected),'sqlite_cache_included':False},ensure_ascii=False))
if __name__=='__main__':main()
