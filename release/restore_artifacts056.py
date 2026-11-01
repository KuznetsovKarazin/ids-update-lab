#!/usr/bin/env python3
"""Restore hash-pinned public evidence/prebuilts. Python standard library only.

No serial port is opened. Existing different files are never overwritten.
Repository chunks are ordinary Git files, not LFS pointers or private URLs.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT/'release/artifacts056/manifest.json'

def sha(p):
    with Path(p).open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()

def safe(root, relative):
    parts=PurePosixPath(relative).parts
    if not parts or relative.startswith('/') or '\\' in relative or '..' in parts or ':' in relative:
        raise ValueError('Unsafe archive path: '+relative)
    path=(root/relative).resolve()
    if not path.is_relative_to(root.resolve()): raise ValueError('Path escapes destination')
    return path

def write_stream(root, relative, stream, expected=None, size=None):
    path=safe(root,relative)
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as f:
        temporary=Path(f.name)
        shutil.copyfileobj(stream,f)
    try:
        actual=sha(temporary)
        if expected is not None and actual!=expected: raise ValueError('Restored content hash mismatch')
        if size is not None and temporary.stat().st_size!=size: raise ValueError('Restored size mismatch')
        if path.exists():
            if sha(path)!=actual: raise FileExistsError('Different existing file: '+str(path))
        else: temporary.replace(path)
    finally: temporary.unlink(missing_ok=True)

def restore(name, record, destination, cache, download=False, ref='main', assemble_only=False):
    cache.mkdir(parents=True,exist_ok=True)
    archive=cache/record['file']
    if not archive.is_file() or sha(archive)!=record['sha256']:
        with tempfile.NamedTemporaryFile(dir=cache,delete=False) as out:
            temp=Path(out.name)
            try:
                for part in record['parts']:
                    p=ROOT/part['path']
                    if not p.exists():
                        if not download: raise FileNotFoundError(str(p)+'; use --download or clone all repository files')
                        p=cache/Path(part['path']).name
                        url='https://raw.githubusercontent.com/KuznetsovKarazin/ids-update-lab/'+ref+'/'+part['path']
                        with urllib.request.urlopen(url,timeout=120) as response:
                            write_stream(cache,p.name,response,part['sha256'],part['bytes'])
                    if p.stat().st_size!=part['bytes'] or sha(p)!=part['sha256']:
                        raise ValueError('Archive part hash mismatch: '+str(p))
                    with p.open('rb') as source: shutil.copyfileobj(source,out)
                out.flush()
                if temp.stat().st_size!=record['bytes'] or sha(temp)!=record['sha256']:
                    raise ValueError('Assembled archive hash mismatch')
            except BaseException:
                temp.unlink(missing_ok=True);raise
        if archive.exists(): raise FileExistsError('Different cached archive: '+str(archive))
        temp.replace(archive)
    if assemble_only:
        return dict(artifact=name,status='assembled',archive=str(archive),sha256=record['sha256'])
    destination.mkdir(parents=True,exist_ok=True)
    count=0
    if record['format']=='zip':
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.is_dir(): continue
                with z.open(info) as stream: write_stream(destination,info.filename,stream,size=info.file_size)
                count+=1
    else:
        with tarfile.open(archive,'r:xz') as tar:
            if record['format']=='content-addressed-preserved-files-v1':
                inventory=json.load(tar.extractfile('PUBLIC_EVIDENCE_MANIFEST.json'))
                if inventory.get('format')!=record['format']: raise ValueError('Archive format mismatch')
                # Extract each object once, then expand exact original paths.
                with tempfile.TemporaryDirectory(dir=cache) as temp:
                    object_root=Path(temp)
                    for item in tar:
                        if item.name=='PUBLIC_EVIDENCE_MANIFEST.json': continue
                        if not item.isfile() or not item.name.startswith('objects/'):
                            raise ValueError('Unexpected content-addressed member')
                        digest=item.name.removeprefix('objects/')
                        if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
                            raise ValueError('Invalid object digest')
                        write_stream(object_root,digest,tar.extractfile(item),digest,item.size)
                    for item in inventory['files']:
                        with (object_root/item['sha256']).open('rb') as stream:
                            write_stream(destination,item['path'],stream,item['sha256'],item['bytes'])
                        count+=1
                import io
                raw=json.dumps(inventory,sort_keys=True,indent=2).encode()+b'\n'
                write_stream(destination,'_provenance056/'+name+'.json',io.BytesIO(raw))
            elif record['format']=='tar.xz':
                for item in tar:
                    if item.isdir(): continue
                    if not item.isfile(): raise ValueError('Links are not allowed in payload archives')
                    write_stream(destination,item.name,tar.extractfile(item),size=item.size);count+=1
            else: raise ValueError('Unknown archive format')
    return dict(artifact=name,status='restored',files=count,destination=str(destination),sha256=record['sha256'])

def main():
    registry=json.loads(REGISTRY.read_text())
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifact',action='append',choices=['all',*registry['artifacts']],required=True)
    p.add_argument('--destination',type=Path,required=True)
    p.add_argument('--cache',type=Path,default=ROOT.parent/'ids056-archive-cache')
    p.add_argument('--download',action='store_true');p.add_argument('--ref',default='main')
    p.add_argument('--assemble-only',action='store_true')
    a=p.parse_args();names=list(registry['artifacts']) if 'all' in a.artifact else a.artifact
    for name in names:
        print(json.dumps(restore(name,registry['artifacts'][name],a.destination.resolve(),a.cache.resolve(),a.download,a.ref,a.assemble_only)),flush=True)
if __name__=='__main__': main()
