#!/usr/bin/env python3
"""Developer-only integration using SYNTHETIC fitted models. Never touches a board."""
from pathlib import Path
import hashlib,importlib.util,json,os,shutil,struct,subprocess,sys
import numpy as np
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'training'));sys.path.insert(0,str(ROOT/'hardware_codec'));sys.path.insert(0,str(ROOT/'tools'))
import hardware030 as hw
import codec030 as codec
import model030 as ref

def main():
 source=Path(sys.argv[1]);out=Path(sys.argv[2]);target=Path(sys.argv[3]);work=out.parent/(out.name+'-fixture')
 shutil.copytree(source,work);summary=hw.read(work/'summary.json');summary.update(status='complete',validation_only_synthetic=True,scientific_full_result=False,hardware_access_attempted=False);hw.save(work/'summary.json',summary);hw.pins(work,'result_manifest.json')
 artifacts=hw.prepare(work,out,allow_validation=True);hw.verify_pins(out)
 if not artifacts['validation_only_synthetic']:raise AssertionError('Missing validation provenance')
 report={'status':'running','validation_only_synthetic':True,'scientific_full_result':False,'measurement_origin':'host_software_integration','hardware_access_attempted':False,'envelopes_verified':0,'images_verified':0,'negative_contracts_verified':0,'comparisons':[]}
 for family,details in artifacts['families'].items():
  for v,data in details['versions'].items():
   blob=(out/data['path']).read_bytes();meta=codec.envelope_metadata(blob)
   if meta['version']!=int(v) or hashlib.sha256(blob).hexdigest()!=data['envelope_sha256']:raise AssertionError('Envelope metadata mismatch')
   report['envelopes_verified']+=1
  bad=(out/details['bad_contract']).read_bytes();plen=struct.unpack_from('<I',bad,8)[0];payload=bad[16:16+plen]
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding
  codec.key().public_key().verify(bad[16+plen:],payload,padding.PKCS1v15(),hashes.SHA256())
  if payload[24:56]==codec.SCHEMA:raise AssertionError('Bad contract not changed')
  report['negative_contracts_verified']+=1
  for policy,pdata in details['policies'].items():
   for v,image in pdata['images'].items():
    path=out/image['path'];blob=path.read_bytes();meta=codec.verify_image(blob);envelope=(out/details['versions'][v]['path']).read_bytes()
    if meta['version']!=int(v) or blob.count(envelope)!=1 or hashlib.sha256(blob).hexdigest()!=image['sha256']:raise AssertionError('Patched image binding mismatch')
    if 'ota' in image:
     codec.key().public_key().verify(bytes.fromhex(image['ota']['signature_hex']),bytes.fromhex(image['ota']['metadata_hex']),padding.PKCS1v15(),hashes.SHA256())
    report['images_verified']+=1
 core=ROOT/'firmware/components/ids_core';exe=out/'native_validation'
 command=['g++','-std=c++17','-O1','-g','-ffp-contract=off','-fsanitize=address,undefined','-fno-omit-frame-pointer','-no-pie','-I',str(core/'include'),str(ROOT/'validation/native030.cpp'),*[str(core/n) for n in ('ids_core.cpp','ids_tree.cpp','ids_mlp.cpp')],'-lcrypto','-o',str(exe)]
 subprocess.run(command,check=True,capture_output=True)
 env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1'}
 for modelpath in sorted((work/'models').glob('*.json')):
  model=hw.read(modelpath);golden=hw.read(work/'hardware_vectors'/modelpath.name);raw=np.asarray(golden['raw'],'<f4');p,y=ref.predict(model,raw)
  envelope=out/'native_model.sids';envelope.write_bytes(codec.sign_envelope(model,77,'native030'))
  result=subprocess.run([str(exe),str(envelope),str(out/'public.pem')],input=raw.tobytes(),capture_output=True,timeout=60,env=env)
  if result.returncode:raise RuntimeError('Native failed '+modelpath.name+':'+result.stderr.decode())
  rows=[json.loads(line) for line in result.stdout.splitlines()]
  if len(rows)!=len(raw) or not all(r['ok'] for r in rows):raise AssertionError('Native invalid result '+modelpath.name)
  got=np.array([r['p'] for r in rows]);labels=np.array([r['label'] for r in rows]);error=float(np.max(abs(got-p)));mismatch=int((labels!=y).sum())
  report['comparisons'].append({'model':modelpath.stem,'rows':len(raw),'label_mismatches':mismatch,'max_probability_abs_error':error})
  if error>2e-6 or mismatch:raise AssertionError('Native parity mismatch '+modelpath.name+':'+str(report['comparisons'][-1]))
 report.update(status='complete',native_compiler_flags=command[:9],sanitizers=['address','undefined'],leak_sanitizer='disabled: execution environment ptrace',total_native_inferences=sum(r['rows'] for r in report['comparisons']),label_mismatches=sum(r['label_mismatches'] for r in report['comparisons']))
 paths=[Path(__file__),ROOT/'training/model030.py',ROOT/'training/run_training030.py',ROOT/'tools/hardware030.py',ROOT/'hardware_codec/codec030.py',ROOT/'validation/native030.cpp',*[core/n for n in ('ids_core.cpp','ids_tree.cpp','ids_mlp.cpp')]]
 report['source_sha256']={str(p.relative_to(ROOT)):hw.sha(p) for p in paths}
 hw.save(target,report);print(json.dumps(report))
if __name__=='__main__':main()
