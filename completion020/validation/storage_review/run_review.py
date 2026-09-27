#!/usr/bin/env python3
"""Reproduce independent native storage audit (Linux, C++17, OpenSSL headers)."""
from pathlib import Path
import hashlib,json,subprocess,tempfile,sys,datetime
HERE=Path(__file__).resolve().parent
KIT=HERE.parents[1]
CORE=KIT/'firmware/components/ids_core'
FLAGS=['-std=c++17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-ffp-contract=off']
def run(cmd,**kwargs):
    return subprocess.run([str(x) for x in cmd],check=True,capture_output=True,text=True,**kwargs)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def compile_native(out,legacy=False):
    if legacy:
        base=HERE/'legacy'; includes=[base/'include',base/'generated']; sources=[base/'ids_core.cpp',base/'ids_protocol.cpp',base/'main.cpp']
    else:
        includes=[CORE/'include',KIT/'firmware/main/generated']; sources=[CORE/'ids_core.cpp',CORE/'ids_protocol.cpp',CORE/'ids_tree.cpp',KIT/'firmware/native/main.cpp']
    run(['c++',*FLAGS,*['-I'+str(p) for p in includes],*sources,'-lcrypto','-o',out])
def native_run(exe,store,lines):
    result=run([exe,'--store',store],input='\n'.join(lines)+'\n')
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
def real_signed_counterexample(build):
    package=(KIT/'references/artifacts018/release-B.sids').read_bytes()
    records={}
    for legacy,name in [(True,'old'),(False,'journal')]:
        exe=build/('native_'+name); compile_native(exe,legacy)
        store=build/('store_'+name)
        first=native_run(exe,store,['UPDATE '+package.hex(),'STATUS'])
        assert first[0]['event']=='boot' and first[0]['ready'] and first[0]['version']==1
        update=next(r for r in first if r['event']=='update')
        assert update['accepted'] is True and update['version']==2
        assert first[-1]['event']=='status' and first[-1]['ready'] and first[-1]['version']==2
        # Change only one zero to one in old slot A, retaining its exact commit.
        p=store/'ids_a.bin'; raw=bytearray(p.read_bytes()); before=sha(p)
        assert raw[24]==ord('S'); marker=bytes(raw[:8]); raw[24]|=0x80; p.write_bytes(raw)
        assert raw[:8]==marker
        boot=native_run(exe,store,['STATUS'])[0]
        if legacy: assert not boot['ready'] and boot['reason']=='committed_slot_invalid'
        else: assert boot['ready'] and boot['version']==2 and boot['reason']=='ok'
        records[name]={'initial_boot':first[0],'accepted_update':update,'after_inactive_slot_one_bit_erase':boot,'slot_before_sha256':before,'slot_after_sha256':sha(p),'modified_area':'inactive model slot 0','modified_byte_offset':24,'operation':'bit 7 set from 0 to 1, commit unchanged','RSA_signature_verified_by':'OpenSSL native adapter'}
    # Deliberately OUTSIDE the promised interrupted-operation model: corrupt
    # the latest, already committed selector without touching another operation.
    # This exposes the exact rollback limit instead of silently assuming it away.
    out_store=build/'out_of_model_corruption'
    native_run(build/'native_journal',out_store,['UPDATE '+package.hex()])
    meta=out_store/'ids_meta0.bin'; data=bytearray(meta.read_bytes())
    assert data[128]==ord('S'); data[128]|=0x80; meta.write_bytes(data)
    outside=native_run(build/'native_journal',out_store,['STATUS'])[0]
    assert outside['ready'] and outside['version']==1
    limitation={'fault':'independent bit corruption in latest committed selector, outside interrupted-addressed-operation model','observed_old_version_booted':1,'supports_arbitrary_bitrot_antirollback':False,'boot':outside}
    return {'status':'pass','measurement_origin':'native_fault_model_not_MCU','real_signed_package_sha256':hashlib.sha256(package).hexdigest(),'cases':records,'demonstrated_out_of_model_limitation':limitation}
def main():
    with tempfile.TemporaryDirectory(prefix='storage_review_') as tmp:
        build=Path(tmp)
        sources=[CORE/'ids_core.cpp',CORE/'ids_tree.cpp',HERE/'adversarial_storage.cpp']
        exe=build/'adversarial'
        run(['c++',*FLAGS,'-I'+str(CORE/'include'),*sources,'-lcrypto','-o',exe])
        result=json.loads(run([exe]).stdout)
        legacy=build/'legacy'
        run(['c++',*FLAGS,'-Wno-unused-function','-Wno-unused-variable','-DLEGACY','-I'+str(HERE/'legacy/include'),HERE/'legacy/ids_core.cpp',HERE/'adversarial_storage.cpp','-lcrypto','-o',legacy])
        old=json.loads(run([legacy]).stdout)
        real=real_signed_counterexample(build)
    for name,value in [('result.json',result),('legacy_result.json',old),('real_signed_counterexample.json',real)]:
        (HERE/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    pins={}
    for folder in [CORE,KIT/'firmware/native',KIT/'firmware/main/generated',HERE/'legacy']:
        for path in sorted(folder.rglob('*')):
            if path.is_file(): pins[str(path.relative_to(KIT))]=sha(path)
    for path in [HERE/'adversarial_storage.cpp',Path(__file__).resolve(),KIT/'references/artifacts018/release-B.sids']:
        pins[str(path.relative_to(KIT))]=sha(path)
    metadata={'status':'pass','reviewed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_sha256':pins,'compiler':run(['c++','--version']).stdout.splitlines()[0],'native_test_result':result,'physical_power_loss_tested':False,'authentication_scope':'synthetic cut matrix uses accepting fixture verifier; separate real signed counterexample uses OpenSSL RSA2048 verification','fault_model':'one interrupted addressed NOR mutation; arbitrary subsets of intended program 1->0 or erase 0->1; no collateral corruption, dishonest reads, post-write instability, or simultaneous multiple faults'}
    (HERE/'REVIEW_METADATA.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(metadata['native_test_result']))
if __name__=='__main__': main()
