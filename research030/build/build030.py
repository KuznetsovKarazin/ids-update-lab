#!/usr/bin/env python3
"""Rebuild stage030 eight ESP32S3 templates; no hardware access."""
from pathlib import Path
import json, hashlib, os, shutil, subprocess, sys, datetime
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from hardware_codec import codec030 as c
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def main():
    out=Path('/tmp/ids030-build');out.mkdir(exist_ok=True)
    src=out/'source'
    if src.exists():shutil.rmtree(src)
    shutil.copytree(ROOT/'firmware',src)
    build=out/'build'
    logs=ROOT/'build'/'logs';logs.mkdir(exist_ok=True)
    metadata={'stage':'030','status':'building','sdk':'ESP-IDF v5.3.2','sdk_commit':subprocess.check_output(['git','-C',os.environ['IDF_PATH'],'rev-parse','HEAD'],text=True).strip(),
      'hardware_accessed':False,'public_development_key':True,'production_security_claim':False,'whole_chunk_max_bytes':1024,
      'compiler':subprocess.check_output(['xtensa-esp32s3-elf-g++','--version'],text=True).splitlines()[0],
      'compiled_template_patch_note':'Model/version patch recomputes image checksum/SHA; embedded ELF SHA identifies unmodified compiled template only.',
      'source_sha256':{str(p.relative_to(ROOT)):c.sha(p.read_bytes()) for p in sorted((ROOT/'firmware').rglob('*')) if p.is_file()},'configurations':{}}
    save(ROOT/'build'/'BUILD_METADATA.json',metadata)
    for family in c.ABI:
      (src/'main/generated/model_contract.h').write_text(c.header(family))
      for policy in ('bundle','whole'):
        name=family+'_'+policy;print('BUILD '+name,flush=True)
        defaults=(ROOT/'firmware/sdkconfig.defaults').read_text()+('\nCONFIG_IDS_BUNDLE_POLICY=y\n' if policy=='bundle' else '\nCONFIG_IDS_WHOLE_FIRMWARE_BASELINE=y\n')
        defaults+='CONFIG_IDS_ERASE_NECESSARY_SECTORS=y\nCONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160=y\nCONFIG_FREERTOS_HZ=100\nCONFIG_COMPILER_OPTIMIZATION_DEBUG=y\nCONFIG_ESPTOOLPY_FLASHMODE_DIO=y\nCONFIG_ESPTOOLPY_FLASHFREQ_80M=y\n'
        cfg=out/'active.sdkconfig';cfg.write_text(defaults);(src/'sdkconfig.selected').write_text(defaults)
        base=['idf.py','-C',str(src),'-B',str(build),'-D','IDF_TARGET=esp32s3','-D','SDKCONFIG='+str(cfg),'-D','SDKCONFIG_DEFAULTS='+str(src/'sdkconfig.selected')]
        with (logs/(name+'.log')).open('w') as f:
          r=subprocess.run(base+['reconfigure','build'],stdout=f,stderr=subprocess.STDOUT)
        if r.returncode:raise RuntimeError('Build failed '+name)
        with (logs/(name+'-size.log')).open('w') as f:subprocess.run(base+['size'],check=True,stdout=f,stderr=subprocess.STDOUT)
        dest=ROOT/'prebuilt'/name;dest.mkdir(exist_ok=True)
        for rel in ['ids_update_lab.bin','bootloader/bootloader.bin','partition_table/partition-table.bin','ota_data_initial.bin','flash_args','flasher_args.json']:
          target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(build/rel,target)
        shutil.copy2(cfg,dest/'sdkconfig');shutil.copy2(src/'main/generated/model_contract.h',dest/'factory_model_contract.h')
        image=(dest/'ids_update_lab.bin').read_bytes();info=c.verify_image(image)
        if c.sha((build/'ids_update_lab.elf').read_bytes())!=info['elf_sha256']:raise AssertionError('ELF identity')
        e=c.sign_envelope(c.bootstrap(family),123,'patch-check030');patched=c.patch_image(image,e);pinfo=c.verify_image(patched)
        if pinfo['version']!=123 or pinfo['elf_sha256']!=info['elf_sha256']:raise AssertionError('patch failed')
        settings=dict(line.split('=',1) for line in cfg.read_text().splitlines() if line.startswith('CONFIG_') and '=' in line)
        gates={'CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ':'160','CONFIG_FREERTOS_HZ':'100','CONFIG_ESPTOOLPY_FLASHMODE':'"dio"','CONFIG_ESPTOOLPY_FLASHFREQ':'"80m"','CONFIG_ESP_MAIN_TASK_STACK_SIZE':'65536','CONFIG_IDS_ERASE_NECESSARY_SECTORS':'y'}
        for k,v in gates.items():
          if settings.get(k)!=v:raise AssertionError(k)
        for k in ['CONFIG_SECURE_BOOT','CONFIG_SECURE_FLASH_ENC_ENABLED','CONFIG_SPIRAM']:
          if settings.get(k)=='y':raise AssertionError(k)
        info.update(family=family,policy='whole_firmware' if policy=='whole' else policy,runtime_abi=c.ABI[family],schema=c.SCHEMA.hex(),
          erase_policy='necessary_sectors',template_region_offset=image.index(c.MAGIC),factory_length=c.envelope_metadata(c.sign_envelope(c.bootstrap(family),1,'bootstrap030'))['envelope_bytes'],
          patch_checksum_sha_verified=True,whole_chunk_max_bytes=1024,expected_feature_count=8,hardware_accessed=False)
        save(dest/'metadata.json',info);metadata['configurations'][name]=info;save(ROOT/'build'/'BUILD_METADATA.json',metadata)
    metadata['status']='complete';metadata['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    metadata['files_sha256']={str(p.relative_to(ROOT)):c.sha(p.read_bytes()) for p in sorted((ROOT/'prebuilt').rglob('*')) if p.is_file()}
    save(ROOT/'build'/'BUILD_METADATA.json',metadata)
    print('DONE eight templates, no hardware accessed',flush=True)
if __name__=='__main__':main()
