#!/usr/bin/env python3
"""Independent esptool parser verification of each real patched ESP template."""
from pathlib import Path
import io,json,sys
import esptool
from esptool.bin_image import ESP32S3FirmwareImage
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from hardware_codec import codec030 as c
def main():
    paths=sorted((ROOT/'prebuilt').glob('*/ids_update_lab.bin'))
    if len(paths)!=8:raise ValueError('Expected eight runtime/policy templates')
    result=[]
    for p in paths:
        kind=p.parent.name.rsplit('_',1)[0];template=p.read_bytes()
        # Version changes decimal length and covers runtime factory-version use.
        e=c.sign_envelope(c.bootstrap(kind),300,'official-parse')
        patched=c.patch_image(template,e)
        image=ESP32S3FirmwareImage(io.BytesIO(patched))
        if image.checksum!=image.calculate_checksum() or image.stored_digest!=image.calc_digest:
            raise AssertionError('Official esptool checksum/SHA rejected '+str(p))
        result.append({'configuration':p.parent.name,'template_image_sha256':c.sha(template),
                       'patched_image_sha256':c.sha(patched),'patched_version':300,
                       'elf_sha256':c.image_metadata(patched)['elf_sha256'],
                       'esptool_checksum_verified':True,'esptool_appended_SHA256_verified':True,
                       'segments':len(image.segments)})
    report={'status':'passed','hardware_accessed':False,'measurement_origin':'host_validation',
            'esptool_version':esptool.__version__,'images':result}
    (ROOT/'build/OFFICIAL_ESPTOOL_PATCH_CHECK.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':'passed','images':len(result),'esptool_version':esptool.__version__,'hardware_accessed':False}))
if __name__=='__main__':main()
