#!/usr/bin/env python3
"""Rebuild the reviewed ESP32-S3 configurations with ESP-IDF v5.3.2.

Linux/WSL, offline once the SDK is installed. Creates a fresh output directory;
never flashes a board. An external existing laboratory signing key is required
for authenticated full-image artifacts. It is neither copied nor logged.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
META = struct.Struct('<8sII32sI32s')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def identity(image):
    if len(image) < 288 or image[0] != 0xe9 or struct.unpack_from('<I', image, 32)[0] != 0xabcd5432:
        raise ValueError('Not an ESP-IDF application image')
    version_field = image[48:80]
    sdk_field = image[144:176]
    if b'\0' not in version_field or b'\0' not in sdk_field:
        raise ValueError('Unterminated image descriptor')
    version_string = version_field.split(b'\0', 1)[0].decode('ascii')
    if not version_string.isdigit() or version_string.startswith('0'):
        raise ValueError('Factory app version must be a positive decimal integer')
    version = int(version_string)
    sdk = sdk_field.split(b'\0', 1)[0].decode('ascii')
    elf = image[176:208].hex()
    if not 1 <= version <= 0xffffffff or elf == '0' * 64:
        raise ValueError('Invalid image identity')
    return {'version': version, 'idf_version': sdk, 'elf_sha256': elf,
            'image_sha256': sha(image), 'image_size': len(image),
            'expected_build': f'esp-idf-{sdk};app={version};elf={elf[:9]}'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    key_path = args.private_key.resolve()
    if out.exists() or out.is_relative_to(ROOT) or key_path.is_relative_to(out) or key_path.is_relative_to(ROOT):
        raise ValueError('Use a fresh output directory and a signing key outside the kit and output')
    version = subprocess.run(['idf.py', '--version'], check=True, capture_output=True, text=True).stdout.strip()
    if version != 'ESP-IDF v5.3.2':
        raise ValueError('Activate pinned ESP-IDF v5.3.2 first')
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    public_bytes = (ROOT / 'artifacts/lr/public.pem').read_bytes()
    public = serialization.load_pem_public_key(public_bytes)
    if key.key_size != 2048 or key.public_key().public_numbers() != public.public_numbers():
        raise ValueError('Signing key differs from the frozen laboratory identity')
    out.mkdir()
    source = out / 'source'
    shutil.copytree(ROOT / 'firmware', source, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    build = out / 'build'
    logs = out / 'logs'; logs.mkdir()
    prebuilt = out / 'prebuilt'; prebuilt.mkdir()
    source_hashes = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes())
                     for p in sorted((ROOT / 'firmware').rglob('*')) if p.is_file()}
    source_hashes['tools/build_firmware.py'] = sha(Path(__file__).read_bytes())
    save(out / 'SOURCE_BEFORE_BUILD.json', source_hashes)
    matrix = [('lr', 'bundle', 'A'), ('lr', 'compatible', 'A'),
              ('lr', 'whole', 'A'), ('lr', 'whole', 'B'), ('lr', 'whole', 'C'),
              ('dt', 'bundle', 'A'), ('dt', 'whole', 'A'), ('dt', 'whole', 'B'), ('dt', 'whole', 'C')]
    metadata = {'stage': 'completion020', 'hardware_tested': False, 'sdk': version,
                'idf_commit': '9d7f2d69f50d1288526d4f1027108e314e8c879f',
                'main_task_reserved_stack_bytes': 65536, 'flash_bytes': 4194304,
                'storage_scheme': 'journal_dualrail_v1', 'configurations': {},
                'source_sha256': source_hashes}
    for family, policy, letter in matrix:
        name = f'{family}_{policy}'
        build_name = name + '_' + letter
        print('BUILD ' + build_name, flush=True)
        art = ROOT / 'artifacts' / family
        experiment = json.loads((art / 'experiment.json').read_text())
        # Refresh mtime so Ninja recompiles the embedded envelope even if all
        # frozen source headers were generated before the previous build.
        shutil.copyfile(art / 'headers' / (letter + '.h'), source / 'main/generated/model_contract.h')
        defaults = (ROOT / 'firmware/sdkconfig.defaults').read_text()
        selected_policy = {'bundle': 'CONFIG_IDS_BUNDLE_POLICY',
                           'compatible': 'CONFIG_IDS_MODEL_ONLY_BASELINE',
                           'whole': 'CONFIG_IDS_WHOLE_FIRMWARE_BASELINE'}[policy]
        defaults += '\n' + selected_policy + '=y\n'
        (source / 'sdkconfig.selected').write_text(defaults)
        config = out / 'active.sdkconfig'
        # Load an explicit minimal configuration on every matrix entry. A
        # deleted sdkconfig can be restored from generated build state, and
        # writing `n` to a choice sibling can reset the selected choice.
        config.write_text(defaults)
        cmd = ['idf.py', '-C', str(source), '-B', str(build), '-D', 'IDF_TARGET=esp32s3',
               '-D', 'SDKCONFIG=' + str(config), '-D', 'SDKCONFIG_DEFAULTS=' + str(source / 'sdkconfig.selected'), 'reconfigure', 'build']
        with (logs / (build_name + '-build.log')).open('w') as log:
            process = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        if process.returncode:
            raise RuntimeError('Build failed: ' + build_name + '; inspect saved build log')
        with (logs / (build_name + '-size.log')).open('w') as log:
            subprocess.run(['idf.py', '-C', str(source), '-B', str(build), 'size'],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        image = (build / 'ids_update_lab.bin').read_bytes()
        envelope = (art / ('release-' + letter + '.sids')).read_bytes()
        info = identity(image)
        if info['version'] != experiment['models'][letter]['version'] or image.count(envelope) != 1:
            raise ValueError('Firmware does not contain the exact factory envelope/version: ' + build_name)
        config_text = config.read_text()
        if 'CONFIG_ESP_MAIN_TASK_STACK_SIZE=65536' not in config_text:
            raise ValueError('Main task stack setting missing')
        for option, enabled in [('CONFIG_IDS_MODEL_ONLY_BASELINE', policy == 'compatible'),
                                ('CONFIG_IDS_WHOLE_FIRMWARE_BASELINE', policy == 'whole')]:
            if (option + '=y' in config_text) != enabled:
                raise ValueError('Compiled policy flag differs: ' + option)
        entry = metadata['configurations'].setdefault(name, {
            'family': family, 'policy': policy, 'factory_dir': 'prebuilt/' + name,
            'images': {}, 'ota': {}, 'runtime_abi': experiment['runtime_abi'],
            'erase_model_region': {'offset': 0x3b0000, 'length': 0x22000},
            'timing_schema_status': 3, 'timing_schema_OTA_commands': 2 if policy == 'whole' else None})
        image_dir = prebuilt / (name if letter == 'A' else build_name)
        image_dir.mkdir(exist_ok=True)
        if letter == 'A':
            for relative in ['ids_update_lab.bin', 'bootloader/bootloader.bin',
                             'partition_table/partition-table.bin', 'ota_data_initial.bin',
                             'flash_args', 'flasher_args.json']:
                dest = image_dir / relative; dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(build / relative, dest)
            shutil.copy2(config, image_dir / 'sdkconfig')
        else:
            (image_dir / 'ids_update_lab.bin').write_bytes(image)
        entry['images'][letter] = {'path': str((image_dir / 'ids_update_lab.bin').relative_to(out)), **info}
        if policy == 'whole':
            ota = prebuilt / (name + '_' + letter)
            ota.mkdir(exist_ok=True)
            abi = experiment['runtime_abi']
            schema = bytes.fromhex(experiment['schema_sha256'])
            blob = META.pack(b'SIDSFW1\0', info['version'], len(image), hashlib.sha256(image).digest(), abi, schema)
            signature = key.sign(blob, padding.PKCS1v15(), hashes.SHA256())
            public.verify(signature, blob, padding.PKCS1v15(), hashes.SHA256())
            for filename, content in [('image.bin', image), ('metadata.bin', blob), ('signature.bin', signature),
                                      ('factory.sids', envelope), ('public.pem', public_bytes)]:
                (ota / filename).write_bytes(content)
            save(ota / 'manifest.json', {'format': 'ids-update-lab-whole-firmware-v1',
                  'version': info['version'], 'runtime_abi': abi, 'image_sha256': info['image_sha256'],
                  'image_size': len(image), 'metadata_sha256': sha(blob), 'signature_sha256': sha(signature),
                  'feature_contract_sha256': schema.hex(), 'factory_envelope_sha256': sha(envelope),
                  'hardware_measurement': False, 'trust_boundary': 'trusted running firmware; no secure-boot/eFuse claim'})
            entry['ota'][letter] = str(ota.relative_to(out))
        save(out / 'BUILD_METADATA.json', metadata)
    metadata['finished_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
    metadata['prebuilt_sha256'] = {p.relative_to(out).as_posix(): sha(p.read_bytes())
                                 for p in sorted(prebuilt.rglob('*')) if p.is_file()}
    save(out / 'BUILD_METADATA.json', metadata)
    print(json.dumps({'status': 'complete', 'configurations': len(metadata['configurations']),
                      'images': len(matrix), 'hardware_accessed': False, 'output': str(out)}))

if __name__ == '__main__':
    main()
