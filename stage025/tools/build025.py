#!/usr/bin/env python3
"""Build four stage025 factory images with the pinned ESP-IDF v5.3.2 SDK.

Linux/WSL; activate ESP-IDF first. Output must be a fresh directory outside the
kit. This command never accesses hardware and requires no private signing key.
The frozen, already signed factory A envelope is embedded exactly once.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SDK_COMMIT = '9d7f2d69f50d1288526d4f1027108e314e8c879f'
CONFIG_GATES = {
    'CONFIG_IDF_TARGET': '"esp32s3"',
    'CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ': '160',
    'CONFIG_FREERTOS_HZ': '100',
    'CONFIG_COMPILER_OPTIMIZATION_DEBUG': 'y',
    'CONFIG_ESPTOOLPY_FLASHMODE': '"dio"',
    'CONFIG_ESPTOOLPY_FLASHFREQ': '"80m"',
    'CONFIG_ESPTOOLPY_FLASHSIZE': '"4MB"',
    'CONFIG_ESP_MAIN_TASK_STACK_SIZE': '65536',
    'CONFIG_IDS_BUNDLE_POLICY': 'y',
    'CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG': 'y',
}
POLICIES = {
    'full_slot': 'CONFIG_IDS_ERASE_FULL_SLOT',
    'necessary_sectors': 'CONFIG_IDS_ERASE_NECESSARY_SECTORS',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def capture(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def identity(image):
    if len(image) < 288 or image[0] != 0xe9 or struct.unpack_from('<I', image, 32)[0] != 0xabcd5432:
        raise ValueError('Not an ESP-IDF application image')
    version_field, sdk_field = image[48:80], image[144:176]
    if b'\0' not in version_field or b'\0' not in sdk_field:
        raise ValueError('Unterminated image descriptor')
    version_string = version_field.split(b'\0', 1)[0].decode('ascii')
    if not version_string.isdigit() or version_string.startswith('0'):
        raise ValueError('Invalid factory app version')
    version = int(version_string)
    sdk = sdk_field.split(b'\0', 1)[0].decode('ascii')
    elf = image[176:208].hex()
    if not 1 <= version <= 0xffffffff or elf == '0' * 64:
        raise ValueError('Invalid image identity')
    return {'version': version, 'idf_version': sdk, 'elf_sha256': elf,
            'image_sha256': sha(image), 'image_size': len(image),
            'expected_build': f'esp-idf-{sdk};app={version};elf={elf[:9]}'}


def config_map(text):
    return dict(line.split('=', 1) for line in text.splitlines()
                if line.startswith('CONFIG_') and '=' in line)


def source_hashes():
    paths = list((ROOT / 'firmware').rglob('*')) + [Path(__file__)]
    return {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sorted(paths)
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def verify_artifacts():
    sys.path.insert(0, str(ROOT / 'host'))
    from ids_update_lab import package, tree_package
    verified = {}
    for family, module in [('lr', package), ('dt', tree_package)]:
        art = ROOT / 'artifacts' / family
        experiment = json.loads((art / 'experiment.json').read_text())
        public = package.load_public(art / 'public.pem')
        entries = {}
        for letter in ('A', 'B', 'C'):
            data = (art / f'release-{letter}.sids').read_bytes()
            expected = experiment['models'][letter]
            if sha(data) != expected['envelope_sha256']:
                raise ValueError('Frozen envelope hash differs: ' + family + letter)
            model = module.verify(data, public, bytes.fromhex(experiment['schema_sha256']),
                                  experiment['feature_count'], experiment['runtime_abi'])
            if model.version != expected['version']:
                raise ValueError('Frozen envelope version differs')
            entries[letter] = {'sha256': sha(data), 'bytes': len(data), 'version': model.version,
                               'signature_verified': True}
        verified[family] = entries
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() or out.is_relative_to(ROOT):
        raise ValueError('Use a fresh output directory outside the kit')
    sdk = Path(os.environ.get('IDF_PATH', '')).resolve()
    if not (sdk / 'tools/idf.py').is_file():
        raise ValueError('Activate pinned ESP-IDF first (IDF_PATH missing)')
    if capture('idf.py', '--version') != 'ESP-IDF v5.3.2':
        raise ValueError('Expected ESP-IDF v5.3.2')
    if capture('git', '-C', str(sdk), 'rev-parse', 'HEAD') != SDK_COMMIT:
        raise ValueError('SDK commit differs from the frozen build')
    if capture('git', '-C', str(sdk), 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('SDK contains tracked modifications')
    submodules = capture('git', '-C', str(sdk), 'submodule', 'status', '--recursive')
    # A leading '-' means missing; '+' means different commit; 'U' means conflict.
    if any(line.startswith(('-', '+', 'U')) for line in submodules.splitlines()):
        raise ValueError('SDK submodule state differs or is incomplete')
    verified = verify_artifacts()
    before = source_hashes()
    out.mkdir()
    source = out / 'source'
    shutil.copytree(ROOT / 'firmware', source, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    build = out / 'build'
    logs = out / 'build_logs'; logs.mkdir()
    prebuilt = out / 'prebuilt'; prebuilt.mkdir()
    save(out / 'SOURCE_BEFORE_BUILD.json', before)
    compiler = capture('xtensa-esp32s3-elf-gcc', '--version')
    metadata = {
        'stage': '025', 'status': 'building', 'hardware_tested': False,
        'hardware_accessed': False, 'sdk': 'ESP-IDF v5.3.2', 'idf_commit': SDK_COMMIT,
        'sdk_submodules': submodules.splitlines(), 'compiler_version': compiler,
        'cmake_version': capture('cmake', '--version').splitlines()[0],
        'ninja_version': capture('ninja', '--version'), 'python_version': platform.python_version(),
        'python_packages': capture(sys.executable, '-m', 'pip', 'freeze').splitlines(),
        'sdk_tools_manifest_sha256': sha((sdk / 'tools/tools.json').read_bytes()),
        'build_host': platform.platform(), 'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'cpu_frequency_mhz': 160, 'flash_frequency_mhz': 80, 'flash_mode': 'dio',
        'freertos_tick_hz': 100, 'compiler_optimization': '-Og (CONFIG_COMPILER_OPTIMIZATION_DEBUG)',
        'main_task_reserved_stack_bytes': 65536, 'flash_bytes': 4194304,
        'model_slot_capacity_bytes': 65536, 'erase_sector_bytes': 4096,
        'storage_scheme': 'journal_dualrail_v1', 'configurations': {},
        'source_sha256': before, 'frozen_artifact_verification': verified,
        'private_signing_key_used': False,
        'trust_boundary': 'trusted running firmware; no Secure Boot/eFuse claim',
    }
    for family in ('lr', 'dt'):
        family_configs = {}
        for policy, option in POLICIES.items():
            name = f'{family}_{policy}'
            print('BUILD ' + name, flush=True)
            if source_hashes() != before:
                raise ValueError('Source changed after the build freeze')
            art = ROOT / 'artifacts' / family
            experiment = json.loads((art / 'experiment.json').read_text())
            header = art / 'headers/A.h'
            shutil.copyfile(header, source / 'main/generated/model_contract.h')
            defaults = (ROOT / 'firmware/sdkconfig.defaults').read_text()
            defaults += ('\nCONFIG_IDS_BUNDLE_POLICY=y\n' + option + '=y\n'
                         'CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160=y\nCONFIG_FREERTOS_HZ=100\n'
                         'CONFIG_COMPILER_OPTIMIZATION_DEBUG=y\n'
                         'CONFIG_ESPTOOLPY_FLASHMODE_DIO=y\nCONFIG_ESPTOOLPY_FLASHFREQ_80M=y\n')
            selected = source / 'sdkconfig.selected'; selected.write_text(defaults)
            config = out / 'active.sdkconfig'; config.write_text(defaults)
            base = ['idf.py', '-C', str(source), '-B', str(build), '-D', 'IDF_TARGET=esp32s3',
                    '-D', 'SDKCONFIG=' + str(config), '-D', 'SDKCONFIG_DEFAULTS=' + str(selected)]
            command = base + ['reconfigure', 'build']
            with (logs / (name + '-build.log')).open('w') as log:
                process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            if process.returncode:
                raise RuntimeError('Build failed: ' + name + '; inspect saved build log')
            with (logs / (name + '-size.log')).open('w') as log:
                subprocess.run(base + ['size'], stdout=log, stderr=subprocess.STDOUT, check=True)
            image = (build / 'ids_update_lab.bin').read_bytes()
            envelope = (art / 'release-A.sids').read_bytes()
            info = identity(image)
            if (info['version'] != 1 or info['idf_version'] != 'v5.3.2'
                    or image.count(envelope) != 1):
                raise ValueError('Factory envelope/version/SDK binding differs: ' + name)
            if sha((build / 'ids_update_lab.elf').read_bytes()) != info['elf_sha256']:
                raise ValueError('Image ELF descriptor differs from built ELF')
            config_text = config.read_text(); settings = config_map(config_text)
            for k, v in {**CONFIG_GATES, option: 'y'}.items():
                if settings.get(k) != v:
                    raise ValueError('Compiled setting differs: ' + k)
            for disabled in ('CONFIG_IDS_MODEL_ONLY_BASELINE', 'CONFIG_IDS_WHOLE_FIRMWARE_BASELINE',
                             'CONFIG_SECURE_BOOT', 'CONFIG_SECURE_FLASH_ENC_ENABLED', 'CONFIG_SPIRAM'):
                if settings.get(disabled) == 'y':
                    raise ValueError('Unexpected enabled setting: ' + disabled)
            if settings.get(next(v for k, v in POLICIES.items() if k != policy)) == 'y':
                raise ValueError('Both erase policies are enabled')
            family_configs[policy] = {k: v for k, v in settings.items() if k not in POLICIES.values()}
            image_dir = prebuilt / name; image_dir.mkdir()
            for relative in ['ids_update_lab.bin', 'bootloader/bootloader.bin',
                             'partition_table/partition-table.bin', 'ota_data_initial.bin',
                             'flash_args', 'flasher_args.json']:
                dest = image_dir / relative; dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(build / relative, dest)
            shutil.copy2(config, image_dir / 'sdkconfig')
            (image_dir / 'factory_model_contract.h').write_bytes(header.read_bytes())
            metadata['configurations'][name] = {
                'family': family, 'policy': 'bundle', 'erase_policy': policy,
                'factory_dir': 'prebuilt/' + name,
                'images': {'A': {'path': f'prebuilt/{name}/ids_update_lab.bin', **info}},
                'ota': {}, 'runtime_abi': experiment['runtime_abi'],
                'erase_model_region': {'offset': 0x3b0000, 'length': 0x22000},
                'timing_schema_status': 3, 'timing_schema_OTA_commands': None,
                'model_slot_capacity_bytes': 65536, 'erase_sector_bytes': 4096,
                'factory_envelope_sha256': sha(envelope), 'factory_envelope_occurrences': 1,
                'factory_header_sha256': sha(header.read_bytes()), 'sdkconfig_sha256': sha(config.read_bytes()),
                'source_sha256': before, 'build_command': command,
                'factory_signature_verified': True,
            }
            save(out / 'BUILD_METADATA.json', metadata)
        if family_configs['full_slot'] != family_configs['necessary_sectors']:
            raise ValueError('Matched-family settings differ beyond the erase policy')
    if source_hashes() != before:
        raise ValueError('Source changed before all builds completed')
    metadata['matched_configuration_settings_verified'] = True
    metadata['status'] = 'complete'
    metadata['finished_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
    metadata['prebuilt_sha256'] = {p.relative_to(out).as_posix(): sha(p.read_bytes())
                                 for p in sorted(prebuilt.rglob('*')) if p.is_file()}
    save(out / 'BUILD_METADATA.json', metadata)
    print(json.dumps({'status': 'complete', 'configurations': 4, 'images': 4,
                      'hardware_accessed': False, 'output': str(out)}))


if __name__ == '__main__':
    main()
