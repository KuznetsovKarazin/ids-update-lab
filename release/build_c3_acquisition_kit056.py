#!/usr/bin/env python3
"""Make a portable acquisition subset from this checkout and restored C3 artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

ROOT=Path(__file__).resolve().parents[1]
START=r'''# Две ESP32-C3 SuperMini: этап 056

Это отдельный комплект для новых измерений. Старые каталоги опытов не используются.
Новых измерений на C3 при сборке комплекта ещё не было: прошивки скомпилированы,
а подготовка пакетов и численной панели проверена на компьютере.

Распакуйте ZIP в НОВУЮ папку, например E:\ids-c3-056. Откройте PowerShell в папке,
где лежит этот файл. Не распаковывайте поверх E:\ids-update-lab с прежними опытами.

## Python и проверка комплекта

Можно использовать $Py из прежних опытов. Если он не задан, создайте окружение
на Python 3.13 (или замените -3.13 на -3.12, если установлена версия 3.12):

```powershell
py -3.13 -m venv .venv056
$Py = (Resolve-Path .\.venv056\Scripts\python.exe).Path
& $Py -m pip install -r .\revision056\requirements-hardware.txt
& $Py .\verify_kit056.py
```

Эталонные образы уже включены; ESP-IDF собирать не нужно. KIT_MANIFEST056.json
проверяет именно этот переносимый комплект. MANIFEST.sha256.json сохранён из
полного репозитория как источник хешей замороженных моделей; он не является
перечнем файлов сокращённого комплекта.

## Сначала первая плата

Подключите только одну C3 кабелем USB с передачей данных. Pico, TPS22919 и стенд
отключения питания не нужны. Закройте Serial Monitor и другие программы,
занимающие порт. Определите новый COM-порт:

```powershell
& $Py -m serial.tools.list_ports -v
$Port = Read-Host 'COM-порт подключённой C3, например COM7'
& $Py .\revision056\hardware\inspect_c3.py --port $Port --output ..\c3-board1-identity
```

Ожидается status=passed, chip=esp32c3 и flash_bytes не меньше 4194304.
Проверка читает ROM/MAC и объём flash, перезапускает плату, но не записывает flash.
Сохраните вывод. Если проверка не прошла, остановитесь и сохраните rom.log.

Следующая команда устанавливает тестовую прошивку и заменяет приложение/модель
на выбранной C3. MAC повторно проверяется перед каждой записью. Это лабораторная
плата; необходимые данные и прежнюю прошивку следует сохранить до запуска.

```powershell
& $Py .\revision056\hardware\run_board056.py --identity ..\c3-board1-identity\identity.json --output ..\c3-board1-056
```

Будут выполнены 26 конфигураций × 1024 численных входа и 120 измеряемых установок
обновления, с отдельными прогревами и отрицательными контролями. Расхождения
численных результатов сохраняются; параметры и пороги из-за них не подстраиваются.
Windows получает временный запрос не переходить автоматически в сон. Не закрывайте
крышку и не отключайте USB во время опыта. Настройки электропитания постоянно не меняются.

При любой ошибке цикл остановится и сохранит ZIP с частичным результатом.
Не удаляйте его и не продолжайте с новым запуском до разбора причины.

## Затем вторая плата

Отключите первую, подключите вторую и снова определите порт. Её MAC должен отличаться.

```powershell
& $Py -m serial.tools.list_ports -v
$Port = Read-Host 'COM-порт второй C3'
& $Py .\revision056\hardware\inspect_c3.py --port $Port --output ..\c3-board2-identity
& $Py .\revision056\hardware\run_board056.py --identity ..\c3-board2-identity\identity.json --output ..\c3-board2-056
```

Если COM-порт сменился после проверки, у run_board056.py есть параметр --port COMn;
проверка MAC остаётся обязательной. Все выходные папки должны быть новыми.

## Что вернуть и как проверить

Нужны c3-board1-056.zip и c3-board2-056.zip, в том числе если цикл завершился ошибкой.
После двух полных прогонов можно выполнить независимый пересчёт по журналам:

```powershell
& $Py .\revision056\hardware\analyze_boards056.py --board ..\c3-board1-056 --board ..\c3-board2-056 --output ..\c3-analysis056
```

Результаты двух плат анализируются отдельно. Они проверяют повторяемость на двух
экземплярах C3 и перенос с S3 на C3; это не замена отсутствующей второй S3 и не
доказательство работы на любом микроконтроллере.
'''

VERIFY='''import hashlib,json\nfrom pathlib import Path\nr=Path(__file__).resolve().parent\nm=json.loads((r/'KIT_MANIFEST056.json').read_text())\nfor name,expected in m['sha256'].items():\n    p=r/name\n    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:\n        raise ValueError('Changed or missing kit file: '+name)\nprint(json.dumps(dict(status='verified',files=len(m['sha256']),source_commit=m['source_commit'],hardware_accessed=False)))\n'''

def build(output,commit):
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    if not (ROOT/'revision056/build/prebuilt/BUILD_METADATA.json').is_file():
        raise ValueError('Restore the C3 prebuilt artifact first')
    folders=['research030/training','research030/hardware_codec','research030/tools',
             'paper037/evidence_inputs/training','paper037/new_diagnostics/quantization','revision056']
    for folder in folders:
        for p in sorted((ROOT/folder).rglob('*')):
            relative=p.relative_to(ROOT)
            if not p.is_file() or '__pycache__' in p.parts:continue
            if folder=='revision056' and relative.parts[1] in ('cic','results','tests','presentation'):continue
            target=output/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
    for name in ('MANIFEST.sha256.json','LICENSE','LICENSE_SCOPE.md','THIRD_PARTY_NOTICES.md','AUTHORS.md'):
        shutil.copyfile(ROOT/name,output/name)
    (output/'START_C3_RU.md').write_text(START,encoding='utf-8')
    (output/'verify_kit056.py').write_text(VERIFY)
    manifest=dict(source_commit=commit,scope='portable C3 acquisition subset; no new C3 results',
       sha256={p.relative_to(output).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(output.rglob('*')) if p.is_file()})
    (output/'KIT_MANIFEST056.json').write_text(json.dumps(manifest,indent=2)+'\n')
    archive=output.with_suffix('.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(output.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(output.parent))
    print(json.dumps(dict(status='packaged',archive=str(archive),bytes=archive.stat().st_size,
                         sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),files=len(manifest['sha256']))))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-commit',required=True);a=p.parse_args();build(a.output,a.source_commit)
