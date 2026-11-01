# Сжатое обновление полного образа и парная серия 039

Автор интеграции и протокола: **Oleksandr Kuznetsov**. Лицензия и авторство
стороннего miniz сохранены в `../firmware/components/miniz_tinfl/`.

Этот каталог содержит исполняемый MCU baseline, а не только вычисление размера
сжатого файла. `FWZ_BEGIN / FWZ_CHUNK / FWZ_END / FWZ_ABORT` в новой прошивке
распаковывают zlib-поток на ESP32-S3 с фиксированным окном 32 KiB. Восстановленные
байты сразу поступают в `esp_ota_write` неактивного OTA-раздела и SHA256. Перед
выбором загрузочного раздела проверяются точная длина, конец единственного zlib
потока, подписанный SHA256, валидность ESP application image и embedded version.
Сжатый хвост, конкатенированные потоки, нарушение смещения и усечённый образ
отклоняются. При сбое активный образ не выбирается заново.

Подписывается идентичность **восстановленного** полного образа (обычный 84-byte
manifest плюс RSA2048 signature). Длина сжатого потока — ограниченный недоверенный
параметр кадрирования, не основание доверять кандидату. Ключ лабораторный,
публично опубликован: это не production security или аппаратный anti-rollback.

## Подготовка без оборудования

Из корня репозитория после сборки новых bin:

```bash
python revision039/baseline/run_baseline039.py prepare \
  --prebuilt-root revision039/build/prebuilt/O2 \
  --output /path/to/empty/baseline039-O2
```

По умолчанию используются опубликованные замороженные A/B-модели из
`paper037/evidence_inputs/training/models`; `--training DIR` выбирает другой
сохранённый training-каталог с `models/`. Хеш каждой модели и образа сохраняется.
Новые модели не обучаются. `prepare` не открывает serial port и не прошивает плату.
Значения размера `.zlib` в подготовленных артефактах помечены `offline_only`.
Восемь A/B-моделей обязательно совпадают с опубликованными frozen SHA256 из
корневого `MANIFEST.sha256.json`, даже если передан другой `--training` с собственным
manifest. SHA256 всех файлов prebuilt проверяется до подготовки; SHA256 всех
подготовленных файлов — до обращения к плате.

Нужны именно новые `revision039/build/prebuilt/{Og,O2}/<family>_<policy>`:
старые images не содержат FWZ-команд. GPIO-инструментированные сборки
отклоняются для timing campaign.

## Явный запуск на конкретной плате

```bash
python revision039/baseline/run_baseline039.py run \
  --artifacts /path/to/baseline039-O2 \
  --port /dev/ttyACM0 --board-id esp32s3-001122aabbcc \
  --repetitions 10 --families lr,dt,mlp_float,mlp_int8 \
  --output /path/to/empty/measured-board1-O2
```

`run` **перепрошивает указанную плату**, очищает экспериментальные model/journal
разделы и inactive OTA-раздел при подготовке. Перед записью проверяются ROM chip
и MAC. Подготовка исключена из timing. Выходной каталог должен быть новым;
прерывание сохраняет частичные данные, команда мутации автоматически не повторяется.

Каждый блок содержит три политики в меняющемся порядке: package, raw full image,
compressed full image. Raw и compressed используют **один и тот же whole binary**.
Для каждой политики выполняются A1 → A2 (прогрев, исключён), A2 → B3
(содержательное обновление) и B3 → C4 (те же B-параметры, новая версия). Обе
измеряемые установки обращаются к ранее использованному целевому разделу.
Результаты A→B и B→C сохраняются отдельно. Все политики проходят warm factory
signature context и одинаковую проверку release после установки. Full-image
host interval включает перезагрузку и подтверждение running identity.

При 10 блоках и четырёх семействах это 240 измеренных observations плюс
подготовительные установки/negative controls; energy blocks на 5280 updates
не повторяются. Для второй платы и `Og` запускается отдельная серия с отдельным
board ID и каталогом. Это не заменяет новые numerical inputs и physical power cuts.

В первом блоке каждой семьи сохранены отрицательные проверки signatures,
replay, package contract и reconstructed-image hash; для compressed — также
заведомо повреждённый zlib header. После измерений повторяется replay rejection.
Идентичность и три диагностических входа проверяются для A/B/C; это smoke check,
а не расширенная numerical panel.

## Метрики и ограничения

`revision039_cost` records содержат точные TX bytes команд передачи обновления
(служебные STATUS/REBOOT и inference исключены из этого счётчика),
артефакт (metadata/signature включены), raw flash bytes, instrumented active MCU
interval и end-to-end host interval. `inflate_and_dispatch_sum_us` — остаток
chunk interval после вложенных write/hash, включая dispatch, а не чистое время
алгоритма inflate. `decoder_static_bytes` — размер фиксированного decoder state,
а не peak RAM. Запросы flash erase/write не приравниваются к износу ячеек.
Работа ESP OTA metadata отдельно не инструментирована. Energy не измеряется.

Подпись/хеш/boot identity сохраняются; Secure Boot и flash encryption не включаются.
Native-тесты проверяют exact MCU decoder и actual OTA dispatcher с настоящими
RSA/SHA, но подменёнными flash/boot API. Успешная сборка и host tests **не являются**
результатами физических MCU измерений.

```bash
python revision039/baseline/test_stream_inflate.py -v
python revision039/baseline/test_ota039.py -v
```
