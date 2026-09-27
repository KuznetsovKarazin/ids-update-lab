# Готовые образы для проверки стенда

Эти образы собраны для ESP32-S3 с 4 MiB flash на ESP-IDF 5.3.2. Они используют только `examples/synthetic_demo`. Компиляция и проверки файлов выполнены; на физическую плату эти образы здесь не записывались.

Три каталога A: `bundle`, `model_only`, `whole_firmware`. В каждом находятся приложение, загрузчик, таблица разделов, начальные OTA-данные, параметры записи и использованный `sdkconfig`. `whole_firmware_B` содержит образ второй версии для полного обновления. `whole_B_ota` — подготовленный подписанный пакет для передачи через инструмент OTA.

Для первого опыта можно использовать готовый `bundle`, не собирая C++ заново. Полный SDK в этом случае необязателен: после подготовки host-Python из корня проекта установить инструмент записи:

```powershell
.\.venv\Scripts\python.exe -m pip install "esptool==4.12.0"
```

Перейти в каталог `prebuilt/synthetic_smoke/bundle` и выполнить:

```powershell
..\..\..\.venv\Scripts\python.exe -m esptool --chip esp32s3 -b 460800 --port COM10 --before default_reset --after hard_reset write_flash "@flash_args"
```

Если ESP-IDF 5.3.2 уже установлен, можно использовать его терминал и более короткую команду из того же каталога:

```powershell
python -m esptool --chip esp32s3 -b 460800 --port COM10 --before default_reset --after hard_reset write_flash "@flash_args"
```

Заменить `COM10` реальным портом. Команда заменяет загрузчик, разметку и приложение выбранной экспериментальной платы. Два раздела IDS автоматически не очищаются: если на них уже есть другая модель, восстановить A по `START_HERE_RU.md`.

После записи запустить из корня проекта, обычным host-Python:

```powershell
.\.venv\Scripts\python.exe -m ids_update_lab run --port COM10 --experiment examples/synthetic_demo --output runs\esp32-prebuilt-001
```

Для второго контрольного режима установить образ из `model_only`, явно восстановить IDS-разделы и выбрать новый каталог результата. Для полного обновления сначала записать `whole_firmware` (A), затем из корня проекта:

```powershell
.\.venv\Scripts\python.exe tools\firmware_ota.py send --artifact prebuilt\synthetic_smoke\whole_B_ota --port COM10 --out runs\esp32-whole-001
```

`fw_ready` означает подготовленное переключение, а не успешную загрузку новой версии. Перезапустить плату и отдельно зафиксировать `STATUS` версии 2. Подробности и отрицательный контроль — в `docs/WHOLE_FIRMWARE.md`.

Эти файлы позволяют проверить связь и процедуру. Для результатов на TON_IoT нужны собственный набор данных, новые подписанные комплекты и соответствующая пересборка. Приватного ключа демонстрационной поставки здесь нет. Хеши файлов приведены в `build_manifest.json`.
