# Сборки ESP32-S3 для ревизии 039

Автор новых инструментов: Oleksandr Kuznetsov. Скрипты не подключаются к устройству,
не запускают flashing и не программируют eFuse. Исходная `research030/firmware`
используется только через её отдельную копию `revision039/firmware`.

## Подготовка среды

Нужны Linux, Git и Python 3.11 или 3.12. При наличии активированной ESP-IDF 5.3.2
среды можно перейти сразу к сборке. Установщик загружает официальный SDK и проверяет
commit `9d7f2d69f50d1288526d4f1027108e314e8c879f`; инструменты компилятора проверяет
официальный `idf_tools.py` по манифесту Espressif. Python-пакеты зафиксированы
в `python-environment.lock`. Component Manager отключён: все проектные
компоненты включены в исходники, обращение к registry при сборке не требуется.

```bash
bash revision039/build/install_idf.sh /tmp/ids039-tools
source /tmp/ids039-tools/activate_ids039.sh
python revision039/build/build039.py
```

Полная матрица: четыре семейства × package/full-image × `-Og`/`-O2`. CPU 160 MHz,
flash DIO 80 MHz, PSRAM выключена, sector-granular erase. `-ffp-contract=off`
сохранён в компонентах; fast-math запрещён проверкой compile commands. Приватный
лабораторный ключ открыт, Secure Boot и flash encryption не включаются.

Результаты: `revision039/build/prebuilt/Og/lr_bundle/`,
`revision039/build/prebuilt/O2/lr_whole/` и аналогичные каталоги. Каждый содержит
BIN, bootloader, partition table, OTA initial data, flash arguments, sdkconfig,
factory header, compile commands и metadata. Bootstrap header задаёт ABI;
измеряемые A/B/C модели устанавливаются или встраиваются отдельным экспериментальным
runner. SHA образа относится к конкретному образу; ELF SHA относится к исходному
скомпилированному шаблону, в том числе после patch изменения модели.

Короткая сборка:

```bash
python revision039/build/build039.py --families lr --policies bundle,whole --optimizations O2
```

`--work` задаёт временный каталог CMake; `--output` — каталог результатов.
Внутри одной сборки объекты SDK повторно используются для семейства с той же
policy/optimization, но артефакты каждого семейства сохраняются отдельно.
`--prepare-only` создаёт staged source/config без компиляции. Глобальный manifest
каждого вызова описывает именно выбранную матрицу этого вызова; не трактуйте его
как полный инвентарь оставшихся от других вызовов файлов.

## Фазовые GPIO-сборки

```bash
python revision039/build/build039.py --families mlp_float --policies bundle --optimizations O2 --phase-gpio 4
```

Такие артефакты сохраняются отдельно:
`prebuilt/phase_gpio4/O2/mlp_float_bundle/`. Номер 4 — явный параметр, а не
утверждение о пригодности pin на конкретной плате: требуется проверить разводку
и отсутствие конфликта с периферией. Фазовую прошивку нельзя смешивать с чистой
прошивкой в итоговой timing таблице без отдельной идентификации. GPIO — только
логический сигнал для внешнего контроллера, не силовой выключатель питания.

## Проверки и границы результата

```bash
python -m unittest discover -s revision039/build -p 'test_build039.py' -v
```

Сборщик проверяет фактическую SDK revision, sdkconfig, compiler flags, ELF identity,
ESP image checksum/SHA и повторную проверку patched model/version image. Он не
доказывает host–device equivalence, physical power-cut recovery или скорость
сжатого OTA. Для каждого бинарника статус `compiled_not_hardware_validated`
означает, что аппаратные результаты ещё предстоит собрать.

Сборку можно запускать теми же командами в CI на Linux; `ci_build.sh` делает
установку, unit checks и выбранную матрицу без доступа к аппаратуре. GitHub workflow
или удалённое выполнение автоматически не создаются и не запускаются.
