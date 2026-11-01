# Временная проверка и устойчивость порогов, revision039

Автор нового кода: **Oleksandr Kuznetsov**. Код переиспользует неизменённые
`research030/training/{run_training030,model030}.py` и metadata-only генератор
`research028/tools/coverage028.py`. Рукопись и прежние результаты не изменяются.

Это пакет для выполнения экспериментов, а не уже полученные новые результаты.
Коллекция TON ранее исследовалась: все новые результаты следует описывать как
reviewer-driven, post-exploration analysis, с протоколом, замороженным до новых
обучения/предсказаний. Они не являются новым нетронутым внешним тестом.

## Требования и команды Windows PowerShell

Нужны Python и зависимости `research030/requirements.txt` (для `plan` и анализа
готовых scores достаточно NumPy; обучение также требует scikit-learn). Для
реального исследования нужны исходные 23 CSV TON из manifest
`research030/training/vendor/source_manifest.json`. Проверяются размер и SHA-256
каждого файла. Папка `--data-root` должна непосредственно содержать эти CSV.
Имена каталогов могут содержать пробелы: заключайте их в кавычки.

Все выходные каталоги должны быть **новыми**. Команды не переиспользуют и не
перезаписывают частично завершённые или старые эксперименты. При ошибке внутри
нового каталога сохраняется `summary.json` со статусом `failed` и реальной
причиной; отсутствующие данные не подменяются синтетическими.

```powershell
python revision039/science/run_science039.py plan --root . --data-root "D:/TON/Network" --output "D:/runs039/science-plan-001"
python revision039/science/run_science039.py run --root . --data-root "D:/TON/Network" --plan "D:/runs039/science-plan-001/plan.json" --output "D:/runs039/science-run-001"
python revision039/science/run_science039.py threshold --root . --data-root "D:/TON/Network" --prior-run "D:/runs039/science-run-001/original030" --output "D:/runs039/threshold-001"
python -m unittest discover -s revision039/science/tests -v
```

`run --scenario window_Cxxxx` позволяет выполнить один **уже выбранный** сценарий
из `plan.json` в отдельном новом каталоге. Эта опция не разрешает менять сценарий.
`--prior-run` у `threshold` указывает на каталог обучения, содержащий `models/`
и `protocol_lock_before_data_and_predictions.json`, а не на внешний каталог
нескольких сценариев. Прежний полноценный run030 с такой структурой тоже подходит.
До predictions модели и protocol lock проверяются по `result_manifest.json`.
Изменение даже одного байта останавливает запуск.

Если private run отсутствует, можно использовать публичные frozen models:

```powershell
python revision039/science/run_science039.py threshold --root . --data-root "D:/TON/Network" --prior-run paper037/evidence_inputs/training --output "D:/runs039/threshold-public-001"
```

Здесь модели проверяются по исходному `MANIFEST.sha256.json` (его собственный
SHA-256 также закреплён в коде), а хронология берётся из проверенного
`research030/protocol/coverage_selection.json`. Private samples не нужны:
scores считаются из исходных CSV. Нельзя передать произвольные модели без
manifest и без проверяемой связи с опубликованными артефактами. Каталог с
protocol lock, но без итогового result manifest не считается завершённым run.

## Что именно выполняется

**plan** сначала записывает правила выбора и hashes кода, затем проверяет CSV,
строит почасовое покрытие и исходную сетку кандидатов (calibration 6/12/24 часов;
added fitting 1/2/4 таких блока). Это не сканирование результатов моделей.
Для кандидатов с достаточной предварительной поддержкой выполняется второй
проход с точными 60-секундными margins и полным containment потока. Исходное
окно включается отдельно. Получается `plan.json`, `plan.sha256`, полная таблица
предварительных кандидатов и точные покрытия всех прошедших prefilter.

Выбор: исходное окно плюс до двух дополнительных уникальных протоколов.
Каждая атомарная роль должна иметь >=1000 normal и >=1000 attack после purge;
будущий временной интервал — хотя бы 24 часа. Вначале предпочтительно окно,
имеющее >=1000 old-A и >=1000 added-B атак в будущем, затем другой future start,
затем хронологический порядок, длина calibration/added fit и ID. Одновременное
наличие полностью новых типов **не требуется**. Если подходящего mixed окна
нет, это явно отражается в `mixed_retention_scenario_available=false`.
Если доступны менее двух новых сценариев, фактическое число сообщается честно.
Исходное окно не обходится молча при нарушении support gate — обучение останавливается.

**run** проверяет hash неизменённого плана, код и source hashes; сохраняет lock
перед каждым обучением; вызывает настоящие `prepare_data`, `fit_models` и
`evaluate` из 030. Для каждого нового сценария обучаются A/B всех четырёх
семейств и оцениваются исходные component/export варианты (до 24 конфигураций;
decision-preserving LR при endpoint threshold явно неприменим).
Sampler, seed 25092026, архитектуры и hyperparameters сохранены. Обе calibration
роли исключены из обоих fitting наборов. Test не используется для tuning.
Выходы совместимы со структурой 030: `samples`, `models`, `evaluation.json`,
`by_day.json`, `by_attack_type.json`, cohort metrics, uncertainty diagnostics.
Старые 258 hardware vectors, которые создаёт evaluator030, остаются историческим
контролем; расширенную аппаратную проверку выполняет отдельный модуль revision039.

**threshold** сохраняет веса B и оценивает normal calibration в исходном и
более длинных окнах: фиксированные окончания через 6/12/24 часа от начала B_cal,
но не короче исходного B_cal. Используются только варианты, оставляющие >=24 часа
общего последующего test. Если исходный calibration дольше 24 часов, остаётся
исходный вариант. Общее начало test перенесено за самое длинное calibration окно
плюс 60 секунд; ни одна использованная calibration строка не остаётся в holdout.
Начало calibration также имеет margin 60 секунд, flow end должен быть строго
меньше конца окна минус 60 секунд. Используются все доступные normal строки,
без cap; это явно отличается от 030, если normals превышают cap 100000.

Для каждого семейства и окна выбирается тот же empirical 1% cutoff, с сохранением
ties. 1000 повторов (можно явно задать `--repeats`) дают iid-row и временные
block sensitivities с блоками 15/30/60 минут. Пустые временные блоки сохраняются;
пустые bootstrap draws учитываются отдельно. Показаны cut distributions и
изменение FPR/recall на общем holdout; test не выбирает порог. Сортировка scores
holdout выполняется один раз на модель, оценки множества thresholds используют
binary search. Это **не** population-FPR guarantee и не независимый test-day CI.
Не предполагается независимость потоков, кампаний или соседних блоков.

Scores записываются в локальные `.bin` кэши без raw features. Calibration record:
little-endian float64 `score, ts, end` (24 байта); test record: little-endian
float64 `score`, uint8 `label` (9 байт). Эти кэши, модели и source hashes описаны
в JSON/manifest. Для полного теста требуется существенное место и RAM для одной
сортировки scores; не запускайте параллельно несколько полных threshold задач
на машине с ограниченной памятью. Основные вычисления выполняются последовательно.

В том же CSV-проходе `threshold` строит `historical_retention.json`: полная
retained attack population старого A_cal оценивается моделями A/B, с разбивкой
по типам и явным признаком, встречался ли тип в A fitting. Если A models
отсутствуют, файл имеет статус `partial_missing_A_models`. Это исторический
retrospective diagnostic на ранее просмотренном материале, не независимый
будущий тест и не замена old+new temporal scenario.

## Анализ заранее сохранённых scores и синтетическая проверка

```powershell
python revision039/science/run_science039.py threshold --scores "D:/scores.npz" --output "D:/runs039/score-analysis-001"
```

NPZ не должен содержать pickled objects. Поля:

| Поле | Смысл |
|---|---|
| `cal_scores` | 1D scores **только normal** строк; float32 probabilities или exact integer codes |
| `cal_ts`, `cal_end` | Начало/конец этих потоков, Unix seconds UTC |
| `test_scores`, `test_labels`, `test_ts` | Фиксированный общий holdout, labels 0/1; длины согласованы |
| `cal_start` | Скаляр: номинальное начало calibration |
| `cal_ends` | Массив номинальных окончаний окон |
| `integer` | Bool scalar: integer `>= code` против float32 strict `> threshold` |

CLI отвергает test timestamps раньше максимального calibration end + 60 секунд.
Этот режим маркируется `caller_supplied_scores`, **не** TON reproduction; для
тестовых fixtures ничего не называется результатом на реальном трафике.
Tests проверяют chronological leakage rejection, exclusion обеих calibration
ролей, flow-spill/margins на реальном CSV parser030, ties, int8 thresholds,
целостность временных блоков, общий holdout и сохранность входов/старых outputs.
Отдельный небольшой synthetic CSV проходит настоящие sampler, обучение четырёх
семейств, compatible/component exports и SQLite evaluation030; он не называется
научным результатом на TON и требует установленного scikit-learn.

## Границы выводов

- Перекрывающиеся будущие окна не являются независимыми повторениями.
- При отсутствии old+new в хронологии набор не изобретает такую когорту и не
  переносит ранние атаки в будущее. Исторический retention diagnostic должен
  быть отдельно обозначен; он не подменяет смешанный будущий сценарий.
- A/B обучаются заново, B использует старые fitting строки. Изменение recall
  известных типов здесь не является экспериментом catastrophic forgetting
  последовательного fine-tuning.
- Расширение calibration меняет доступный test population. Сравнение окон
  проводится на одном новом общем holdout, а не со старыми headline metrics.
- Отсутствие времени/данных для полного запуска — незавершённый эксперимент,
  а не отрицательный результат. Никакие новые научные значения не зашиты в код.
