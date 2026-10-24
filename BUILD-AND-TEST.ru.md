Финальный код rc.6 расширяет тот же парсер на сборку adopt; текущие факты и границы — PERFORMANCE.ru.md.

# Сборка и проверки 1CDB2SRC 0.3.0-rc.6

## Проверки 0.3.0-rc.6

Встроенный Expat проверяет весь поток XML без построения дерева. Прежний
ElementTree остаётся для потребителей, которым дерево нужно. Нет изменений
сериализации, Rust, публичных параметров и зависимостей. Helper пересобран
с текущими Python-файлами, принятый ELF сохранён побайтово.

Windows: 138 методов без ошибок, два symlink subcase пропущены. Linux offline:
254 метода, 233 PASS и 21 SKIP (17 реальных memory-limit по действующему запрету,
четыре Windows-only). Дополнительные тесты проверяют пространства имён,
DTD/entities, кодировки, большие атрибуты и текст, поздние ошибки и совпадение
с ElementTree. Небольшой прогон двух сохранённых CF — 15 файлов/1 BSL exact.
Промежуточный вариант: четыре live PostgreSQL DB→CF→XML прогона — 46 786 файлов/11 774 BSL exact.

Измерения — PERFORMANCE.ru.md; current evidence — release-validation.json.
Проверку результатов выполнял руководитель этапа, отдельного независимого
ревьюера в этом выпуске не было. Упаковка и offline install сами по себе не
означают новый DB→XML прогон. Известные opaque/закрытые исходники и ограничения
форматов не изменены; новая обратная загрузка в платформу 1С не выполнялась.

## Историческое дополнение 0.3.0-rc.5

Generic readback принимает2/6 с прежними SHA/kind/path/XML checks. Final main2/
vendor6 — два вложенных OS supervisor, общая отмена/join, outer2CPU/aggregate8.
Общий CF manifest before/after; закрытые side receipts проверяются до common PASS.
Windows115 и Linux241 приняты. Два heavy medium прогона сверены целиком со
свежим sequential и balanced; source/helper одинаковы. Факты и границы измерений
в release-validation.json. Helper sealed заново; Rust и XML сериализация прежние.
Root review не является independent. Live DB E2E и ERP в этой итерации не повторяли.

## Историческое дополнение 0.3.0-rc.4

Добавлен optional verify-overlap: закрытый main producer → ранняя полная XML V,
одновременно vendor generation → общая final CF/profile/raw lineage и полное
новое чтение main SHA без повторного XML parsing → прежняя полная vendor V.
Early evidence не является final PASS; проверяются закрытый supervisor,
его invocation, CF/profile/source/helper/raw snapshot и hash chain. Поздний
readback не заменяется stat/mtime. Перенос CF, Rust и XML-сериализация прежние.

Окончательная r2 отличается от A/B source r1 только проверкой регистра пути
config по правилам ОС и её тестом. Оба source/helper сохранены раздельно.
Windows focused103 метода без ошибок,2 symlink subcases SKIP; Linux229методов:
208PASS/21SKIP(17 memory-limit по запрету,4Windows). Это root review, не independent.
Малый final E2E с mixed-case Windows config path и CF copy принят; medium A/B
проведён на r1, ERP нового режима NOT_RUN. Helper пересобран и запечатан заново;
Rust/ELF не пересобирались. Факты и scope — release-validation.json.

## Историческое дополнение 0.3.0-rc.3

Явный `--side-scheduling transfer-overlap` перекрывает перенос готовой основной
XML с обработкой поставщика. Default sequential, native и остальные маршруты
сохранены. Один pair-worker запускает два side-supervisor с общей отменой;
поставщик допускается только после связанного с CF/runtime подтверждения
завершения main helper. Общая integrity выполняется после обеих сторон.
Очистка при ошибке требует положительного подтверждения закрытия outer
producer, а не успешного результата конвертации. Rust/ELF не изменены.

Профильные Windows-проверки: 78 PASS. Linux-container discovery: 212 методов,
191 PASS, 21 SKIP (17 действующих запретов тестов лимитов памяти и 4 Windows).
Включены реальные малые отмены дерева процессов и вложенного supervisor;
файлы конфигураций и BSL в этих тестах не исполняются. Проверку выполнял
руководитель BD; отдельное независимое ревью для этой итерации не заявляется.
Реальные пары CF/XML и их измерения перечислены в release-validation.json;
unit/offline install сами по себе не являются сквозной выгрузкой из СУБД.

## Дополнение 0.3.0-rc.2

Оптимизации затрагивают только поиск некавыченных токенов brace.py и отложенное
чтение Properties/Name у нужных MDClasses UUID. Обход вложенных XML и владельцы
сохранены. Новый cf_copy.py копирует ровно один RO CF в новый own volume;
закрытый результат независимо хешируется. Только новый target нормализуется
для UID 65532; права исходника не меняются. Роль cf-copy: UID 0, только CHOWN,
2 CPU, без лимита памяти и сети, корень только для чтения, два точных mount. Условия UID/rootless — в README.
После изменения app sources требуется полный rebuild/seal helper по процедуре
ниже; вручную заменять отдельный hash нельзя. Rust build не требуется.
Нейтральные регрессии добавлены в test_brace.py, test_dumpinfo_single_pass.py,
test_cf_copy.py. Новые unit/E2E границы — в release-validation.json.

## Что изменилось в 0.3

Выпуск добавляет явно выбираемый ускоренный Docker-маршрут: конвертация и
Python-сборка XML выполняются в Linux volume, затем результат переносится и
независимо проверяется на стороне запуска. Как включить режим и подключиться
к СУБД — в [README.md](README.md). По умолчанию сохранён `--docker-mode host`;
native/прежние Docker-маршруты не заменены автоматически.

Python orchestration/helper и тесты обновлены. Rust-код и принятый ELF остались
от 0.2.0: **65435328 байт**, SHA256
`e4823a015f093e3e805da57f874793cf767d35675314baf58a13424f3f67a0df`.
Они не пересобирались ради 0.3. Источники идентичностей — `provenance.json`,
`APP-MANIFEST.json`, `app/runtime/manifest.json`,
`app/runtime/local/manifest.json` и manifest helper image. Изменять один хеш
вместо пересборки и проверки всего связанного комплекта нельзя.

## 0.3: обновление Python helper image

Готовый fast-режим использует поставленный offline helper archive. При изменении
любого `app/onecdb2src/**/*.py`, `xml/data/assets.rs` или `runtime/local`
нужен новый helper archive и manifest: старый комплект будет отклонён по хешам.
Rust перекомпилировать при изменении только Python не требуется. Служебные
скрипты находятся в `tools/` и используют Python 3.13+ и Docker CLI.

**Ограничение сборщика:** приведённая остановленная сборка образа проверена
только в Windows с локальным Docker Desktop, context `desktop-linux`, Linux
amd64 containers. Linux-сборка этим скриптом не заявляется. Это ограничение
служебного сборщика, а не запуска готового приложения: runtime поддерживает
Windows/Docker и Linux/Docker, а прежние host/native режимы сохранены.

Нужен уже закешированный базовый Python image с immutable ID
`sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641`
(исходное имя `python:3.13-slim-bookworm`). Скрипты не выполняют pull, сетевой
build, apt/pip или Rust build. При отсутствии этого точного base операция
откажет; базовый image для пересборки не входит отдельным архивом в комплект.
Для обычного запуска пересборка и этот base не нужны — достаточно готового
helper archive.

Из корня **собственной копии исходников** в PowerShell, после установки Python
зависимостей приложения:

1. Переместите существующий `app/runtime/fast-helper` целиком за пределы `app`,
   сохранив резервную копию. Новые пути вывода ниже должны отсутствовать.
2. Зафиксируйте контекст, соберите локальный image без запуска контейнера,
   затем сохраните его и manifest:

```powershell
python tools/build_helper_context.py --app app --output helper-context
$context = (Get-FileHash helper-context/context-manifest.json -Algorithm SHA256).Hash.ToLowerInvariant()
python tools/assemble_helper_image.py --manifest helper-context/context-manifest.json --expected-context-sha256 $context --output helper-assembly --seconds 180
$assembly = (Get-FileHash helper-assembly/result.json -Algorithm SHA256).Hash.ToLowerInvariant()
python tools/seal_helper_image.py --app app --assembly helper-assembly/result.json --assembly-sha256 $assembly --context-manifest helper-context/context-manifest.json --context-sha256 $context --docker-context desktop-linux --compression gzip --seconds 300
```

Первый скрипт копирует и проверяет исходники/runtime по хешам; второй создаёт
собственный **не запущенный** контейнер, копирует payload, делает commit и
подтверждает удаление контейнера. Третий сохраняет точный image, проверяет
его содержимое и создаёт `app/runtime/fast-helper/manifest.json`,
`helper-image.tar.gz`, `THIRD-PARTY-NOTICES.txt`. Образ не получает единую новую
лицензию: уведомления CPython/Debian и вложенного runtime сохраняются.

3. Переместите три диагностических файла `seal-result.json`, `image-before.json`,
   `image-after.json` из `app/runtime/fast-helper` в свой каталог журналов.
   В публичном helper-каталоге оставьте только archive, manifest и notices.
4. Выполните unit tests и небольшой реальный DB→CF→XML прогон обоих компонентов
   по README; успешная сборка image сама по себе не доказывает работу экспорта.
   После проверки обновите APP/source/release manifests при выпуске пакета.

Другой cached base, новые библиотеки или новый Rust ELF требуют отдельной
проверки и обновления закреплённых идентичностей; не меняйте только хеши,
чтобы обойти отказ несовместимого комплекта.


## Текущие Python-проверки

Рядом с `app/` находится `tests/`. Зависимости устанавливаются по README
из включённых платформенных wheels. Из корня на Windows:

```powershell
app/.venv/Scripts/python.exe -B -m unittest discover -s tests -v
```

В предыдущем 0.3.0-rc.2 Linux: 190 методов — 169 прошли, 21 пропущен (17 с лимитами памяти и
4 Windows), ошибок 0; тесты 1,203 с, контейнерная операция 7,407 с. Отдельно на Windows
прошли 28 нейтральных методов трёх изменённых модулей за 4,751 с; полный Windows
discovery в этой итерации не повторялся.

Историческая проверка 0.3.0-rc.1: discovery **171 метод**. На Windows проверен один
полный прогон: failures 0, errors 0; 17 методов Linux-process/environment
пропущены как `real Linux required`, ещё два subcase одного symlink-теста —
из-за отсутствия права создавать symlink. Это не означает 171 выполненный
положительный тест. В протоколе сохраняются состав, причины SKIP и время.
Тесты используют синтетические CF/TAR/файлы и fake Docker; прохождение unit
не является живой проверкой СУБД или подтверждением одинакового XML.

**Особенность Linux:** обычный `unittest discover` включает 17 настоящих
process/environment методов из `test_posix_process` и
`test_posix_env_boundary`. Они требуют `/proc`, pidfd/prctl/affinity и могут
устанавливать RSS/RLIMIT/адресные лимиты, несмотря на отсутствие реального
конвертера. В текущей приёмке эти 17 методов **явно исключаются как SKIP**
по прямому правилу отключения memory controls; их ожидания и тела не меняются.
Обычный Linux discovery без такого исключения не повторяет эту приёмку.
Исторические успешные проверки capped process-тестов приведены ниже отдельно;
они не заявляются как заново выполненные для 0.3.

Для проверки выпуска отдельно нужны установка из offline-комплекта, небольшой
реальный DB→CF→XML прогон основной конфигурации и поставщика, независимое
чтение файлов результата и подтверждение очистки собственных ресурсов.
Unit tests, пересборка helper и проверки формата архива эти шаги не заменяют.
Текущие факты конкретной поставки находятся в `release-validation.json`;
исторические результаты внутри него не являются новыми actual.

## Rust: воспроизведение команды, не новая сборка 0.3

`converter/` содержит полный сохранённый patched ibcmd-rs. Отличия от upstream,
Cargo.lock и принятый бинарник описаны в `provenance.json`. Происхождение
сохраняется без переписывания при подготовке Python/Docker helper.

Граница сборки: Linux x86-64/glibc, Rust/Cargo 1.95.0,
target x86_64-unknown-linux-gnu, системный C toolchain/linker (в частности для
libmimalloc-sys). Cargo dependencies определены неизменным Cargo.lock.
Старые target и registry cache не поставляются. Для первого получения registry
dependencies нужен доступ к crates.io либо свой заранее подготовленный mirror/cache.

Из каталога `converter` после установки toolchain:

```sh
cargo fetch --locked --target x86_64-unknown-linux-gnu
SOURCE_DATE_EPOCH=1791526512 CARGO_BUILD_JOBS=2 cargo build --release --offline --frozen --features experimental-native-projection --bin ibcmd-rs --target x86_64-unknown-linux-gnu
```

Результат — `target/x86_64-unknown-linux-gnu/release/ibcmd-rs`.
Это сохранённая принятая Cargo-команда. В 0.3 её заново не выполняли.
Побайтовая воспроизводимость ELF не обещается: пути/debug/toolchain/system
linker могут влиять на него; одних приведённых переменных для exact SHA256
может быть недостаточно. Точный текущий бинарник поставлен в runtime и
закреплён его manifest; предыдущий ELF из истории ниже использовать вместо
него нельзя.

Обязательный feature `experimental-native-projection` сохраняет известные
ограничения XML, opaque-only отказ и неполную native generalization. Обычный
build без feature не объявляется эквивалентом поставленного runtime.

Для запуска нового ELF нужны его glibc loader/shared libraries. Зависимости
проверяются `ldd` отдельно; произвольным новым ELF нельзя молча заменять runtime:
приложение закрепляет бинарник, локальные библиотеки и OCI archive по хешам.
Native использует `app/runtime/local/ld-linux-x86-64.so.2 --library-path
app/runtime/local/lib app/runtime/local/ibcmd-rs`, Docker — тот же бинарник
в image. Runtime Linux x86-64/glibc не означает поддержку ARM/musl или
проверенную сборку helper всеми Linux-дистрибутивами.

## Замыкание локальных зависимостей

Сохранены Cargo.toml/Cargo.lock, семь workspace crates, локально адаптированный
morph1c и все его path dependencies/пять JSONL входов codegen. Его build.rs
также перечисляет сохранённые Rust metadata-модули и генерирует OUT_DIR tables.
include_str!/include_bytes!/include! проверены статически: production ресурсы
на месте, девять OUT_DIR включений генерируются build.rs. Метаданные и include
references перечислены в closure-audit.json; это статическая проверка, не build.

В tests/fixtures оставлены ровно15 обязательных публичных upstream schema/probe
ресурсов, включаемых production исходниками:13JSON и2base64 reference.
Это часть исходной схемы, а не наши MS/PG/ERP выгрузки. Малый3716B
form_choice_parameters_slot27_live.json сохранён побайтно из публичного commit
под MIT: публичный upstream E:/ibcmd_lab provenance — исторический текст,
не runtime path. Он участвует в production whole-byte SHA256 проверке evidence.
Удаление/редактирование этих байтов ломает исходную проверку; это не выполнено.

Остальные старые Rust unit/integration test sources сохранены как legacy code.
Их внешние lab/corpus/native-evidence fixtures и installed-platform oracle
данные намеренно не поставляются. **Полный `cargo test` не является готовой
переносимой проверкой**: 544 include references требуют отсутствующих legacy
fixtures, также есть runtime чтения внешних datasets. Отдельная feature
research-corpus-tests/platform-oracle/mssql-live-tests здесь не проверялась.
Не включайте их ради запуска опубликованного приложения.

## Лицензии

Root ibcmd-rs — MIT (`converter/LICENSE`). Vendored morph1c — Apache-2.0
выбранная альтернатива из MIT OR Apache-2.0: его NOTICE.md/LICENSE-APACHE сохранены.
ibcmd-number-format — GPL-2.0-only WITH Classpath-exception-2.0: полный LICENSE
и исходные Oracle notices сохранены. Пятьдесят с лишним мегабайт исходников
не получают автоматически единую MIT лицензию.

third-party-licenses/rust содержит декларации и доступные license/notice тексты
registry packages из Cargo.lock. Это перечень lock closure (включая optional,
platform/test dependencies), не новый linked-binary SBOM. Отдельные runtime
glibc/GNU и Python wheels licenses остаются в app/licenses и wheels.

## История, не новые проверки 0.3

### Выпуск 0.2.0

Содержит generic legacy roots/UsePurposes/TitleFont из исходного commit7cefdce
и Python-исправления профилей, сохранения подписи и длинных путей. Исходники
Rust и runtime поставляются вместе. Тогда принят ELF65435328байт,
SHA256 `e4823a015f093e3e805da57f874793cf767d35675314baf58a13424f3f67a0df`.
Docker и native используют этот ELF; сборка не повторялась ради упаковки.

Команда Cargo ниже и ограничения legacy corpus сохраняются. Дополнительные
переносимые Rust integration-тесты без внешнего корпуса:

```sh
cargo test --release --offline --frozen --features experimental-native-projection --test native_configuration_legacy --target x86_64-unknown-linux-gnu
```

В принятой сборке:8PASS/1external-corpusignored. Python-тесты из `tests/`
проверяют приложение, а не Rust и не живую СУБД. Полный результат проверок
упаковки этого выпуска хранится в `release-validation.json`.


### BD-018: прежние права, сборка и ELF — исторические данные

Комплект BD-018 включал универсальное исправление порядка прав
Catalog/InformationRegister из BD-017. Тогда проверены 5 schema + 6 production
тестов и адресная генерация четырёх ролей из каждой СУБД; это не был новый
полный экспорт. Оставшееся ограничение формы описано в
`converter/docs/form-binding-scope.md`. Исходный код 1С и контрольные выгрузки
в поставку не включались и при запуске не использовались.

Историческая release-сборка исправления заняла 289,93 с с сохранённым dependency
cache; сборка полностью с нуля не проверялась. Её прежний бинарник:
**65346072 байт**, SHA256
`b087962e13423f833ccae5e495423fa2228767da628f3c06a375ba48b7a48358`.
Этот ELF **не текущий runtime 0.3** и не является рекомендуемой заменой.

### Старый набор Python: 51 проверка — не текущий discovery

В историческом наборе было пять модулей /51 различная проверка: OCI digest/config binding и отрицательные
endpoint cases; native process/result contracts и budget; mocked local runtime
без запуска converter;17реальных Linux process/environment tests. Они создают
только нейтральные временные данные; нет SQL, паролей, сохранённых CF/XML или
Docker daemon. POSIX tests пропускаются на Windows, требуют Linux /proc,
pidfd/prctl/affinity/RLIMIT и примерно19с. Никакие служебные пути этого workspace
не используются тестами. OCI metadata tests полностью моделируют daemon,
bind proof и свободную память, не требуют5GiB доступной RAM.

В копиях изменены только относительный import root, синтетические records
вместо старого реального CF/report и переносимость test assertion (родительский
путь может содержать слово docker). Для того этапа приложение/первоначальные тесты не изменялись.
Результаты:34PASS Windows,34PASS Linux pure/mock плюс17PASS реальных Linux
process tests. Ни один из этих тестов не заявляется DB→XML E2E или Rust build.
