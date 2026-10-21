# Исходники конвертера и воспроизведение сборки

Комплект BD-018 включает универсальное исправление порядка прав
Catalog/InformationRegister из BD-017. Исходники и оба runtime соответствуют
новой принятой сборке. Проверены 5 schema + 6 production-тестов, адресная
генерация четырёх ролей из каждой СУБД; это не новый полный экспорт конфигурации.
Оставшееся ограничение формы — `converter/docs/form-binding-scope.md`.
Версия XML/совместимость малого стенда не менялись. Исходный код 1С и
контрольные выгрузки не включены в поставку и не используются при запуске.

`converter/` — полный сохранённый код patched ibcmd-rs, а не ссылка на upstream.
Происхождение и отличающиеся от upstream файлы,
Cargo.lock и принятый бинарник описаны в `provenance.json`.
Собственные изменения и сохранённые исходники не переписаны при подготовке.

Первая граница сборки: Linux x86-64/glibc, Rust/Cargo 1.95.0,
target x86_64-unknown-linux-gnu, системный C toolchain/linker (в частности для
libmimalloc-sys). Cargo dependencies определены неизменным Cargo.lock.
Старые target и registry cache не поставляются. Для первого получения registry
dependencies нужен доступ к crates.io либо свой заранее подготовленный mirror/cache.

Из каталога converter после установки toolchain:

```sh
cargo fetch --locked --target x86_64-unknown-linux-gnu
SOURCE_DATE_EPOCH=1791526512 CARGO_BUILD_JOBS=2 cargo build --release --offline --frozen --features experimental-native-projection --bin ibcmd-rs --target x86_64-unknown-linux-gnu
```

Результат — `target/x86_64-unknown-linux-gnu/release/ibcmd-rs`.
Это принятая Cargo-команда. Release-сборка исправления выполнена за289,93с
с сохранённым dependency cache; сборка полностью с нуля не проверялась. Побайтовая
воспроизводимость нового ELF не обещается: пути/debug/toolchain/system linker
могут влиять на него. Нет утверждения, что одних приведённых переменных достаточно
для одинакового SHA256. Для exact принятого runtime используется поставленный
бинарник 65346072 байт / SHA256
`b087962e13423f833ccae5e495423fa2228767da628f3c06a375ba48b7a48358`.

Обязательный feature `experimental-native-projection` сохраняет известные
ограничения XML, opaque-only отказ и неполную native generalization. Обычный
build без feature не объявляется эквивалентом поставленного runtime.

Для запуска собранному ELF нужны его glibc loader/shared libraries.
Зависимости конкретной новой сборки проверяются `ldd` отдельно; произвольным
новым ELF нельзя молча заменять runtime в Python: приложение закрепляет
бинарник, локальные библиотеки и OCI archive по хешам. В принятой поставке native
запускает `app/runtime/local/ld-linux-x86-64.so.2 --library-path
app/runtime/local/lib app/runtime/local/ibcmd-rs`, Docker — тот же бинарник
в OCI image. Основная инструкция запуска приложения принадлежит README проекта.

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

## Переносимые Python тесты

Ожидаемое размещение: `app/` — приложение с BD-018 runtime; рядом `tests/` из
этого набора. Установите зависимости app по основной инструкции. Из корня:

```sh
python -B -m unittest discover -s tests -v
```

Пять модулей /51различная проверка: OCI digest/config binding и отрицательные
endpoint cases; native process/result contracts и budget; mocked local runtime
без запуска converter;17реальных Linux process/environment tests. Они создают
только нейтральные временные данные; нет SQL, паролей, сохранённых CF/XML или
Docker daemon. POSIX tests пропускаются на Windows, требуют Linux /proc,
pidfd/prctl/affinity/RLIMIT и примерно19с. Никакие служебные пути этого workspace
не используются тестами. OCI metadata tests полностью моделируют daemon,
bind proof и свободную память, не требуют5GiB доступной RAM.

В копиях изменены только относительный import root, синтетические records
вместо старого реального CF/report и переносимость test assertion (родительский
путь может содержать слово docker). Приложение/первоначальные тесты не изменялись.
Результаты:34PASS Windows,34PASS Linux pure/mock плюс17PASS реальных Linux
process tests. Ни один из этих тестов не заявляется DB→XML E2E или Rust build.
