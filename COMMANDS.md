# DeStruct — справочник команд

Все команды запускаются через собранный бинарник `destruct` (`make build` → `./destruct <command> ...`), кроме `lifttest`, который собирается отдельно из `cmd/lifttest/`.

---

## `destruct jvm` — декомпиляция JVM `.class`/`.jar` → Java

```
destruct jvm input.jar -o output/
destruct jvm SomeClass.class -o output/
```

Принимает `.class` (один файл) или `.jar` (весь архив, включая streaming-режим для больших файлов). На выходе — дерево `.java`-файлов с восстановленной структурой пакетов.

---

## `destruct hermes` — дизассемблирование/декомпиляция Hermes `.hbc` (React Native)

```
destruct hermes index.android.bundle -o output/                # exact hermes-dec формат (.hasm)
destruct hermes index.android.bundle -o output/ --decompile     # декомпиляция в читаемый JS
destruct hermes index.android.bundle -o output/ -p              # упрощённый формат для ручного патчинга
destruct hermes index.android.bundle -o output/ --patch-map     # + точные file-offset'ы по-операндно
destruct hermes index.android.bundle -o output/ --hex           # hex-editor-friendly, абсолютные offset'ы
```

**Флаги:**
- `--decompile` — вывод `.js` вместо ассемблера.
- `--hermes-dec` — (по умолчанию включён) точный hermes-dec-формат; без него — старый упрощённый.
- `-p, --patch` — упрощённый формат специально для ручного патчинга.
- `--patch-map` — тот же точный формат + карта offset'ов каждого операнда.
- `--hex` — абсолютные file-offset'ы вместо относительных.

**Workflow для мелких правок того же размера (без переассемблирования):**
```
destruct hermes file.hbc -o output/ --patch-map
# найти байты в hex-редакторе, поправить на месте — offset'ы абсолютные, реассемблирование не нужно
```

**Workflow для структурных правок (добавить/убрать/переставить инструкции):**
```
destruct hermes file.hbc -o output/
# отредактировать output/file.hbc.hasm текстовым редактором
destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc --hermes-dec
```

---

## `destruct assemble` — сборка `.hasm` обратно в `.hbc`

```
destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc --hermes-dec
destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc   # упрощённый формат
```

**Обязательно:** `-i` с оригинальным `.hbc`/`.bundle` — текст `.hasm` ссылается на его таблицы строк/функций, сам по себе не самодостаточен.

С `--hermes-dec` пересобираются только реально изменившиеся функции; адреса пересчитываются автоматически (включая промоцию `Addr8`→`Addr8Long`, если правка вытолкнула цель прыжка за пределы диапазона байта).

---

## `destruct patch` — быстрый точечный патч Hermes-байткода

```
destruct patch file.hbc -t "isPro" --check-only   # патчит только CHECK-инструкции (безопасно)
destruct patch file.hbc -t "isPro"                 # патчит ВСЕ вхождения (может сломать логику)
destruct patch file.hbc -s "someString"            # только поиск, без патча
```

**Флаги:**
- `-t, --patch-string` — заменить строковый операнд инструкции на `true`/`false`/`nop`.
- `-s, --search` — поиск строки в байткоде.
- `--check-only` — ограничить патч только инструкциями проверки (безопаснее, чем патчить все вхождения).

---

## `destruct interactive` (или `destruct repl`) — интерактивный radare2-подобный патчер

```
destruct interactive file.bundle
destruct repl file.bundle
```

Внутри REPL:

| Команда | Действие |
|---|---|
| `s <addr>` | перейти на адрес |
| `sf <name\|#N>` | перейти к функции по имени или номеру |
| `f [filter]` | список функций (опционально с фильтром по подстроке) |
| `i` | информация о файле |
| `pf` | распечатать текущую функцию |
| `px [n]` | hex-дамп |
| `pd [n]` | дизассемблировать n инструкций |
| `wx <hex>` | записать сырые байты (без пересчёта адресов, фиксированный размер) |
| `wi <instr>` | записать инструкцию текстом (полный пересчёт адресов через LCS, размер может измениться) |
| `w` | сохранить изменения в текущий файл |
| `wq [path]` | сохранить и выйти (опционально в другой файл) |
| `q` | выйти |
| `q!` | выйти без сохранения |
| `help`, `?` | список команд |

---

## `destruct flutter` — дизассемблирование Flutter `libapp.so` (Dart AOT)

```
destruct flutter libapp.so -o output/
destruct flutter libapp.so -o output/ --decompile   # вывод в .dart вместо ассемблера
```

Требует, чтобы файл реально существовал и имел расширение `.so`/`.apk` — проверяется до запуска.

---

## `destruct elf` — дизассемблирование ELF-бинарников (нативные `.so`, ARM/ARM64/x86)

```
destruct elf libnative.so -o output/
```

Даёт читаемый ассемблерный листинг всех code-секций с аннотацией символами (если есть `.symtab`).

**`--decompile`** (только AArch64): вместо листинга ассемблера прогоняет каждую функцию через ARM64→псевдокод лифтер (`internal/arm64lift`) и пишет результат ОДНИМ файлом — `<имя>.decompiled.c` — со всеми функциями подряд, каждая под своим `// имя_символа`.

```
destruct elf libnative.so -o output/ --decompile
```

Восстанавливает реальный control flow (if/else, while/do-while, вызовы, локальные переменные, доступ к полям структур через указатели), а не плоский листинг инструкций. Для бинарников с другой архитектурой (не AArch64) завершается с понятной ошибкой — используйте обычный `destruct elf` (без флага) для сырого дизассемблирования любой архитектуры. Функция, которую не удалось лифтить (паника внутри лифтера), не прерывает весь прогон — помечается комментарием `// [failed to decompile: ...]` в выходном файле и продолжается со следующей.

---

## `destruct pe` — дизассемблирование PE-бинарников (Windows `.exe`/`.dll`)

```
destruct pe program.exe -o output/
```

Тот же принцип, что `elf`, но для формата PE.

---

## `destruct version` / `destruct help`

```
destruct version   # версия
destruct help       # полный usage-текст (встроен в бинарник)
```

---

## Общие флаги (применимы к большинству команд)

| Флаг | Значение |
|---|---|
| `-o, --output` | выходной файл/директория |
| `-i, --input` | входной `.hbc`-файл (для `assemble`/`patch`) |
| `-v, --verbose` | подробный вывод |
| `--deobfuscate` | включить деобфускацию |
| `--no-project` | не создавать структуру проекта |

---

## `lifttest` — тестовый драйвер для ARM64→C лифтера (экспериментальный, отдельный бинарник)

Не входит в основной `destruct` CLI — собирается отдельно из `cmd/lifttest/`:

```
go build -o lifttest ./cmd/lifttest/
./lifttest <путь_к_ELF> <mangled_имя_символа> [имена_параметров...]
```

**Пример:**
```
./lifttest il2cpp_memory_dumper _ZN5utils7is_rootEv
# // _ZN5utils7is_rootEv
#     return .geteuid() == 0;

./lifttest il2cpp_memory_dumper _ZN5utils10write_fileE... path data size
```

Имя символа для второго аргумента нужно узнать заранее, например через `readelf -s <файл> | grep FUNC`.

**Статус:** для разовой проверки одной функции удобнее `lifttest`; для декомпиляции ВСЕГО бинарника одним файлом — `destruct elf <файл> --decompile` (см. выше, уже часть основного CLI). Лифтер восстанавливает if/else, while/do-while (включая произвольную вложенность и составные `&&`/`||`-условия любой глубины), локальные переменные, доступ к полям структур через указатели и косвенные вызовы (`blr`/`br`, включая C++ vtable-thunk'и) — на тестовом бинарнике (`test/il2cpp_memory_dumper`) все 177 функций декомпилируются без пустого вывода и без паник. Оставшиеся ограничения (нет полноценной системы типов — имена вида `field_8`/`local_16` синтетические, не настоящие; индексная и pre/post-indexed адресация не отличается от обычной со смещением) см. в `internal/arm64lift/lift.go`, блок `TODO` в конце файла.

---

## Сборка

```
make build     # собрать destruct → ./destruct
make test      # прогнать тесты
make vet       # go vet
make clean     # убрать бинарник и output/
```

Требует `libcapstone-dev` в системе (для ELF/PE-дизассемблера и `lifttest`).
