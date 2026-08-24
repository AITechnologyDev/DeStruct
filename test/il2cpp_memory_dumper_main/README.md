# IL2CPP Memory Dumper v2.0

Standalone бинарник для дампа `libil2cpp.so` и `global-metadata.dat` из памяти запущенного процесса.
**Не требует инжекта, Zygisk, JNI, ptrace, Frida!**

## Что делает

1. Находит процесс игры по имени пакета или PID
2. Парсит `/proc/PID/maps` — находит регионы памяти библиотеки
3. Читает `/proc/PID/mem` — сливает все сегменты в файл
4. Фиксит ELF заголовки (восстанавливает Section Header)
5. Извлекает `global-metadata.dat` если она в памяти
6. **NEW:** Deep scan — ищет metadata внутри каждого региона памяти
7. **NEW:** IL2CPP API finder — находит функции по сигнатурам в `libunity.so`

## Сборка

```bash
chmod +x build.sh
./build.sh
```

Или вручную:
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Для Android (через NDK):
```bash
$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-21 ..
make
```

## Использование

**Требуется root на Android!**

### Быстрый старт

```bash
# Дамп всего (lib + metadata)
su -c "./il2cpp_memory_dumper dump-all -n com.example.game -o ./mygame"

# По PID
su -c "./il2cpp_memory_dumper dump-all -p 1234 -o ./mygame"
```

### Команды

```bash
# Основные:
dump-lib       - Дамп libil2cpp.so по имени
dump-meta      - Дамп global-metadata.dat по имени файла
dump-all       - Дамп обоих

# Сканирование (для защищённых игр):
scan-lib       - Сканировать память на ELF заголовки и дампить
scan-meta      - Сканировать начала регионов на metadata
scan-all       - Сканировать и дампить оба

# Расширенные:
deep-scan      - ГЛУБОКОЕ сканирование ВСЕЙ памяти (медленно, но тщательно)
find-api       - Найти IL2CPP API функции в libunity.so по сигнатурам
list           - Показать регионы памяти процесса
```

### Для защищённых игр (Standoff 2, PUBG, и т.д.)

Когда `libil2cpp.so` не существует как отдельный файл (встроен в `libunity.so`) и metadata зашифрована:

```bash
# Шаг 1: Найти IL2CPP API функции
su -c "./il2cpp_memory_dumper find-api -n com.axlebolt.standoff2"

# Шаг 2: Попробовать deep scan (может занять 5-15 минут)
su -c "./il2cpp_memory_dumper deep-scan -n com.axlebolt.standoff2 -o ./standoff_dump"

# Шаг 3: Если deep scan не нашёл — попробовать во время загрузки игры
# (запустить игру, быстро выполнить deep-scan пока игра загружается)
```

## После дампа

```bash
# Используй Perfare/Il2CppDumper
./Il2CppDumper libil2cpp_fixed.so global-metadata.dat ./output
```

## Как это работает

```
Процесс игры
    │
    ├─ /proc/PID/maps  →  находим адреса libil2cpp.so / libunity.so
    │
    ├─ /proc/PID/mem   →  читаем память по адресам
    │
    ├─ Сканируем на:    →  ELF magic (0x7F454C46)
    │                    →  Metadata sanity (0xFAB11BAF)
    │                    →  IL2CPP API signatures
    │
    └─ Собираем → фиксим ELF → готово!
```

## Deep Scan

Обычный `scan-meta` проверяет только **начало** каждого региона памяти. Но metadata может быть:
- Внутри региона (не в начале)
- Временно расшифрована и смещена
- В `libunity.so` среди других данных

`deep-scan` читает **каждый байт** каждого readable региона, ищет сигнатуру `0xFAB11BAF`.

**Время работы:** 5-15 минут для процесса с 3-4 GB памяти.

## IL2CPP API Finder

Находит функции IL2CPP runtime по ARM64 сигнатурам прологов:
- `il2cpp_init`
- `il2cpp_class_from_name`
- `il2cpp_string_new`
- `il2cpp_domain_get`

Полезно для ручного hooking'а или Frida-скриптов.

## Ограничения

- Требует root (для чтения `/proc/PID/mem` чужого процесса)
- Некоторые защищённые игры могут:
  - Шифровать metadata в памяти
  - Использовать anti-dump (обнаружение чтения памяти)
  - Мапить библиотеку с `(deleted)` — всё равно читается через `/proc/mem`
- ELF fixing — базовый, для сложных случаев используй `sofix` из maiyao1988/elf-dump-fix

## Устранение неполадок

### "No metadata found"
- Попробуй `deep-scan` вместо `scan-meta`
- Запускай во время загрузки игры (не в главном меню)
- Metadata может быть зашифрована — нужен runtime hook

### "Library dump failed"
- Используй `scan-lib` вместо `dump-lib`
- Для встроенного IL2CPP (в `libunity.so`) используй `scan-all`

### "Permission denied"
- Убедись, что запускаешь через `su -c "..."`
- Проверь SELinux: `getenforce` (если Enforcing, попробуй `setenforce 0`)

## Альтернативы

- **kp7742/IL2CPPDumper** — похожий подход, но только для ARM32
- **maiyao1988/elf-dump-fix** — более продвинутый fixer для ELF
- **GameGuardian** — GUI инструмент с Lua скриптами для дампа
- **Frida + frida-il2cpp-bridge** — если Frida работает на устройстве
