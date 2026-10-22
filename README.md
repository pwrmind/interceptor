# 📡 interceptor

Минималистичный x86-отладчик для Windows, написанный с нуля на Rust. Работает напрямую с Win32 Debugging API, парсит PE-экспорты из памяти целевого процесса, ставит программные и аппаратные точки останова и умеет перехватывать вызовы функций (включая чтение аргументов и результата).

Проект создан как учебный, но успешно решает практические задачи: анализ crackme, перехват расшифрованных данных после `CryptDecrypt`, реверс-инжиниринг закрытых приложений без исходников.

## Возможности

- **Запуск и attach**: стартует target под отладкой (`DEBUG_ONLY_THIS_PROCESS`) или подключается к уже запущенному процессу по PID (`DebugActiveProcess` + `SeDebugPrivilege`).
- **Парсинг экспортов из памяти**: читает таблицу экспорта каждого загруженного модуля через `ReadProcessMemory` — работает с динамически подгружаемыми DLL и ASLR.
- **Поиск функций**: `find <pattern>` — поиск по кэшу загруженных экспортов.
- **Точки останова**:
  - **Программные** (`0xCC` / `INT 3`) с автоматическим восстановлением и повторной установкой — `break <func> [enter|exit]`.
  - **Режим enter**: остановка на входе в функцию.
  - **Режим exit**: остановка на выходе, с сохранением и чтением аргументов функции (x86 stdcall ABI).
  - **Аппаратные** через регистры `DR0..DR3` / `DR7` — `hwbreak <addr> exec|write|read`.
- **Pending breakpoints**: брейкпоинт на функцию, которая ещё не загружена, автоматически установится при загрузке соответствующей DLL.
- **Инспекция**:
  - `dump <addr> [size]` — hex-дамп памяти с постраничным чтением и корректной обработкой недоступных участков.
  - `regs` — регистры текущего остановленного потока.
  - `bt` — backtrace по EBP-цепочке.
  - `disas <addr> [count]` — дизассемблирование через `iced-x86`.
  - `info modules` / `info exports <module>` — список модулей и их экспортов.
- **Управление выполнением**: `run` / `continue` / `step`.
- **Перехват результата функции**: при `break <func> exit` отладчик на выходе читает `EAX` (результат), длину и данные из аргументов (например, `pbData` / `pdwDataLen` для `CryptDecrypt`) и делает автоматический hex-dump.

## Требования

- Windows (x86_64 хост, 32-битный target для отладки)
- Rust с target `i686-pc-windows-msvc`
- MSVC toolchain

```powershell
rustup target add i686-pc-windows-msvc
```

## Сборка

```powershell
cargo build --release --target i686-pc-windows-msvc
```

Готовый бинарник: `target\i686-pc-windows-msvc\release\interceptor.exe`

> **Почему 32-битная сборка?** Отладчик использует `CONTEXT` x86 и раскладку стека x86 (аргументы функций читаются через `[ESP+N]`). Для 64-битных target'ов логика `CONTEXT` и ABI отличается — это отдельная задача (WOW64).

## Использование

### Запуск target

```powershell
interceptor.exe C:\path\to\target.exe
```

Отладчик запустит процесс под отладкой, обработает стартовые события (создание процесса, загрузка DLL, loader breakpoint) и вернёт управление в REPL.

### Attach к уже запущенному процессу

```powershell
interceptor.exe -p <pid>
```

Требует прав администратора для `SeDebugPrivilege` (отладчик включает привилегию автоматически, но `OpenProcess` на защищённые процессы может потребовать elevation).

### Пример: перехват `CryptDecrypt`

```
dbg> find crypt
  0x75CB8EC0  CryptDecrypt  [advapi32.dll]
  ...

dbg> break CryptDecrypt exit
[+] Breakpoint: CryptDecrypt (0x75CB8EC0) [exit] in advapi32.dll

dbg> run
[+] HIT (enter→arming exit): CryptDecrypt at 0x75CB8EC0
    return addr : 0x00578B30
    pbData      : 0x7FC80010
    pdwDataLen  : 0x001AEFC8
    (type 'continue' to run to function return)
   --- disassembly @ 0x75CB8EC0 ---
  0x75CB8EC0  8B FF                    mov edi,edi
  0x75CB8EC2  55                       push ebp
  ...

dbg> continue
[+] HIT (return): CryptDecrypt back to 0x00578B30
    EAX = 0x00000001 (1)
    decrypted length: 32 bytes
    decrypted bytes at 0x7FC80010:

  0x7FC80010  53 65 63 72 65 74 20 54 65 78 74 20 41 42 43 44  |Secret Text ABCD|
  0x7FC80020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|

   (type 'continue' to resume target)
```

## Команды

| Команда | Алиасы | Описание |
|---|---|---|
| `find <pattern>` | `f` | Поиск функции по подстроке среди загруженных экспортов |
| `break <func> [enter\|exit]` | `b` | Установить BP на вход или выход функции |
| `run` / `continue` | `r` / `c` | Продолжить выполнение |
| `step` | `s` | Один шаг |
| `regs` | `reg` | Показать регистры |
| `bt` | | Backtrace (EBP chain) |
| `dump <hexaddr> [size]` | `d` | Hex-дамп (size — dec или `0x...`) |
| `disas <hexaddr> [count]` | `u` | Дизассемблировать по адресу |
| `info modules` | `i m` | Список загруженных модулей |
| `info exports <module>` | `i e` | Экспорты конкретного модуля |
| `hwbreak <hexaddr> <kind>` | `hb` | Аппаратный BP (`exec` / `write` / `read`) |
| `hwlist` | `hwl` | Список HW BP |
| `hwclear` | `hwc` | Снять все HW BP |
| `quit` | `q` / `exit` | Выход |

## Архитектура

```
src/
├── main.rs       # REPL-цикл, парсинг команд
├── debugger.rs   # Win32 Debug API, BP менеджер, обработка событий
├── pe_parser.rs  # Парсинг таблицы экспорта PE из памяти
└── hexdump.rs    # Форматирование hex-дампа
```

**Ключевые идеи:**

- **Software breakpoint**: замена первого байта инструкции на `0xCC` (`INT 3`). При срабатывании — восстановление оригинального байта, коррекция `EIP -= 1`, выполнение оригинальной инструкции, затем возврат `0xCC` на место.
- **Exit-breakpoint через trap-флаг**: на входе сохраняются адреса аргументов и адрес возврата (из `[ESP]`), устанавливается временный `0xCC` на адрес возврата. После возврата из функции читаются `EAX`, `pdwDataLen`, и буфер `pbData`.
- **Повторяемость BP**: после срабатывания BP «разряжается», выполняется одна оригинальная инструкция с выставленным trap-флагом (`EFLAGS.TF`), затем `0xCC` возвращается на место — `EXCEPTION_SINGLE_STEP` используется как «после-инструкции» хук.
- **Pending breakpoints**: пользователь ставит `break <func>`, но функции ещё нет в памяти — запрос сохраняется и разрешается при `LOAD_DLL_DEBUG_EVENT` после парсинга экспорта.
- **HW breakpoints**: через `DR0..DR3` / `DR7` в `CONTEXT`, применяются к текущему потоку и всем новым (`CREATE_THREAD_DEBUG_EVENT`).

## Ограничения

- Только 32-битные target'ы.
- Не поддерживается: обработка произвольных исключений (AV, C++ EH), символы PDB, дизассемблирование с именами, hot-patch-прологи.
- HW breakpoints не применяются к уже существующим чужим потокам при attach.
- `read` в x86 HW BP работает как read/write (архитектурное ограничение: «только чтение» в DR7 не поддерживается).
- Одно-поточный REPL: все события debug loop обрабатываются в главном потоке.

## Планы

- [ ] Поддержка x64 через WOW64 (`Wow64GetThreadContext` / `Wow64SetThreadContext`).
- [ ] Символы PDB для отображения имён функций и строк исходного кода.
- [ ] Conditional breakpoints (`break <func> if <expr>`).
- [ ] Watchpoints на переменные (read/write HW BP по адресу данных).
- [ ] Плагины / скриптовый движок для автоматизации (например, `rhai`).
- [ ] Сохранение / восстановление состояния сессии.

## Лицензия

MIT (или укажите свою).

## Благодарности

- [`windows-sys`](https://crates.io/crates/windows-sys) — Win32 API биндинги
- [`iced-x86`](https://crates.io/crates/iced-x86) — дизассемблер
- [`anyhow`](https://crates.io/crates/anyhow) — обработка ошибок
