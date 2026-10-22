# 📡 interceptor

Минималистичный x86-отладчик для Windows, написанный с нуля на Rust. Работает напрямую с Win32 Debugging API, парсит PE-экспорты прямо из памяти целевого процесса, ставит программные и аппаратные точки останова, перехватывает вызовы функций с произвольной спецификацией дампа аргументов и сканирует всю доступную память на текстовые/hex-паттерны.

Проект задуман как учебный, но решает практические задачи: анализ crackme, перехват расшифрованных данных после `CryptDecrypt`, поиск утечек секретов (пароли, ключи, токены) в памяти, реверс-инжиниринг закрытых приложений без исходников.

## Возможности

- **Запуск и attach**: старт target'а под отладкой (`DEBUG_ONLY_THIS_PROCESS`) или подключение к уже запущенному процессу по PID (`DebugActiveProcess` + `SeDebugPrivilege`).
- **Парсинг экспортов из памяти**: читает таблицу экспорта каждого загруженного модуля через `ReadProcessMemory` — работает с динамически подгружаемыми DLL и ASLR.
- **Поиск функций**: `find <pattern>` — по кэшу загруженных экспортов.
- **Сканирование памяти**: `scan [-a|-w|-x] [-i] <pattern>` — поиск ASCII / UTF-16LE / hex-байтов по всем committed-регионам целевого процесса с hex-дампом контекста и подписью модуля.
- **Точки останова**:
  - **Программные** (`0xCC` / `INT 3`) с автоматическим восстановлением и повторной установкой — `break <func> [enter|exit]`.
  - **Режим enter**: остановка на входе в функцию.
  - **Режим exit**: остановка на выходе с **универсальной спецификацией дампа** аргументов — не привязан к сигнатуре конкретной функции.
  - **Аппаратные** через регистры `DR0..DR3` / `DR7` — `hwbreak <addr> exec|write|read`.
- **Pending breakpoints**: брейкпоинт на функцию, которая ещё не загружена, автоматически установится при загрузке соответствующей DLL.
- **Инспекция**:
  - `dump <addr> [size]` — hex-дамп с постраничным чтением и обработкой недоступных участков (size — десятичный или `0x...`).
  - `regs` — регистры остановленного потока.
  - `bt` — backtrace по EBP-цепочке.
  - `disas <addr> [count]` — дизассемблирование через `iced-x86`.
  - `info modules` / `info exports <module>` — модули и их экспорты.
- **Управление выполнением**: `run` / `continue` / `step`.

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

> **Почему 32-битная сборка?** Отладчик использует x86 `CONTEXT` и раскладку стека x86 (аргументы функций читаются через `[ESP+N]`, регистры — `EIP`/`ESP`/`EBP`/`EAX`). Для 64-битных target'ов логика `CONTEXT` и ABI отличается — это отдельная задача (WOW64).

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

### Пример 1: перехват расшифрованных данных `CryptDecrypt`

```
dbg> find crypt
  0x75CB8EC0  CryptDecrypt  [advapi32.dll]
  ...

dbg> break CryptDecrypt exit [esp+20]:[[esp+24]]
[+] Breakpoint: CryptDecrypt (0x75CB8EC0) [exit spec=[esp+20]:[[esp+24]]] in advapi32.dll

dbg> run

[+] HIT (enter→arming exit): CryptDecrypt at 0x75CB8EC0
    return addr : 0x00578B30
    entry ESP   : 0x001AEFB0
    --- args ---
    arg[0] [esp+4]  = 0x00A12B40
    arg[1] [esp+8]  = 0x00000000
    arg[2] [esp+12] = 0x00000001
    arg[3] [esp+16] = 0x00000000
    arg[4] [esp+20] = 0x7FC80010
    arg[5] [esp+24] = 0x001AEFC8
    --- planned dumps ---
    [esp+20]:[[esp+24]]: addr=0x7FC80010
    (type 'continue' to run to function return)
   --- disassembly @ 0x75CB8EC0 ---
  0x75CB8EC0  8B FF                    mov edi,edi
  0x75CB8EC2  55                       push ebp
  ...

dbg> continue

[+] HIT (return): CryptDecrypt back to 0x00578B30
    EAX = 0x00000001 (1)
    --- dump [esp+20]:[[esp+24]] @ 0x7FC80010 ---
  0x7FC80010  53 65 63 72 65 74 20 54 65 78 74 20 41 42 43 44  |Secret Text ABCD|
  0x7FC80020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|

   (type 'continue' to resume target)
```

Если поставить BP **без спецификации** (`break CryptDecrypt exit`), на возврате будут напечатаны только сырые значения аргументов и подсказка. Это удобно для первого знакомства с незнакомой функцией — сразу видно, какие аргументы указывают на память.

### Пример 2: поиск секретов в памяти

```
dbg> scan password
[+] Scanning 312 region(s), 87.4 MB

  [ascii] 0x00512A48  (target.exe)
  0x00512A40  4C 6F 67 69 6E 3D 00 70 61 73 73 77 6F 72 64 3D  |Login=.password=|
  0x00512A50  4D 79 53 33 63 72 33 74 21 00 00 00 00 00 00 00  |MyS3cr3t!.......|

  [ascii] 0x0142C1F0  (target.exe)
  0x0142C1E0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
  0x0142C1F0  70 61 73 73 77 6F 72 64 00 00 00 00 00 00 00 00  |password........|

[+] 2 match(es) in 312 region(s) scanned
```

Варианты поиска:

```
scan -a password         # ASCII + UTF-16LE одновременно
scan -w password         # только UTF-16LE (типичные Windows-строки)
scan -i -a PassWord      # регистронезависимый поиск (ASCII)
scan -x 70 61 73 73      # hex-байты "pass"
scan salt key secret     # многословный ASCII-паттерн
```

До 100 матчей за сессию и до 32 матчей в одном регионе — защита от лавины результатов на коротких паттернах.

### Пример 3: пошаговый разбор после BP

```
dbg> break SomeFunc enter
dbg> run
[+] HIT (enter): SomeFunc at 0x00401A20
    EIP=0x00401A20  ESP=0x0019FF34  EBP=0x0019FF80
    EAX=0x00000001  EBX=0x7FFD8000  ECX=0x00000000  EDX=0x00A12B40
    ...
dbg> step
[+] step done. EIP=0x00401A21
dbg> step
[+] step done. EIP=0x00401A23
dbg> bt
  #0  0x00401A23  (EIP, current)
  #1  0x00402B10  (EBP=0x0019FF80)
  #2  0x00403150  (EBP=0x0019FFA0)
```

## Команды

| Команда | Алиасы | Описание |
|---|---|---|
| `find <pattern>` | `f` | Поиск функции по подстроке среди загруженных экспортов |
| `scan [-a\|-w\|-x] [-i] <pattern>` | `search` / `mem` | Поиск ASCII / UTF-16LE / hex-паттерна в памяти процесса |
| `break <func> [enter\|exit] [spec]` | `b` | Установить BP на вход или выход; `spec` — спецификация дампа (см. ниже) |
| `run` / `continue` | `r` / `c` | Продолжить выполнение |
| `step` | `s` | Один шаг процессора |
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

## Спецификация дампа для exit-BP

В режиме `exit` аргументы функции читаются из **snapshot'а стека, снятого на входе**, а регистры — из контекста **на выходе**. Спецификация позволяет указать, что именно дампить:

```
break <func> exit <addr>:<len>[,<addr>:<len>]...
```

- `<addr>` — откуда взять адрес буфера:
  - `[esp+N]` — dword из snapshot'а стека на входе;
  - `eax`, `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`, `esp` — значение регистра на выходе.
- `<len>` — откуда взять длину:
  - `[esp+N]` — значение из snapshot'а (не разыменовывается);
  - `[[esp+N]]` — dword по указателю из snapshot'а, разрешается на выходе;
  - `eax..esp` — значение регистра на выходе;
  - `<N>` — фиксированное число байт (десятичное или `0x...`);
  - `str` — C-string (до `\0`);
  - `wstr` — UTF-16LE строка (до двойного `\0`);
  - `auto` — попробовать C-string, иначе 64 байта.

Несколько буферов перечисляются через запятую. Несколько примеров:

| Функция | Спека |
|---|---|
| `CryptDecrypt` / `CryptEncrypt` | `[esp+20]:[[esp+24]]` |
| `Send` (winsock) | `[esp+8]:[esp+12]` |
| `recv` (winsock) | `[esp+8]:eax` |
| `ReadFile` | `[esp+8]:[[esp+16]]` |
| `MessageBoxA` | `[esp+8]:str` |
| `MessageBoxW` | `[esp+8]:wstr` |
| `RegQueryValueExA` | `[esp+20]:[[esp+24]]` |

## Архитектура

```
src/
├── main.rs       # REPL-цикл, парсинг команд
├── debugger.rs   # Win32 Debug API, BP менеджер, spec-парсер, сканер памяти
├── pe_parser.rs  # Парсинг таблицы экспорта PE из памяти
└── hexdump.rs    # Форматирование hex-дампа
```

**Ключевые идеи:**

- **Software breakpoint**: замена первого байта инструкции на `0xCC` (`INT 3`). При срабатывании — восстановление оригинального байта, `EIP -= 1`, выполнение оригинальной инструкции, затем возврат `0xCC` на место.
- **Повторяемость BP через trap-флаг**: после срабатывания BP «разряжается», выполняется одна оригинальная инструкция с выставленным `EFLAGS.TF`, приходит `EXCEPTION_SINGLE_STEP`, `0xCC` возвращается на место. Это и даёт `continue`/`step` без потери BP.
- **Exit-BP через `0xCC` на адресе возврата**: на входе сохраняется snapshot стека (16 dword от `ESP`), включая адрес возврата. На адрес возврата ставится временный BP. На возврате по спеке разрешаются адреса и длины, читаются буферы, печатается hex-dump.
- **Универсальные dump-спеки**: вместо хардкода `pbData`/`pdwDataLen` пользователь сам указывает, что читать. `AddrSource`/`LenSource` — AST-подобные enum'ы, разбираемые из строки.
- **Pending breakpoints**: `break <func>` при отсутствии функции в памяти сохраняется в очередь и разрешается в `LOAD_DLL_DEBUG_EVENT` после парсинга экспорта только что загруженной DLL.
- **HW breakpoints**: через `DR0..DR3` / `DR7` в `CONTEXT`, применяются к текущему остановленному потоку и ко всем новым (`CREATE_THREAD_DEBUG_EVENT`).
- **Сканирование памяти**: `VirtualQueryEx` по всему адресному пространству, фильтрация по `MEM_COMMIT`, `PAGE_GUARD`, `PAGE_NOACCESS`, чтение чанками по 64 KiB с перекрытием на длину паттерна. Для каждого матча — hex-dump 80 байт контекста и подпись модуля, если адрес принадлежит загруженному образу.

## Ограничения

- Только 32-битные target'ы.
- Не поддерживается: обработка произвольных исключений (AV, C++ EH), символы PDB, дизассемблирование с именами, hot-patch-прологи.
- HW breakpoints при attach не применяются к уже существующим чужим потокам (только к текущему и новым). Обход через `CreateToolhelp32Snapshot` — в планах.
- `temp_breakpoints` не привязан к TID: если одна и та же функция вызывается из двух потоков одновременно, контексты могут перезаписать друг друга. Для одиночных вызовов — не проблема.
- `read` в x86 HW BP работает как read/write (архитектурное ограничение: «только чтение» в DR7 не поддерживается).
- Одно-поточный REPL: все события debug loop обрабатываются в главном потоке.
- Сканер памяти не различает регионы по типу (`MEM_IMAGE` / `MEM_MAPPED` / `MEM_PRIVATE`) — сканирует все committed-регионы.

## Планы

- [x] Универсальные dump-спеки для exit-BP (вместо хардкода `pbData`/`pdwDataLen`).
- [x] Сканирование памяти (`scan`) с ASCII / UTF-16LE / hex-паттернами.
- [x] Аппаратные точки останова через `DR0..DR3` / `DR7`.
- [ ] Привязка `temp_breakpoints` к TID (`HashMap<(u32, u32), ...>`).
- [ ] Полный обход потоков при attach через `CreateToolhelp32Snapshot`.
- [ ] Поддержка x64 через WOW64 (`Wow64GetThreadContext` / `Wow64SetThreadContext`).
- [ ] Символы PDB для отображения имён функций и строк исходного кода.
- [ ] Conditional breakpoints (`break <func> if <expr>`).
- [ ] Скриптовый движок для автоматизации (например, `rhai`).
- [ ] Сохранение / восстановление состояния сессии.

## Лицензия

MIT (или укажите свою).

## Благодарности

- [`windows-sys`](https://crates.io/crates/windows-sys) — Win32 API биндинги
- [`iced-x86`](https://crates.io/crates/iced-x86) — дизассемблер
- [`anyhow`](https://crates.io/crates/anyhow) — обработка ошибок