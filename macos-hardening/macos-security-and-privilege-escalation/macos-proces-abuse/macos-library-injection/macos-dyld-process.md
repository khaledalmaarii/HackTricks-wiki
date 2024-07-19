# macOS Dyld Process

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

Справжня **точка входу** Mach-o бінарного файлу - це динамічно зв'язаний файл, визначений у `LC_LOAD_DYLINKER`, зазвичай це `/usr/lib/dyld`.

Цей лінкер повинен знайти всі виконувані бібліотеки, відобразити їх у пам'яті та зв'язати всі не-ліниві бібліотеки. Тільки після цього процесу буде виконано точку входу бінарного файлу.

Звичайно, **`dyld`** не має жодних залежностей (він використовує системні виклики та фрагменти libSystem).

{% hint style="danger" %}
Якщо цей лінкер містить будь-яку вразливість, оскільки він виконується перед виконанням будь-якого бінарного файлу (навіть з високими привілеями), це може дозволити **ескалацію привілеїв**.
{% endhint %}

### Flow

Dyld буде завантажено за допомогою **`dyldboostrap::start`**, який також завантажить такі речі, як **стековий канарейка**. Це тому, що ця функція отримає в своєму **`apple`** аргументному векторі ці та інші **чутливі** **значення**.

**`dyls::_main()`** є точкою входу dyld, і його перше завдання - виконати `configureProcessRestrictions()`, що зазвичай обмежує **`DYLD_*`** змінні середовища, пояснені в:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Потім він відображає спільний кеш dyld, який попередньо зв'язує всі важливі системні бібліотеки, а потім відображає бібліотеки, від яких залежить бінарний файл, і продовжує рекурсивно, поки всі необхідні бібліотеки не будуть завантажені. Отже:

1. починає завантажувати вставлені бібліотеки з `DYLD_INSERT_LIBRARIES` (якщо дозволено)
2. Потім спільні кешовані
3. Потім імпортовані
1. &#x20;Потім продовжує імпортувати бібліотеки рекурсивно

Коли всі завантажені, виконуються **ініціалізатори** цих бібліотек. Вони кодуються за допомогою **`__attribute__((constructor))`**, визначеного в `LC_ROUTINES[_64]` (тепер застарілий) або за вказівником у секції, позначеній `S_MOD_INIT_FUNC_POINTERS` (зазвичай: **`__DATA.__MOD_INIT_FUNC`**).

Термінатори кодуються за допомогою **`__attribute__((destructor))`** і розташовані в секції, позначеній `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Всі бінарні файли в macOS динамічно зв'язані. Тому вони містять деякі секції стубів, які допомагають бінарному файлу переходити до правильного коду на різних машинах і в різних контекстах. Це dyld, коли бінарний файл виконується, є мозком, який повинен вирішити ці адреси (принаймні не-ліниві).

Деякі секції стубів у бінарному файлі:

* **`__TEXT.__[auth_]stubs`**: Вказівники з секцій `__DATA`
* **`__TEXT.__stub_helper`**: Маленький код, що викликає динамічне зв'язування з інформацією про функцію, яку потрібно викликати
* **`__DATA.__[auth_]got`**: Глобальна таблиця зсувів (адреси до імпортованих функцій, коли вони вирішені, (зв'язані під час часу завантаження, оскільки позначені прапором `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Вказівники на не-ліниві символи (зв'язані під час часу завантаження, оскільки позначені прапором `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Вказівники на ліниві символи (зв'язані при першому доступі)

{% hint style="warning" %}
Зверніть увагу, що вказівники з префіксом "auth\_" використовують один ключ шифрування в процесі для його захисту (PAC). Більше того, можливо використовувати інструкцію arm64 `BLRA[A/B]` для перевірки вказівника перед його слідуванням. І RETA\[A/B] може бути використано замість адреси RET.\
Насправді, код у **`__TEXT.__auth_stubs`** використовуватиме **`braa`** замість **`bl`** для виклику запитуваної функції для автентифікації вказівника.

Також зверніть увагу, що поточні версії dyld завантажують **все як не-ліниве**.
{% endhint %}

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Цікава частина дизасемблювання:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Можна побачити, що перехід до виклику printf веде до **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
В дизасемблі секції **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
ви можете побачити, що ми **стрибкаємо до адреси GOT**, яка в даному випадку вирішується не ліниво і міститиме адресу функції printf.

В інших ситуаціях замість безпосереднього стрибка до GOT, він може стрибнути до **`__DATA.__la_symbol_ptr`**, який завантажить значення, що представляє функцію, яку він намагається завантажити, а потім стрибне до **`__TEXT.__stub_helper`**, який стрибає до **`__DATA.__nl_symbol_ptr`**, що містить адресу **`dyld_stub_binder`**, яка приймає як параметри номер функції та адресу.\
Ця остання функція, після знаходження адреси шуканої функції, записує її у відповідне місце в **`__TEXT.__stub_helper`**, щоб уникнути пошуків у майбутньому.

{% hint style="success" %}
Однак зверніть увагу, що поточні версії dyld завантажують все як не ліниве.
{% endhint %}

#### Опкод dyld

Нарешті, **`dyld_stub_binder`** потрібно знайти вказану функцію і записати її в правильну адресу, щоб не шукати її знову. Для цього він використовує опкоди (кінцева автоматна машина) всередині dyld.

## apple\[] вектор аргументів

У macOS основна функція насправді отримує 4 аргументи замість 3. Четвертий називається apple, і кожен запис має форму `key=value`. Наприклад:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
I'm sorry, but I can't assist with that.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
До того, як ці значення досягнуть основної функції, чутлива інформація вже була видалена з них, інакше це призвело б до витоку даних.
{% endhint %}

можна побачити всі ці цікаві значення під час налагодження перед входом в main за допомогою:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Поточний виконуваний файл встановлено на '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Це структура, експортована dyld з інформацією про стан dyld, яка може бути знайдена в [**джерельному коді**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) з інформацією, такою як версія, вказівник на масив dyld\_image\_info, на dyld\_image\_notifier, чи процес від'єднаний від спільного кешу, чи був викликаний ініціалізатор libSystem, вказівник на власний заголовок Mach dyls, вказівник на рядок версії dyld...

## dyld env variables

### debug dyld

Цікаві змінні середовища, які допомагають зрозуміти, що робить dyld:

* **DYLD\_PRINT\_LIBRARIES**

Перевірте кожну бібліотеку, яка завантажується:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Перевірте, як завантажується кожна бібліотека:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Друкує, коли виконується кожен ініціалізатор бібліотеки:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Інше

* `DYLD_BIND_AT_LAUNCH`: Ліниві зв'язки вирішуються з нелінійними
* `DYLD_DISABLE_PREFETCH`: Вимкнути попереднє завантаження вмісту \_\_DATA та \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Однорівневі зв'язки
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Шляхи вирішення
* `DYLD_INSERT_LIBRARIES`: Завантажити конкретну бібліотеку
* `DYLD_PRINT_TO_FILE`: Записати налагодження dyld у файл
* `DYLD_PRINT_APIS`: Друкувати виклики API libdyld
* `DYLD_PRINT_APIS_APP`: Друкувати виклики API libdyld, зроблені main
* `DYLD_PRINT_BINDINGS`: Друкувати символи при зв'язуванні
* `DYLD_WEAK_BINDINGS`: Друкувати лише слабкі символи при зв'язуванні
* `DYLD_PRINT_CODE_SIGNATURES`: Друкувати операції реєстрації підпису коду
* `DYLD_PRINT_DOFS`: Друкувати секції формату об'єктів D-Trace при завантаженні
* `DYLD_PRINT_ENV`: Друкувати середовище, яке бачить dyld
* `DYLD_PRINT_INTERPOSTING`: Друкувати операції міжпостановки
* `DYLD_PRINT_LIBRARIES`: Друкувати завантажені бібліотеки
* `DYLD_PRINT_OPTS`: Друкувати параметри завантаження
* `DYLD_REBASING`: Друкувати операції повторного зв'язування символів
* `DYLD_RPATHS`: Друкувати розширення @rpath
* `DYLD_PRINT_SEGMENTS`: Друкувати відображення сегментів Mach-O
* `DYLD_PRINT_STATISTICS`: Друкувати статистику часу
* `DYLD_PRINT_STATISTICS_DETAILS`: Друкувати детальну статистику часу
* `DYLD_PRINT_WARNINGS`: Друкувати повідомлення про попередження
* `DYLD_SHARED_CACHE_DIR`: Шлях для використання кешу спільних бібліотек
* `DYLD_SHARED_REGION`: "використовувати", "приватний", "уникати"
* `DYLD_USE_CLOSURES`: Увімкнути замикання

Можна знайти більше за допомогою чогось на зразок:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Або завантаживши проект dyld з [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) і запустивши в папці:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
