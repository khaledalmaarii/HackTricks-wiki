# macOS Dyld 进程

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

- 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
- 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** 上关注我们**。
- 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

Mach-o 二进制文件的真正**入口点**是动态链接器，在 `LC_LOAD_DYLINKER` 中定义，通常为 `/usr/lib/dyld`。

这个链接器需要定位所有可执行库，在内存中映射它们，并链接所有非懒加载库。只有在此过程完成后，二进制文件的入口点才会被执行。

当然，**`dyld`** 没有任何依赖（它使用系统调用和 libSystem 片段）。

{% hint style="danger" %}
如果此链接器包含任何漏洞，因为它在执行任何二进制文件（甚至是高度特权的二进制文件）之前被执行，将有可能**提升权限**。
{% endhint %}

### 流程

Dyld 将由 **`dyldboostrap::start`** 加载，它还会加载诸如**栈保护**之类的东西。这是因为此函数将在其**`apple`**参数向量中接收此类**敏感**的**值**。

**`dyls::_main()`** 是 dyld 的入口点，它的第一个任务是运行 `configureProcessRestrictions()`，通常会限制**`DYLD_*`**环境变量，详细说明在：

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

然后，它映射 dyld 共享缓存，其中预链接了所有重要的系统库，然后映射二进制文件依赖的库，并递归继续，直到加载所有需要的库。因此：

1. 它开始加载插入的库，使用 `DYLD_INSERT_LIBRARIES`（如果允许）
2. 然后是共享缓存中的库
3. 然后是导入的库
4. 然后继续递归导入库

一旦所有库都加载完毕，这些库的**初始化程序**将被运行。这些程序使用**`__attribute__((constructor))`**编写，在 `LC_ROUTINES[_64]` 中定义（现在已弃用），或者通过指针在一个带有 `S_MOD_INIT_FUNC_POINTERS` 标志的部分中（通常为：**`__DATA.__MOD_INIT_FUNC`**）。

终结器使用**`__attribute__((destructor))`**编写，并位于一个带有 `S_MOD_TERM_FUNC_POINTERS` 标志的部分中（**`__DATA.__mod_term_func`**）。

### 存根

macOS 中的所有二进制文件都是动态链接的。因此，它们包含一些存根部分，帮助二进制文件在不同的机器和上下文中跳转到正确的代码。在执行二进制文件时，需要 dyld 来解析这些地址（至少是非懒加载的地址）。

二进制文件中的一些存根部分：

- **`__TEXT.__[auth_]stubs`**：来自 `__DATA` 部分的指针
- **`__TEXT.__stub_helper`**：调用带有要调用函数信息的动态链接的小代码
- **`__DATA.__[auth_]got`**：全局偏移表（指向导入函数的地址，在解析后绑定（在加载时绑定，因为它标记为 `S_NON_LAZY_SYMBOL_POINTERS`））
- **`__DATA.__nl_symbol_ptr`**：非懒加载符号指针（在加载时绑定，因为它标记为 `S_NON_LAZY_SYMBOL_POINTERS`）
- **`__DATA.__la_symbol_ptr`**：惰性符号指针（首次访问时绑定）

{% hint style="warning" %}
请注意，带有前缀 "auth\_" 的指针使用一个进程内加密密钥进行保护（PAC）。此外，可以使用 arm64 指令 `BLRA[A/B]` 在跟随指针之前验证指针。而 RETA\[A/B\] 可以用于替代 RET 地址。\
实际上，**`__TEXT.__auth_stubs`** 中的代码将使用 **`braa`** 而不是 **`bl`** 来调用请求的函数以验证指针。

还要注意，当前的 dyld 版本将**所有内容加载为非懒加载**。
{% endhint %}

### 查找惰性符号
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
有趣的反汇编部分：
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
可以看到跳转到调用 printf 的位置是在 **`__TEXT.__stubs`**：
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
在**`__stubs`**部分的反汇编中：
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
你可以看到我们正在**跳转到GOT的地址**，在这种情况下，它是通过非延迟解析的，将包含printf函数的地址。

在其他情况下，而不是直接跳转到GOT，它可以跳转到**`__DATA.__la_symbol_ptr`**，它将加载一个代表它正在尝试加载的函数的值，然后跳转到**`__TEXT.__stub_helper`**，它跳转到包含**`dyld_stub_binder`**地址的**`__DATA.__nl_symbol_ptr`**，该函数接受函数编号和地址作为参数。\
在找到搜索的函数地址后，该最后一个函数将其写入**`__TEXT.__stub_helper`**中的相应位置，以避免将来进行查找。

{% hint style="success" %}
但请注意，当前dyld版本将所有内容都作为非延迟加载。
{% endhint %}

#### Dyld操作码

最后，**`dyld_stub_binder`**需要找到指定的函数并将其写入正确的地址，以免再次搜索。为此，它在dyld内部使用操作码（有限状态机）。

## apple\[]参数向量

在macOS中，主函数实际上接收4个参数而不是3个。第四个称为apple，每个条目的形式为`key=value`。例如：
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
结果：
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
当这些值到达主函数时，敏感信息已经被删除，否则可能会导致数据泄漏。
{% endhint %}

在进入主函数之前，可以通过调试查看所有这些有趣的值：

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>当前可执行文件设置为'/tmp/a' (arm64)。
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

这是由dyld导出的一个结构，包含有关dyld状态的信息，可以在[**源代码**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html)中找到，包括版本、指向dyld\_image\_info数组的指针、指向dyld\_image\_notifier的指针、如果进程与共享缓存分离、是否调用了libSystem初始化程序、指向dyld自身Mach头文件的指针、指向dyld版本字符串的指针...

## dyld环境变量

### 调试dyld

有助于了解dyld操作的有趣环境变量：

* **DYLD\_PRINT\_LIBRARIES**

检查加载的每个库：
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

检查每个库是如何加载的：
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

打印每个库初始化程序运行时的信息:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### 其他

* `DYLD_BIND_AT_LAUNCH`: 惰性绑定将使用非惰性绑定解析
* `DYLD_DISABLE_PREFETCH`: 禁用对 \_\_DATA 和 \_\_LINKEDIT 内容的预取
* `DYLD_FORCE_FLAT_NAMESPACE`: 单级绑定
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 解析路径
* `DYLD_INSERT_LIBRARIES`: 加载特定库
* `DYLD_PRINT_TO_FILE`: 将 dyld 调试信息写入文件
* `DYLD_PRINT_APIS`: 打印 libdyld API 调用
* `DYLD_PRINT_APIS_APP`: 打印主程序调用的 libdyld API
* `DYLD_PRINT_BINDINGS`: 绑定时打印符号
* `DYLD_WEAK_BINDINGS`: 仅在绑定时打印弱符号
* `DYLD_PRINT_CODE_SIGNATURES`: 打印代码签名注册操作
* `DYLD_PRINT_DOFS`: 打印加载的 D-Trace 对象格式部分
* `DYLD_PRINT_ENV`: 打印 dyld 可见的环境变量
* `DYLD_PRINT_INTERPOSTING`: 打印 interposing 操作
* `DYLD_PRINT_LIBRARIES`: 打印加载的库
* `DYLD_PRINT_OPTS`: 打印加载选项
* `DYLD_REBASING`: 打印符号重新定位操作
* `DYLD_RPATHS`: 打印 @rpath 的扩展
* `DYLD_PRINT_SEGMENTS`: 打印 Mach-O 段的映射
* `DYLD_PRINT_STATISTICS`: 打印时间统计信息
* `DYLD_PRINT_STATISTICS_DETAILS`: 打印详细的时间统计信息
* `DYLD_PRINT_WARNINGS`: 打印警告消息
* `DYLD_SHARED_CACHE_DIR`: 用于共享库缓存的路径
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: 启用闭包

可以通过类似以下方式找到更多内容：
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
或者从[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)下载dyld项目，并在文件夹内运行：
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## 参考资料

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。 

</details>
