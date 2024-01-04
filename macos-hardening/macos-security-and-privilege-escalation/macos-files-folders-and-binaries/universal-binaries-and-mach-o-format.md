# macOS 通用二进制文件 & Mach-O 格式

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

Mac OS 二进制文件通常被编译为**通用二进制文件**。一个**通用二进制文件**可以在同一个文件中**支持多个架构**。

这些二进制文件遵循**Mach-O 结构**，基本上由以下部分组成：

* 头部
* 加载命令
* 数据

![](<../../../.gitbook/assets/image (559).png>)

## Fat 头部

使用以下命令搜索文件：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC 或 FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 随后的结构体数量 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu 指定符 (int) */
cpu_subtype_t	cpusubtype;	/* 机器指定符 (int) */
uint32_t	offset;		/* 到此对象文件的文件偏移 */
uint32_t	size;		/* 此对象文件的大小 */
uint32_t	align;		/* 2 的幂次对齐 */
};
</code></pre>

头部包含**魔数**字节，后面跟着文件**包含**的**架构数量**（`nfat_arch`），每个架构都会有一个 `fat_arch` 结构体。

使用以下命令检查：

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O 通用二进制文件，包含 2 种架构：[x86_64:Mach-O 64 位可执行文件 x86_64] [arm64e:Mach-O 64 位可执行文件 arm64e]
/bin/ls (对于架构 x86_64):	Mach-O 64 位可执行文件 x86_64
/bin/ls (对于架构 arm64e):	Mach-O 64 位可执行文件 arm64e

% otool -f -v /bin/ls
Fat 头部
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>架构 x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    偏移 16384
</strong><strong>    大小 72896
</strong>    对齐 2^14 (16384)
<strong>架构 arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    偏移 98304
</strong><strong>    大小 88816
</strong>    对齐 2^14 (16384)
</code></pre>

或者使用 [Mach-O View](https://sourceforge.net/projects/machoview/) 工具：

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

正如您可能想到的，通常为 2 种架构编译的通用二进制文件的大小是为单一架构编译的文件的**两倍**。

## **Mach-O 头部**

头部包含有关文件的基本信息，例如作为 Mach-O 文件的魔数字节和有关目标架构的信息。您可以在以下位置找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
**文件类型**:

* MH\_EXECUTE (0x2): 标准Mach-O可执行文件
* MH\_DYLIB (0x6): Mach-O动态链接库（即.dylib）
* MH\_BUNDLE (0x8): Mach-O包（即.bundle）
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
或使用 [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 加载命令**

这指定了**文件在内存中的布局**。它包含了**符号表的位置**、执行开始时的主线程上下文，以及所需的**共享库**。
命令基本上指导动态加载器 **(dyld) 如何将二进制文件加载到内存中。**

加载命令都以 **load\_command** 结构开始，该结构在前面提到的 **`loader.h`** 中定义：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
大约有 **50种不同类型的加载命令**，系统会以不同方式处理。最常见的包括：`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB` 和 `LC_CODE_SIGNATURE`。

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
基本上，这种类型的加载命令定义了在二进制文件执行时，根据**数据部分中指示的偏移量**，如何加载 **\_\_TEXT**（可执行代码）和 **\_\_DATA**（进程数据）**段**。
{% endhint %}

这些命令**定义了段**，在执行进程时，这些段会被**映射**到进程的**虚拟内存空间**中。

有**不同类型**的段，例如 **\_\_TEXT** 段，包含程序的可执行代码，以及 **\_\_DATA** 段，包含进程使用的数据。这些**段位于Mach-O文件的数据部分**。

**每个段**可以进一步**划分**为多个**区段**。**加载命令结构**包含了关于各个段内**这些区段的信息**。

在头部首先找到**段头部**：

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* 适用于64位架构 */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* 包括 section_64 结构的大小 */
char		segname[16];	/* 段名称 */
uint64_t	vmaddr;		/* 该段的内存地址 */
uint64_t	vmsize;		/* 该段的内存大小 */
uint64_t	fileoff;	/* 该段的文件偏移 */
uint64_t	filesize;	/* 从文件映射的大小 */
int32_t		maxprot;	/* 最大VM保护 */
int32_t		initprot;	/* 初始VM保护 */
<strong>	uint32_t	nsects;		/* 段中的区段数量 */
</strong>	uint32_t	flags;		/* 标志 */
};
</code></pre>

段头部示例：

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

此头部定义了**其后出现的区段头部的数量**：
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
示例**节标题**：

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

如果您**添加** **节偏移量**（0x37DC）+ **架构开始**的地方的**偏移量**，在这个例子中是 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

也可以通过**命令行**获取**头部信息**：
```bash
otool -lv /bin/ls
```
此命令加载的常见段：

* **`__PAGEZERO`:** 它指示内核将**地址零**映射，以便**不能从中读取、写入或执行**。结构中的 maxprot 和 minprot 变量设置为零，表示此页面**没有读写执行权限**。
* 这种分配对于**减轻 NULL 指针解引用漏洞**很重要。
* **`__TEXT`**: 包含具有**读取**和**执行**权限的**可执行** **代码**（不可写）**。**此段的常见部分：
* `__text`: 编译后的二进制代码
* `__const`: 常量数据
* `__cstring`: 字符串常量
* `__stubs` 和 `__stubs_helper`: 在动态库加载过程中涉及
* **`__DATA`**: 包含**可读**和**可写**的数据（不可执行）**。**
* `__data`: 全局变量（已初始化）
* `__bss`: 静态变量（未初始化）
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist 等): Objective-C 运行时使用的信息
* **`__LINKEDIT`**: 包含链接器（dyld）的信息，例如 "符号、字符串和重定位表条目。"
* **`__OBJC`**: 包含 Objective-C 运行时使用的信息。尽管这些信息也可能在 \_\_DATA 段中的各种 \_\_objc\_\* 部分中找到。

### **`LC_MAIN`**

包含在**entryoff 属性**中的入口点。在加载时，**dyld** 简单地将此值**添加**到（内存中的）二进制文件的**基址**，然后**跳转**到此指令以开始执行二进制文件的代码。

### **LC\_CODE\_SIGNATURE**

包含有关 Macho-O 文件**代码签名**的信息。它只包含一个**偏移量**，指向**签名 blob**。这通常在文件的最末尾。\
然而，你可以在[**这篇博客文章**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)和这个[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)中找到有关此部分的一些信息。

### **LC\_LOAD\_DYLINKER**

包含映射共享库到进程地址空间的**动态链接器可执行文件**的**路径**。**值始终设置为 `/usr/lib/dyld`**。值得注意的是，在 macOS 中，dylib 映射发生在**用户模式**中，而不是内核模式。

### **`LC_LOAD_DYLIB`**

此加载命令描述了一个**动态** **库**依赖项，它**指示** **加载器**（dyld）**加载并链接所述库**。Mach-O 二进制文件需要的每个库都有一个 LC\_LOAD\_DYLIB 加载命令。

* 这个加载命令是类型为 **`dylib_command`** 的结构（其中包含一个描述实际依赖动态库的 struct dylib）：
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
```plaintext
你也可以通过以下命令行界面(cli)获取这些信息：
```
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
一些潜在的恶意软件相关库包括：

* **DiskArbitration**：监控USB驱动器
* **AVFoundation**：捕获音频和视频
* **CoreWLAN**：Wifi扫描。

{% hint style="info" %}
Mach-O二进制文件可以包含一个或**多个** **构造函数**，这些构造函数将在**LC\_MAIN**指定的地址**之前** **执行**。\
任何构造函数的偏移量都保存在**\_\_DATA\_CONST**段的**\_\_mod\_init\_func**部分中。
{% endhint %}

## **Mach-O 数据**

文件的核心是最后一个区域，即数据区域，它由加载命令区域中布局的多个段组成。**每个段可以包含多个数据部分**。这些部分中的每一个都**包含某一特定类型的代码或数据**。

{% hint style="success" %}
数据基本上是包含所有由加载命令**LC\_SEGMENTS\_64**加载的**信息**的部分。
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

这包括：&#x20;

* **函数表**：包含有关程序函数的信息。
* **符号表**：包含有关二进制文件使用的外部函数的信息
* 它还可能包含内部函数、变量名称等更多信息。

要检查它，您可以使用 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 工具：

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

或者从命令行界面：
```bash
size -m /bin/ls
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
