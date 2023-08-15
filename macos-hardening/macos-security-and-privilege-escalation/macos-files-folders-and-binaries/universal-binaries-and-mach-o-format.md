# macOS通用二进制文件和Mach-O格式

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

Mac OS二进制文件通常被编译为**通用二进制文件**。**通用二进制文件**可以在同一个文件中**支持多个架构**。

这些二进制文件遵循**Mach-O结构**，基本上由以下部分组成：

* 头部（Header）
* 载入命令（Load Commands）
* 数据（Data）

![](<../../../.gitbook/assets/image (559).png>)

## Fat Header

使用以下命令搜索文件：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 后面跟随的结构体数量 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPU类型（int） */
cpu_subtype_t	cpusubtype;	/* 机器类型（int） */
uint32_t	offset;		/* 该目标文件的文件偏移量 */
uint32_t	size;		/* 该目标文件的大小 */
uint32_t	align;		/* 2的幂次方对齐 */
};
</code></pre>

头部包含**魔数**（magic）字节，后面是文件包含的**架构数**（`nfat_arch`），每个架构都有一个`fat_arch`结构体。

使用以下命令进行检查：

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

或者使用[Mach-O View](https://sourceforge.net/projects/machoview/)工具：

<figure><img src="../../../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

正如你可能想到的，通常编译为2个架构的通用二进制文件**会使文件大小增加一倍**，而只编译为1个架构的文件则不会。

## **Mach-O  Header**

头部包含文件的基本信息，例如魔数字节以识别它为Mach-O文件，以及有关目标架构的信息。你可以在以下位置找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**文件类型**：

* MH\_EXECUTE (0x2)：标准的 Mach-O 可执行文件
* MH\_DYLIB (0x6)：Mach-O 动态链接库（即 .dylib）
* MH\_BUNDLE (0x8)：Mach-O bundle（即 .bundle）
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
或者使用[Mach-O View](https://sourceforge.net/projects/machoview/)：

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 加载命令**

这指定了文件在内存中的布局。它包含了符号表的位置，执行开始时的主线程上下文，以及所需的共享库。\
这些命令基本上指示动态加载器**(dyld)如何将二进制文件加载到内存中**。

加载命令都以**load\_command**结构开始，该结构在之前提到的**`loader.h`**中定义：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
大约有**50种不同类型的加载命令**，系统会以不同方式处理它们。最常见的类型有：`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`和`LC_CODE_SIGNATURE`。

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
基本上，这种类型的加载命令定义了在执行二进制文件时如何加载存储在DATA中的段。
{% endhint %}

这些命令定义了在执行过程中映射到进程的虚拟内存空间中的段。

有不同类型的段，比如保存程序可执行代码的**\_\_TEXT**段，以及包含进程使用的数据的**\_\_DATA**段。这些段位于Mach-O文件的数据部分中。

**每个段**可以进一步**划分**为多个**区块**。加载命令结构包含了有关各个段内部的这些区块的**信息**。

在头部中首先找到**段头**：

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* includes sizeof section_64 structs */
char		segname[16];	/* segment name */
uint64_t	vmaddr;		/* memory address of this segment */
uint64_t	vmsize;		/* memory size of this segment */
uint64_t	fileoff;	/* file offset of this segment */
uint64_t	filesize;	/* amount to map from the file */
int32_t		maxprot;	/* maximum VM protection */
int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

段头的示例：

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

该头部定义了在其后出现的**区块头的数量**：
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
示例的**章节标题**：

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

如果你**添加**了**章节偏移量**（0x37DC）和**架构开始的偏移量**，在这个例子中是`0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

也可以通过**命令行**获取**头部信息**：
```bash
otool -lv /bin/ls
```
以下是关于MacOS文件、文件夹和二进制文件的内容。

加载的常见段：

* **`__PAGEZERO`：**它指示内核将**地址零**映射到**不可读取、写入或执行**的位置。结构中的maxprot和minprot变量设置为零，表示该页面**没有读写执行权限**。这种分配对于**减轻空指针解引用漏洞**非常重要。
* **`__TEXT`：**包含**可执行代码**和**只读数据**。该段的常见部分有：
* `__text`：编译的二进制代码
* `__const`：常量数据
* `__cstring`：字符串常量
* `__stubs`和`__stubs_helper`：在动态库加载过程中使用
* **`__DATA`：**包含**可写数据**。
* `__data`：全局变量（已初始化）
* `__bss`：静态变量（未初始化）
* `__objc_*`（\_\_objc\_classlist，\_\_objc\_protolist等）：Objective-C运行时使用的信息
* **`__LINKEDIT`：**包含链接器（dyld）的信息，如“符号、字符串和重定位表项”。
* **`__OBJC`：**包含Objective-C运行时使用的信息。尽管此信息也可以在\_\_DATA段中找到，但位于各种\_\_objc\_\*部分中。

### **`LC_MAIN`**

包含**entryoff属性**中的入口点。在加载时，**dyld**只需将此值添加到（内存中的）二进制文件的基址，然后跳转到此指令以开始执行二进制文件的代码。

### **LC\_CODE\_SIGNATURE**

包含有关Macho-O文件的**代码签名的信息**。它只包含一个**指向签名块的偏移量**。这通常位于文件的末尾。\
但是，您可以在[**此博客文章**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)和此[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)中找到有关此部分的一些信息。

### **LC\_LOAD\_DYLINKER**

包含**动态链接器可执行文件的路径**，该文件将共享库映射到进程地址空间。**值始终设置为`/usr/lib/dyld`**。重要的是要注意，在macOS中，dylib映射发生在**用户模式**而不是内核模式中。

### **`LC_LOAD_DYLIB`**

此加载命令描述了一个**动态库依赖项**，它指示**加载器**（dyld）**加载和链接该库**。Mach-O二进制文件所需的每个库都有一个LC\_LOAD\_DYLIB加载命令。

* 此加载命令是**`dylib_command`**类型的结构（其中包含描述实际依赖动态库的struct dylib）：
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
![](<../../../.gitbook/assets/image (558).png>)

您也可以使用命令行界面获取此信息：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
一些潜在的与恶意软件相关的库包括：

* **DiskArbitration**：监控USB驱动器
* **AVFoundation**：捕获音频和视频
* **CoreWLAN**：Wifi扫描。

{% hint style="info" %}
Mach-O二进制文件可以包含一个或多个构造函数，这些函数将在**LC\_MAIN**指定的地址之前执行。任何构造函数的偏移量都保存在**\_\_DATA\_CONST**段的**\_\_mod\_init\_func**部分中。
{% endhint %}

## **Mach-O数据**

文件的核心是最后一个区域，即数据区域，它由加载命令区域中的多个段组成。**每个段可以包含多个数据段**。每个数据段都包含一种特定类型的代码或数据。

{% hint style="success" %}
数据基本上是包含由加载命令LC\_SEGMENTS\_64加载的所有信息的部分。
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

这包括：

* **函数表**：保存有关程序函数的信息。
* **符号表**：包含二进制文件使用的外部函数的信息
* 它还可以包含内部函数、变量名等等。

您可以使用[Mach-O View](https://sourceforge.net/projects/machoview/)工具来检查：

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

或者使用命令行：
```bash
size -m /bin/ls
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
