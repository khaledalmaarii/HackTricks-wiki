# macOS 应用程序 - 检查、调试和模糊测试

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧。

</details>

## 静态分析

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
### jtool2

该工具可以用作 **codesign**、**otool** 和 **objdump** 的**替代品**，并提供了一些额外的功能。[**在此处下载**](http://www.newosxbook.com/tools/jtool.html)或使用 `brew` 安装。
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** 可在 **macOS** 中找到，而 **`ldid`** 可在 **iOS** 中找到
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) 是一个用于检查 **.pkg** 文件（安装程序）并在安装之前查看其中内容的工具。\
这些安装程序包含 `preinstall` 和 `postinstall` bash 脚本，恶意软件作者通常会滥用这些脚本来 **持久化** **恶意软件**。

### hdiutil

此工具允许 **挂载** Apple 磁盘映像（**.dmg**）文件，以便在运行任何内容之前进行检查：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
它将被挂载在 `/Volumes`

### Objective-C

#### 元数据

{% hint style="danger" %}
请注意，用 Objective-C 编写的程序在编译成 [Mach-O 二进制文件](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) 时**保留**它们的类声明。这些类声明**包括**以下名称和类型：
{% endhint %}

* 类
* 类方法
* 类实例变量

您可以使用 [**class-dump**](https://github.com/nygard/class-dump) 来获取这些信息：
```bash
class-dump Kindle.app
```
请注意，这些名称可能会被混淆，以使二进制文件的逆向工程更加困难。

#### 函数调用

当在使用Objective-C的二进制文件中调用函数时，编译后的代码不会直接调用那个函数，而是会调用**`objc_msgSend`**。这个函数将调用最终的函数：

![](<../../../.gitbook/assets/image (560).png>)

这个函数期望的参数有：

* 第一个参数（**self**）是“指向将要接收消息的**类实例**的指针”。或者更简单地说，它是方法被调用的对象。如果方法是类方法，这将是类对象（整体）的一个实例；对于实例方法，self将指向作为对象的类的一个实例化实例。
* 第二个参数（**op**），是“处理消息的方法的选择器”。再次简单地说，这就是**方法的名称**。
* 剩余的参数是方法所需的任何**值**（op）。

| **参数**          | **寄存器**                                                      | **（用于）objc_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **第1个参数**     | **rdi**                                                         | **self: 方法被调用的对象**                             |
| **第2个参数**     | **rsi**                                                         | **op: 方法的名称**                                     |
| **第3个参数**     | **rdx**                                                         | **方法的第1个参数**                                    |
| **第4个参数**     | **rcx**                                                         | **方法的第2个参数**                                    |
| **第5个参数**     | **r8**                                                          | **方法的第3个参数**                                    |
| **第6个参数**     | **r9**                                                          | **方法的第4个参数**                                    |
| **第7个及以上参数** | <p><strong>rsp+</strong><br><strong>(在栈上)</strong></p>       | **方法的第5个及以上参数**                               |

### Swift

对于Swift二进制文件，由于有Objective-C兼容性，有时可以使用[class-dump](https://github.com/nygard/class-dump/)提取声明，但并非总是如此。

使用**`jtool -l`** 或 **`otool -l`** 命令行，可以找到以**`__swift5`** 前缀开头的几个部分：
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
您可以在[**这篇博客文章中找到有关这些部分存储信息的更多信息**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。

此外，**Swift 二进制文件可能包含符号**（例如，库需要存储符号以便可以调用其函数）。**符号通常以一种不太美观的方式包含有关函数名称的信息**，因此它们非常有用，而且有“**demanglers**”可以恢复原始名称：
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### 打包二进制文件

* 检查高熵
* 检查字符串（如果几乎没有可理解的字符串，表示已打包）
* MacOS的UPX打包器会生成一个名为“\_\_XHDR”的段

## 动态分析

{% hint style="warning" %}
请注意，为了调试二进制文件，**需要禁用SIP**（`csrutil disable` 或 `csrutil enable --without debug`），或者将二进制文件复制到临时文件夹并**移除签名**，使用 `codesign --remove-signature <binary-path>`，或允许调试二进制文件（您可以使用[此脚本](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)）
{% endhint %}

{% hint style="warning" %}
请注意，为了**对系统二进制文件进行插桩**（例如 `cloudconfigurationd`）在macOS上，**必须禁用SIP**（仅移除签名是不够的）。
{% endhint %}

### 统一日志

MacOS会生成大量日志，在运行应用程序试图理解**它在做什么**时非常有用。

此外，有些日志会包含标签 `<private>` 来**隐藏**一些**用户**或**计算机**的**可识别**信息。然而，可以**安装证书来披露这些信息**。请按照[**这里**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)的说明操作。

### Hopper

#### 左侧面板

在Hopper的左侧面板中，可以看到二进制文件的符号（**标签**），程序和函数列表（**Proc**）以及字符串（**Str**）。这些并不是所有的字符串，而是在Mac-O文件的几个部分中定义的字符串（如_cstring或`objc_methname`）。

#### 中间面板

在中间面板中，您可以看到**反汇编代码**。您可以通过点击相应的图标，以**原始**反汇编、**图形**、**反编译**和**二进制**形式查看：

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

在代码对象上右键点击，您可以查看**对该对象的引用**，甚至更改其名称（在反编译的伪代码中不起作用）：

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

此外，在**中间下方您可以编写python命令**。

#### 右侧面板

在右侧面板中，您可以看到诸如**导航历史**（这样您就知道您是如何到达当前情况的），**调用图**，您可以看到所有**调用此函数的函数**以及所有**此函数调用的函数**，以及**局部变量**信息。

### dtrace

它允许用户在极其**低级别**访问应用程序，并为用户提供一种方式来**追踪** **程序**，甚至改变它们的执行流程。Dtrace使用**探针**，这些探针**遍布整个内核**，位于系统调用的开始和结束等位置。

DTrace使用**`dtrace_probe_create`**函数为每个系统调用创建一个探针。这些探针可以在每个系统调用的**入口和出口点**触发。与DTrace的交互通过/dev/dtrace进行，它仅对root用户可用。

{% hint style="success" %}
要在不完全禁用SIP保护的情况下启用Dtrace，您可以在恢复模式下执行：`csrutil enable --without dtrace`

您也可以**`dtrace`** 或 **`dtruss`** 二进制文件，这些是**您已编译**的。
{% endhint %}

可以使用以下命令获取dtrace的可用探针：
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
探针名称由四部分组成：提供者、模块、函数和名称（`fbt:mach_kernel:ptrace:entry`）。如果您没有指定名称的某个部分，Dtrace 将应用该部分作为通配符。

要配置 DTrace 以激活探针并指定在触发时执行什么操作，我们将需要使用 D 语言。

更详细的解释和更多示例可以在 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) 找到

#### 示例

运行 `man -k dtrace` 列出**可用的 DTrace 脚本**。示例：`sudo dtruss -n binary`

* 在线
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* 脚本
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

即使在**SIP激活**状态下，你也可以使用这个工具。
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) 是一个非常有用的工具，用于检查进程正在执行的与进程相关的操作（例如，监控一个进程正在创建哪些新进程）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) 是一个打印进程间关系的工具。\
你需要使用像 **`sudo eslogger fork exec rename create > cap.json`** 这样的命令来监控你的mac（启动此命令的终端需要FDA）。然后你可以在这个工具中加载json文件来查看所有关系：

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) 允许监控文件事件（如创建、修改和删除），提供有关这些事件的详细信息。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) 是一个GUI工具，具有Windows用户可能从Microsoft Sysinternal的 _Procmon_ 熟悉的外观和感觉。它允许你开始和停止记录所有类型的事件，通过类别（文件、进程、网络等）过滤它们，并将记录的事件保存为json文件。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) 是Xcode开发者工具的一部分 - 用于监控应用程序性能，识别内存泄漏和跟踪文件系统活动。

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

允许跟踪进程执行的操作：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**TaskExplorer**](https://objective-see.com/products/taskexplorer.html) 可用于查看二进制文件使用的**库**、它正在使用的**文件**以及**网络**连接。\
它还会将二进制进程与 **virustotal** 对比，并显示有关二进制文件的信息。

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

在 [**这篇博客文章**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) 中，你可以找到一个示例，说明如何**调试正在运行的守护进程**，该守护进程使用了 **`PT_DENY_ATTACH`** 来阻止调试，即使 SIP 被禁用了。

### lldb

**lldb** 是 **macOS** 二进制**调试**的事实上的工具。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
你可以在使用lldb时设置intel风格，方法是在你的家目录中创建一个名为 **`.lldbinit`** 的文件，并写入以下内容：
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
在lldb中，使用`process save-core`命令转储进程。
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) 命令</strong></td><td><strong>描述</strong></td></tr><tr><td><strong>run (r)</strong></td><td>开始执行，将一直执行直到遇到断点或进程终止。</td></tr><tr><td><strong>continue (c)</strong></td><td>继续执行被调试的进程。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>执行下一条指令。此命令将跳过函数调用。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>执行下一条指令。与nexti命令不同，此命令将进入函数调用。</td></tr><tr><td><strong>finish (f)</strong></td><td>执行当前函数（“帧”）中的其余指令，返回并停止。</td></tr><tr><td><strong>control + c</strong></td><td>暂停执行。如果进程已经运行(run (r))或继续(continue (c))，这将导致进程在当前执行的位置停止。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #任何名为main的函数</p><p>b &#x3C;binname>`main #二进制文件的main函数</p><p>b set -n main --shlib &#x3C;lib_name> #指定二进制文件的main函数</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #断点列表</p><p>br e/dis &#x3C;num> #启用/禁用断点</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #获取断点命令的帮助</p><p>help memory write #获取写入内存的帮助</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>以空终止字符串的形式显示内存。</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>以汇编指令的形式显示内存。</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>以字节的形式显示内存。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>打印参数引用的对象</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>注意，大多数Apple的Objective-C API或方法返回对象，因此应该通过“print object” (po)命令显示。如果po没有产生有意义的输出，请使用<code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #在该地址写入AAAA<br>memory write -f s $rip+0x11f+7 "AAAA" #在地址写入AAAA</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #反汇编当前函数</p><p>dis -n &#x3C;funcname> #反汇编函数</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #反汇编函数<br>dis -c 6 #反汇编6行<br>dis -c 0x100003764 -e 0x100003768 # 从一个地址到另一个地址<br>dis -p -c 4 # 从当前地址开始反汇编</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # 检查x1寄存器中的3个组件数组</td></tr></tbody></table>

{% hint style="info" %}
当调用**`objc_sendMsg`**函数时，**rsi**寄存器保存方法的**名称**作为空终止（“C”）字符串。要通过lldb打印名称，请执行：

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### 反动态分析

#### VM检测

* 命令**`sysctl hw.model`**在**宿主是MacOS**时返回"Mac"，但在VM中返回不同的内容。
* 通过操作**`hw.logicalcpu`**和**`hw.physicalcpu`**的值，一些恶意软件尝试检测是否是VM。
* 一些恶意软件还可以根据MAC地址（00:50:56）**检测**机器是否是**VMware**。
* 也可以使用如下简单代码**查找进程是否被调试**：
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //进程被调试 }`
* 它还可以调用**`ptrace`**系统调用，并使用**`PT_DENY_ATTACH`**标志。这将**阻止**调试器附加和跟踪。
* 您可以检查**`sysctl`**或**`ptrace`**函数是否被**导入**（但恶意软件可能会动态导入它）
* 正如这篇文章所指出的，“[击败反调试技术：macOS ptrace变体](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)”：\
“_信息Process # exited with **status = 45 (0x0000002d)** 通常是调试目标使用**PT_DENY_ATTACH**的明显迹象_”

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **分析崩溃的进程并将崩溃报告保存到磁盘**。崩溃报告包含可以**帮助开发者诊断**崩溃原因的信息。\
对于在每用户launchd上下文中**运行的应用程序和其他进程**，ReportCrash作为LaunchAgent运行，并将崩溃报告保存在用户的`~/Library/Logs/DiagnosticReports/`中\
对于守护进程、在系统launchd上下文中**运行的其他进程**和其他特权进程，ReportCrash作为LaunchDaemon运行，并将崩溃报告保存在系统的`/Library/Logs/DiagnosticReports`中

如果您担心崩溃报告**被发送给Apple**，您可以禁用它们。如果不担心，崩溃报告可以帮助您**弄清楚服务器是如何崩溃的**。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 睡眠

在 MacOS 中进行模糊测试时，重要的是不允许 Mac 进入睡眠状态：

* systemsetup -setsleep Never
* pmset, 系统偏好设置
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 断开

如果您通过 SSH 连接进行模糊测试，确保会话不会中断是很重要的。因此请修改 sshd_config 文件：

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 内部处理程序

**查看以下页面** 了解如何找到哪个应用程序负责**处理指定的方案或协议：**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### 枚举网络进程

这对于找到管理网络数据的进程很有趣：
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
或使用 `netstat` 或 `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

适用于CLI工具

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

它在macOS GUI工具上“**就是有效**”。注意，一些macOS应用有一些特定的要求，比如独特的文件名、正确的扩展名、需要从沙盒中读取文件（`~/Library/Containers/com.apple.Safari/Data`）...

一些例子：

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
```markdown
{% endcode %}

### 更多关于MacOS Fuzzing的信息

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考资料

* [**OS X 事件响应：脚本编写与分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS hacking成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的hacking技巧。

</details>
```
