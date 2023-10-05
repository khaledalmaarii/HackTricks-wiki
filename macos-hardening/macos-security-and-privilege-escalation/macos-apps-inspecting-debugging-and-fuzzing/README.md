# macOS应用程序 - 检查、调试和模糊测试

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

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
{% endcode %}

### jtool2

该工具可以用作**codesign**、**otool**和**objdump**的**替代品**，并提供了一些额外的功能。[**在这里下载**](http://www.newosxbook.com/tools/jtool.html)或使用`brew`安装。
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
### Codesign

Codesign（代码签名）是macOS中的一种安全机制，用于验证应用程序的身份和完整性。通过对应用程序进行数字签名，可以确保应用程序未被篡改或恶意注入。

在macOS中，每个应用程序都必须经过代码签名才能被系统信任和运行。签名是使用开发者的证书和私钥生成的，这些证书和私钥由苹果公司颁发。签名包含应用程序的哈希值和开发者的数字签名，以及其他相关信息。

当用户尝试运行一个被签名的应用程序时，macOS会验证签名的有效性。如果签名无效或被篡改，系统会发出警告并阻止应用程序的运行。

通过使用codesign命令，开发者可以对应用程序进行签名和验证。签名应该在应用程序的构建过程中完成，并且应该使用开发者的私钥进行签名。

签名应该是开发过程中的一个重要步骤，以确保应用程序的安全性和完整性。
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
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) 是一个有用的工具，可以在安装之前检查 **.pkg** 文件（安装程序）并查看其中的内容。\
这些安装程序包含 `preinstall` 和 `postinstall` 的 bash 脚本，恶意软件作者通常会滥用这些脚本来**持久化**恶意软件。

### hdiutil

这个工具允许将苹果磁盘映像（**.dmg**）文件挂载起来，在运行任何内容之前进行检查：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
它将被挂载在`/Volumes`目录下。

### Objective-C

#### 元数据

{% hint style="danger" %}
请注意，使用Objective-C编写的程序在编译为[Mach-O二进制文件](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)时会**保留**它们的类声明。这些类声明包括以下信息：
{% endhint %}

* 类
* 类方法
* 类实例变量

您可以使用[class-dump](https://github.com/nygard/class-dump)获取这些信息：
```bash
class-dump Kindle.app
```
注意，这些名称可能会被混淆，以增加二进制反向工程的难度。

#### 函数调用

当在使用Objective-C的二进制文件中调用函数时，编译后的代码不会直接调用该函数，而是调用**`objc_msgSend`**。这将调用最终的函数：

![](<../../../.gitbook/assets/image (560).png>)

该函数期望的参数如下：

* 第一个参数（**self**）是“指向**接收消息的类的实例的指针**”。简单来说，它是方法被调用的对象。如果方法是类方法，则这将是类对象的一个实例（作为一个整体），而对于实例方法，self将指向作为对象的类的一个实例。
* 第二个参数（**op**）是“处理消息的方法的选择器”。简单来说，这只是**方法的名称**。
* 剩余的参数是方法所需的任何**值**（op）。

| **参数**           | **寄存器**                                                      | **（对于）objc_msgSend**                              |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **第一个参数**    | **rdi**                                                         | **self：方法被调用的对象**                            |
| **第二个参数**    | **rsi**                                                         | **op：方法的名称**                                    |
| **第三个参数**    | **rdx**                                                         | **方法的第一个参数**                                  |
| **第四个参数**    | **rcx**                                                         | **方法的第二个参数**                                  |
| **第五个参数**    | **r8**                                                          | **方法的第三个参数**                                  |
| **第六个参数**    | **r9**                                                          | **方法的第四个参数**                                  |
| **第七个及以上参数** | <p><strong>rsp+</strong><br><strong>（在堆栈上）</strong></p> | **方法的第五个及以上参数**                            |

### Swift

对于Swift二进制文件，由于存在Objective-C兼容性，有时可以使用[class-dump](https://github.com/nygard/class-dump/)提取声明，但并非总是有效。

使用**`jtool -l`**或**`otool -l`**命令行，可以找到以**`__swift5`**前缀开头的多个部分：
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
您可以在[**此博客文章中找到有关这些部分存储的信息的更多信息**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。

### 打包的二进制文件

* 检查高熵
* 检查字符串（如果几乎没有可理解的字符串，则为打包）
* MacOS的UPX打包程序会生成一个名为"\_\_XHDR"的部分

## 动态分析

{% hint style="warning" %}
请注意，为了调试二进制文件，需要禁用SIP（`csrutil disable`或`csrutil enable --without debug`），或将二进制文件复制到临时文件夹并使用`codesign --remove-signature <binary-path>`删除签名，或允许对二进制文件进行调试（可以使用[此脚本](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)）
{% endhint %}

{% hint style="warning" %}
请注意，为了在macOS上**检测系统二进制文件**（如`cloudconfigurationd`），必须禁用SIP（仅删除签名不起作用）。
{% endhint %}

### 统一日志

MacOS会生成大量日志，当运行应用程序时，这些日志可以非常有用，以了解它在做什么。

此外，有一些日志将包含标签`<private>`，以隐藏一些**用户**或**计算机**可识别的信息。但是，可以**安装证书以公开此信息**。请按照[**此处**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)的说明进行操作。

### Hopper

#### 左侧面板

在hopper的左侧面板中，可以看到二进制文件的符号（**Labels**），过程和函数的列表（**Proc**）以及字符串（**Str**）。这些不是所有的字符串，而是在Mac-O文件的几个部分中定义的字符串（如_cstring或`objc_methname`）。

#### 中间面板

在中间面板中，您可以看到**反汇编代码**。您可以通过单击相应的图标，以**原始**、**图形**、**反编译**和**二进制**的方式查看它：

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

右键单击代码对象，可以查看对该对象的**引用/来自**，甚至更改其名称（在反编译的伪代码中无效）：

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

此外，在**中间下方，您可以编写Python命令**。

#### 右侧面板

在右侧面板中，您可以查看有趣的信息，例如**导航历史记录**（以便了解您如何到达当前情况）、**调用图**（您可以查看所有调用此函数的函数以及此函数调用的所有函数）和**局部变量**信息。

### dtrace

它允许用户以极其**低级别**访问应用程序，并为用户提供了一种**跟踪**程序甚至更改其执行流程的方法。Dtrace使用**探针**，这些探针**分布在内核的各个位置**，例如系统调用的开始和结束。

DTrace使用**`dtrace_probe_create`**函数为每个系统调用创建一个探针。这些探针可以在每个系统调用的**入口和出口点触发**。与DTrace的交互通过/dev/dtrace进行，该设备仅对root用户可用。

{% hint style="success" %}
要在不完全禁用SIP保护的情况下启用Dtrace，可以在恢复模式下执行：`csrutil enable --without dtrace`

您还可以**运行您已编译的**`dtrace`或`dtruss`二进制文件。
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
探针名称由四个部分组成：提供者、模块、函数和名称（`fbt:mach_kernel:ptrace:entry`）。如果您没有指定名称的某个部分，DTrace将将该部分视为通配符。

要配置DTrace以激活探针并指定触发时要执行的操作，我们需要使用D语言。

更详细的解释和更多示例可以在[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)中找到。

#### 示例

运行`man -k dtrace`以列出可用的**DTrace脚本**。示例：`sudo dtruss -n binary`

* 在行中
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

The `dtruss` command is a powerful tool for inspecting and debugging macOS applications. It allows you to trace system calls and signals made by a specific process, providing valuable insights into its behavior and potential vulnerabilities.

To use `dtruss`, simply run the command followed by the name or process ID of the target application. This will initiate the tracing process and display a detailed log of all system calls and signals generated by the application.

By analyzing the `dtruss` output, you can identify any suspicious or unexpected behavior that may indicate a security issue. This can include unauthorized file access, network communication, or privilege escalation attempts.

Additionally, `dtruss` can be used for fuzzing purposes. By injecting malformed or unexpected inputs into the target application, you can observe how it handles these inputs and potentially uncover vulnerabilities such as crashes or memory leaks.

It is important to note that `dtruss` requires root privileges to trace system calls made by other processes. Therefore, it is recommended to use this tool in a controlled and isolated environment, such as a virtual machine or sandboxed environment, to prevent any unintended consequences.

Overall, `dtruss` is a valuable tool for inspecting, debugging, and fuzzing macOS applications, providing essential insights into their behavior and potential security vulnerabilities.
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

即使启用了**SIP**，您仍然可以使用此方法。
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) 是一个非常有用的工具，用于检查进程执行的与进程相关的操作（例如，监视进程创建的新进程）。

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) 允许监视文件事件（如创建、修改和删除），并提供有关这些事件的详细信息。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) 是一个具有类似于 Windows 用户熟悉的 Microsoft Sysinternal 的 _Procmon_ 的外观和感觉的 GUI 工具。它允许您启动和停止记录各种类型的事件，按类别（文件、进程、网络等）对其进行过滤，并将记录的事件保存为 json 文件。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) 是 Xcode 的开发工具的一部分，用于监视应用程序性能、识别内存泄漏和跟踪文件系统活动。

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

允许跟踪进程执行的操作：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) 是一个有用的工具，可以查看二进制文件使用的**库**，它正在使用的**文件**以及**网络**连接。\
它还会对二进制进程进行**virustotal**检查，并显示有关二进制文件的信息。

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

在[**这篇博文**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)中，您可以找到一个关于如何**调试正在运行的守护进程**的示例，该守护进程使用了**`PT_DENY_ATTACH`**来防止调试，即使SIP已禁用。

### lldb

**lldb** 是用于**macOS**二进制文件**调试**的事实上的工具。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
您可以在使用lldb时设置intel风格，只需在您的主文件夹中创建一个名为**`.lldbinit`**的文件，并添加以下行：
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
在lldb中，使用`process save-core`命令转储进程。
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) 命令</strong></td><td><strong>描述</strong></td></tr><tr><td><strong>run (r)</strong></td><td>开始执行，直到遇到断点或进程终止。</td></tr><tr><td><strong>continue (c)</strong></td><td>继续执行被调试的进程。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>执行下一条指令。该命令会跳过函数调用。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>执行下一条指令。与nexti命令不同，该命令会进入函数调用。</td></tr><tr><td><strong>finish (f)</strong></td><td>执行当前函数（“frame”）中剩余的指令，然后返回并停止。</td></tr><tr><td><strong>control + c</strong></td><td>暂停执行。如果进程已经运行（r）或继续（c），这将导致进程在当前位置停止执行。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #任何名为main的函数</p><p>b &#x3C;binname>`main #二进制文件的主函数</p><p>b set -n main --shlib &#x3C;lib_name> #指定二进制文件的主函数</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #断点列表</p><p>br e/dis &#x3C;num> #启用/禁用断点</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #获取断点命令的帮助</p><p>help memory write #获取写入内存的帮助</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>将内存显示为以空字符结尾的字符串。</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>将内存显示为汇编指令。</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>将内存显示为字节。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>这将打印参数引用的对象</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>请注意，大多数苹果的Objective-C API或方法返回对象，因此应通过“print object”（po）命令显示。如果po没有产生有意义的输出，请使用<x/b></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #在该地址写入AAAA<br>memory write -f s $rip+0x11f+7 "AAAA" #在该地址写入AAAA</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #反汇编当前函数</p><p>dis -n &#x3C;funcname> #反汇编函数</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #反汇编函数<br>dis -c 6 #反汇编6行<br>dis -c 0x100003764 -e 0x100003768 #从一个地址到另一个地址<br>dis -p -c 4 #从当前地址开始反汇编</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #检查x1寄存器中的3个组件的数组</td></tr></tbody></table>

{% hint style="info" %}
在调用**`objc_sendMsg`**函数时，**rsi**寄存器保存方法的名称，作为以空字符结尾的（“C”）字符串。要通过lldb打印名称，请执行以下操作：

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### 反动态分析

#### 虚拟机检测

* 命令**`sysctl hw.model`**在主机为MacOS时返回"Mac"，而在虚拟机上返回其他值。
* 通过调整**`hw.logicalcpu`**和**`hw.physicalcpu`**的值，一些恶意软件尝试检测是否为虚拟机。
* 一些恶意软件还可以根据MAC地址（00:50:56）判断机器是否为VMware。
* 还可以通过简单的代码判断进程是否正在被调试：
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* 还可以使用**`ptrace`**系统调用和**`PT_DENY_ATTACH`**标志来阻止调试器的附加和跟踪。
* 可以检查是否导入了**`sysctl`**或**`ptrace`**函数（但恶意软件可能会动态导入它）。
* 如在此文档中所述：“[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)”：\
“_消息“Process # exited with **status = 45 (0x0000002d)**”通常是调试目标正在使用**PT\_DENY\_ATTACH**的明显迹象_”。
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash（报告崩溃）**分析崩溃的进程并将崩溃报告保存到磁盘**。崩溃报告包含的信息可以**帮助开发人员诊断**崩溃的原因。\
对于在每个用户的launchd上下文中运行的应用程序和其他进程，ReportCrash作为LaunchAgent运行，并将崩溃报告保存在用户的`~/Library/Logs/DiagnosticReports/`目录下。\
对于守护进程、在系统launchd上下文中运行的其他进程和其他特权进程，ReportCrash作为LaunchDaemon运行，并将崩溃报告保存在系统的`/Library/Logs/DiagnosticReports`目录下。

如果你担心崩溃报告**被发送给Apple**，你可以禁用它们。如果不禁用，崩溃报告可以用来**找出服务器崩溃的原因**。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 睡眠

在进行MacOS模糊测试时，不允许Mac进入睡眠状态非常重要：

* systemsetup -setsleep Never
* pmset，系统偏好设置
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH断开连接

如果您通过SSH连接进行模糊测试，确保会话不会断开非常重要。因此，请更改sshd\_config文件：

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 内部处理程序

**查看以下页面**以了解如何找到负责**处理指定方案或协议的应用程序：**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### 枚举网络进程

这是一个有趣的方法，可以找到管理网络数据的进程：
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
或者使用`netstat`或`lsof`

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

它可以与macOS的GUI工具一起使用。请注意，一些macOS应用程序具有特定要求，例如唯一的文件名、正确的扩展名，需要从沙盒(`~/Library/Containers/com.apple.Safari/Data`)中读取文件...

一些示例：

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
### 更多关于Fuzzing MacOS的信息

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考资料

* [**OS X事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
