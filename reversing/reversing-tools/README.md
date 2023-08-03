<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# Wasm反编译器 / Wat编译器

在线工具:

* 使用[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)将wasm（二进制）反编译为wat（明文）
* 使用[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)将wat编译为wasm
* 你也可以尝试使用[https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)进行反编译

软件工具:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

# .Net反编译器

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)
[Visual Studio Code的ILSpy插件](https://github.com/icsharpcode/ilspy-vscode)：你可以在任何操作系统中使用它（你可以直接从VSCode安装，无需下载git。点击**Extensions**然后搜索**ILSpy**）。
如果你需要**反编译**，**修改**和**重新编译**，你可以使用：[**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases)（**右键单击 -&gt; 修改方法**来更改函数内部的内容）。
你也可以尝试[https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

## DNSpy日志记录

为了使**DNSpy记录一些信息到文件中**，你可以使用以下.Net代码：
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
## DNSpy调试

为了使用DNSpy调试代码，您需要：

首先，更改与**调试**相关的**程序集属性**：

![](../../.gitbook/assets/image%20%287%29.png)

从：
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
/hive/hacktricks/reversing/reversing-tools/README.md

# Reversing Tools

This section provides an overview of various tools that can be used for reverse engineering and analysis of software. These tools are essential for understanding the inner workings of a program and identifying vulnerabilities or weaknesses.

## IDA Pro

IDA Pro is a popular disassembler and debugger used for reverse engineering. It supports a wide range of architectures and file formats, making it a versatile tool for analyzing binary code. IDA Pro offers advanced features such as graph view, cross-references, and scripting capabilities.

## Ghidra

Ghidra is a free and open-source software reverse engineering suite developed by the National Security Agency (NSA). It provides a wide range of features, including disassembly, decompilation, and analysis of binary code. Ghidra supports multiple platforms and file formats, making it a powerful tool for reverse engineering.

## Radare2

Radare2 is a command-line based reverse engineering framework that supports a variety of architectures and file formats. It offers a wide range of features, including disassembly, debugging, and analysis of binary code. Radare2 is highly extensible and can be scripted using its own scripting language.

## OllyDbg

OllyDbg is a 32-bit assembler-level debugger for Microsoft Windows. It is widely used for reverse engineering and analyzing binary code. OllyDbg offers features such as code analysis, breakpoints, and memory dumping, making it a valuable tool for understanding the behavior of a program.

## x64dbg

x64dbg is a 64-bit debugger for Windows that is compatible with x86 and x64 architectures. It provides a user-friendly interface and a wide range of features, including disassembly, debugging, and memory analysis. x64dbg is highly customizable and supports plugins for additional functionality.

## Hopper Disassembler

Hopper Disassembler is a reverse engineering tool for macOS and Linux. It supports a wide range of architectures and file formats, making it a versatile tool for analyzing binary code. Hopper Disassembler offers features such as disassembly, decompilation, and graph view.

## Cutter

Cutter is a free and open-source reverse engineering framework powered by Radare2. It provides a user-friendly interface and a wide range of features, including disassembly, debugging, and analysis of binary code. Cutter supports multiple platforms and file formats, making it a powerful tool for reverse engineering.

## Binary Ninja

Binary Ninja is a commercial reverse engineering platform that offers advanced features for analyzing binary code. It supports a wide range of architectures and file formats, making it a versatile tool for reverse engineering. Binary Ninja provides features such as graph view, scripting capabilities, and collaboration tools.

## Conclusion

These are just a few examples of the many tools available for reverse engineering and analysis of software. Each tool has its own strengths and weaknesses, so it is important to choose the right tool for the task at hand. By using these tools effectively, you can gain a deeper understanding of how software works and identify potential vulnerabilities or weaknesses.
```text
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
然后点击**编译**：

![](../../.gitbook/assets/image%20%28314%29%20%281%29.png)

然后将新文件保存在_**文件 &gt;&gt; 保存模块...**_：

![](../../.gitbook/assets/image%20%28261%29.png)

这是必要的，因为如果不这样做，在**运行时**会对代码应用多个**优化**，可能会导致在调试时**断点永远不会触发**或某些**变量不存在**。

然后，如果你的.NET应用程序正在由**IIS**运行，你可以使用以下命令**重新启动**它：
```text
iisreset /noforce
```
然后，为了开始调试，您应该关闭所有打开的文件，并在**调试选项卡**中选择**附加到进程...**：

![](../../.gitbook/assets/image%20%28166%29.png)

然后选择**w3wp.exe**以附加到**IIS服务器**，然后点击**附加**：

![](../../.gitbook/assets/image%20%28274%29.png)

现在我们正在调试进程，是时候停止它并加载所有模块了。首先点击_Debug &gt;&gt; Break All_，然后点击_**Debug &gt;&gt; Windows &gt;&gt; Modules**_：

![](../../.gitbook/assets/image%20%28210%29.png)

![](../../.gitbook/assets/image%20%28341%29.png)

在**模块**中点击任何模块，然后选择**打开所有模块**：

![](../../.gitbook/assets/image%20%28216%29.png)

右键单击**程序集浏览器**中的任何模块，然后点击**排序程序集**：

![](../../.gitbook/assets/image%20%28130%29.png)

# Java反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

# 调试DLL

## 使用IDA

* **加载rundll32**（64位在C:\Windows\System32\rundll32.exe，32位在C:\Windows\SysWOW64\rundll32.exe）
* 选择**Windbg**调试器
* 选择“**在库加载/卸载时暂停**”

![](../../.gitbook/assets/image%20%2869%29.png)

* 配置执行的**参数**，将**DLL的路径**和要调用的函数放入其中：

![](../../.gitbook/assets/image%20%28325%29.png)

然后，当您开始调试时，**每次加载DLL时都会停止执行**，然后当rundll32加载您的DLL时，执行将停止。

但是，您如何获取已加载的DLL的代码？使用这种方法，我不知道如何。

## 使用x64dbg/x32dbg

* **加载rundll32**（64位在C:\Windows\System32\rundll32.exe，32位在C:\Windows\SysWOW64\rundll32.exe）
* **更改命令行**（_文件 --&gt; 更改命令行_）并设置dll的路径和要调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\14.ridii\_2.dll",DLLMain
* 更改_Options --&gt; Settings_并选择“**DLL Entry**”。
* 然后**开始执行**，调试器将在每个dll主函数处停止，最终您将**停在您的dll的dll Entry处**。从那里，只需搜索您想要设置断点的位置。

请注意，当执行由于任何原因停止时，在win64dbg中，您可以在**win64dbg窗口顶部**查看您所在的代码：

![](../../.gitbook/assets/image%20%28181%29.png)

然后，查看此处，您可以看到执行停止在您要调试的dll中的位置。

# ARM和MIPS

{% embed url="https://github.com/nongiach/arm\_now" %}

# Shellcode

## 使用blobrunner调试shellcode

[**Blobrunner**](https://github.com/OALabs/BlobRunner)将在内存空间中**分配**shellcode，并指示shellcode分配的内存地址，并**停止**执行。
然后，您需要将调试器（Ida或x64dbg）**附加到进程**，并在指示的内存地址处设置**断点**，然后**恢复**执行。这样，您就可以调试shellcode了。

发布的github页面包含了编译版本的zip文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
您可以在以下链接中找到稍微修改过的Blobrunner版本。为了编译它，只需在Visual Studio Code中**创建一个C/C++项目，复制并粘贴代码，然后构建**。

{% page-ref page="blobrunner.md" %}

## 使用jmp2it调试shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)与blobrunner非常相似。它将在内存空间中**分配**shellcode，并启动一个**无限循环**。然后，您需要将调试器**附加到进程**，**播放开始等待2-5秒然后按停止**，然后您将发现自己处于**无限循环**中。跳转到无限循环的下一条指令，因为它将是对shellcode的调用，最后您将发现自己正在执行shellcode。

![](../../.gitbook/assets/image%20%28403%29.png)

您可以在[发布页面下载编译版本的jmp2it](https://github.com/adamkramer/jmp2it/releases/)。

## 使用Cutter调试shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)是radare的图形界面。使用cutter，您可以动态地模拟和检查shellcode。

请注意，Cutter允许您“打开文件”和“打开shellcode”。在我的情况下，当我将shellcode作为文件打开时，它正确反编译了，但当我将其作为shellcode打开时，它没有：

![](../../.gitbook/assets/image%20%28254%29.png)

为了从您想要的位置开始模拟，设置一个断点，显然cutter将自动从那里开始模拟：

![](../../.gitbook/assets/image%20%28402%29.png)

![](../../.gitbook/assets/image%20%28343%29.png)

您可以在十六进制转储中看到堆栈，例如：

![](../../.gitbook/assets/image%20%28404%29.png)
## 反混淆 shellcode 并获取执行的函数

你可以尝试使用 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。
它会告诉你 shellcode 使用了哪些函数，并且如果 shellcode 在内存中进行了**解码**。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg也提供了一个图形化启动器，您可以在其中选择所需的选项并执行shellcode。

![](../../.gitbook/assets/image%20%28401%29.png)

如果对shellcode在内存中进行了任何动态更改（用于下载解码后的shellcode），**Create Dump**选项将转储最终的shellcode。**start offset**可以用于在特定偏移处启动shellcode。**Debug Shell**选项可用于使用scDbg终端调试shellcode（但是我发现前面解释的任何选项都更适合此事，因为您将能够使用Ida或x64dbg）。

## 使用CyberChef进行反汇编

将shellcode文件上传为输入，并使用以下配方对其进行反汇编：[https://gchq.github.io/CyberChef/\#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\)](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

# [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个混淆器将所有指令更改为`mov`（是的，非常酷）。它还使用中断来改变执行流程。有关其工作原理的更多信息：

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

如果您很幸运，[demovfuscator](https://github.com/kirschju/demovfuscator)将解混淆二进制文件。它有几个依赖项。
```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```
并且[安装keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) \(`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`\)

如果你在玩CTF，这个绕过方法来找到flag可能非常有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

# Delphi

对于Delphi编译的二进制文件，你可以使用[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

# 课程

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(二进制反混淆\)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
