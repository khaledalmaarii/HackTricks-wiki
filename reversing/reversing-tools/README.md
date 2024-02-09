<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

# Wasm反编译和Wat编译指南

在**WebAssembly**领域，处理**Wasm（WebAssembly二进制）**和**Wat（WebAssembly文本）**文件的**反编译**和**编译**工具对开发人员至关重要。本指南介绍了一些在线资源和软件，用于处理这些文件。

## 在线工具

- 要将Wasm反编译为Wat，可使用[Webt的wasm2wat演示工具](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)。
- 要将Wat编译回Wasm，可使用[Webt的wat2wasm演示工具](https://webassembly.github.io/wabt/demo/wat2wasm/)。
- 另一个反编译选项可在[web-wasmdec](https://wwwg.github.io/web-wasmdec/)找到。

## 软件解决方案

- 对于更强大的解决方案，[PNF Software的JEB](https://www.pnfsoftware.com/jeb/demo)提供了广泛的功能。
- 开源项目[wasmdec](https://github.com/wwwg/wasmdec)也可用于反编译任务。

# .Net反编译资源

可以使用以下工具来反编译.Net程序集：

- [ILSpy](https://github.com/icsharpcode/ILSpy)，还提供了适用于Visual Studio Code的[插件](https://github.com/icsharpcode/ilspy-vscode)，可实现跨平台使用。
- 对于涉及**反编译**、**修改**和**重新编译**的任务，强烈推荐使用[dnSpy](https://github.com/0xd4d/dnSpy/releases)。右键单击方法并选择**修改方法**可进行代码更改。
- [JetBrains的dotPeek](https://www.jetbrains.com/es-es/decompiler/)是反编译.Net程序集的另一选择。

## 使用DNSpy增强调试和日志记录

### DNSpy日志记录
要使用DNSpy将信息记录到文件中，请添加以下.Net代码片段：

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy调试
为了有效地使用DNSpy进行调试，建议按照一系列步骤调整**程序集属性**以进行调试，确保禁用可能阻碍调试的优化。此过程包括更改`DebuggableAttribute`设置，重新编译程序集并保存更改。

此外，要调试由**IIS**运行的.Net应用程序，执行`iisreset /noforce`可重新启动IIS。要将DNSpy附加到IIS进程以进行调试，指南指导选择DNSpy中的**w3wp.exe**进程并开始调试会话。

为了在调试过程中全面查看加载的模块，建议访问DNSpy中的**模块**窗口，然后打开所有模块并对程序集进行排序，以便更轻松地导航和调试。

本指南概括了WebAssembly和.Net反编译的要点，为开发人员提供了轻松处理这些任务的途径。

## **Java反编译器**
要反编译Java字节码，这些工具非常有帮助：
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **调试DLLs**
### 使用IDA
- **Rundll32**从特定路径加载64位和32位版本。
- 选择**Windbg**作为调试器，并启用在库加载/卸载时暂停的选项。
- 执行参数包括DLL路径和函数名称。此设置会在每个DLL加载时停止执行。

### 使用x64dbg/x32dbg
- 与IDA类似，使用命令行修改加载**rundll32**以指定DLL和函数。
- 调整设置以在DLL入口处中断，允许在所需的DLL入口点设置断点。

### 图像
通过屏幕截图展示了执行停止点和配置。

## **ARM和MIPS**
- 对于仿真，[arm_now](https://github.com/nongiach/arm_now)是一个有用的资源。

## **Shellcode**
### 调试技术
- **Blobrunner**和**jmp2it**是用于在内存中分配shellcode并使用Ida或x64dbg进行调试的工具。
- Blobrunner [发布版本](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [编译版本](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**提供基于GUI的shellcode仿真和检查，突出显示作为文件与直接shellcode处理之间的差异。

### 去混淆和分析
- **scdbg**提供有关shellcode功能和去混淆功能的见解。
%%%bash
scdbg.exe -f shellcode # 基本信息
scdbg.exe -f shellcode -r # 分析报告
scdbg.exe -f shellcode -i -r # 交互式挂钩
scdbg.exe -f shellcode -d # 转储解码的shellcode
scdbg.exe -f shellcode /findsc # 查找起始偏移量
scdbg.exe -f shellcode /foff 0x0000004D # 从偏移量执行
%%%

- 使用**CyberChef**来反汇编shellcode：[CyberChef配方](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- 一种用`mov`替换所有指令的混淆器。
- 有用的资源包括[YouTube解释](https://www.youtube.com/watch?v=2VF_wPkiBJY)和[PDF幻灯片](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)。
- **demovfuscator**可能会反转movfuscator的混淆，需要依赖项如`libcapstone-dev`和`libz3-dev`，并安装[keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)。

## **Delphi**
- 对于Delphi二进制文件，推荐使用[IDR](https://github.com/crypto2011/IDR)。


# 课程

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(二进制去混淆\)

</details>
