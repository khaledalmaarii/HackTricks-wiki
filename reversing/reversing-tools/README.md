{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

# Wasm 反编译和 Wat 编译指南

在 **WebAssembly** 领域，**反编译** 和 **编译** 工具对开发者至关重要。本指南介绍了一些处理 **Wasm (WebAssembly 二进制)** 和 **Wat (WebAssembly 文本)** 文件的在线资源和软件。

## 在线工具

- 要将 Wasm **反编译** 为 Wat，可以使用 [Wabt 的 wasm2wat 演示](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)。
- 要将 Wat **编译** 回 Wasm，可以使用 [Wabt 的 wat2wasm 演示](https://webassembly.github.io/wabt/demo/wat2wasm/)。
- 另一个反编译选项可以在 [web-wasmdec](https://wwwg.github.io/web-wasmdec/) 找到。

## 软件解决方案

- 对于更强大的解决方案，[PNF Software 的 JEB](https://www.pnfsoftware.com/jeb/demo) 提供了广泛的功能。
- 开源项目 [wasmdec](https://github.com/wwwg/wasmdec) 也可用于反编译任务。

# .Net 反编译资源

反编译 .Net 程序集可以使用以下工具：

- [ILSpy](https://github.com/icsharpcode/ILSpy)，它还提供了 [Visual Studio Code 插件](https://github.com/icsharpcode/ilspy-vscode)，允许跨平台使用。
- 对于涉及 **反编译**、**修改** 和 **重新编译** 的任务，强烈推荐 [dnSpy](https://github.com/0xd4d/dnSpy/releases)。**右键单击** 方法并选择 **修改方法** 可以进行代码更改。
- [JetBrains 的 dotPeek](https://www.jetbrains.com/es-es/decompiler/) 是另一个反编译 .Net 程序集的替代方案。

## 使用 DNSpy 增强调试和日志记录

### DNSpy 日志记录
要使用 DNSpy 将信息记录到文件中，可以加入以下 .Net 代码片段：

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "密码: " + password + "\n");
%%%

### DNSpy 调试
为了有效地使用 DNSpy 进行调试，建议按照一系列步骤调整 **程序集属性** 以进行调试，确保禁用可能妨碍调试的优化。此过程包括更改 `DebuggableAttribute` 设置、重新编译程序集并保存更改。

此外，要调试由 **IIS** 运行的 .Net 应用程序，执行 `iisreset /noforce` 以重启 IIS。要将 DNSpy 附加到 IIS 进程进行调试，指南指示在 DNSpy 中选择 **w3wp.exe** 进程并开始调试会话。

为了在调试期间全面查看加载的模块，建议访问 DNSpy 中的 **模块** 窗口，然后打开所有模块并对程序集进行排序，以便于导航和调试。

本指南概述了 WebAssembly 和 .Net 反编译的本质，为开发者提供了轻松处理这些任务的途径。

## **Java 反编译器**
要反编译 Java 字节码，这些工具非常有用：
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **调试 DLL**
### 使用 IDA
- **Rundll32** 从特定路径加载 64 位和 32 位版本。
- **Windbg** 被选为调试器，并启用了在库加载/卸载时暂停的选项。
- 执行参数包括 DLL 路径和函数名称。此设置在每个 DLL 加载时暂停执行。

### 使用 x64dbg/x32dbg
- 类似于 IDA，**rundll32** 通过命令行修改加载 DLL 和函数。
- 设置调整为在 DLL 入口处中断，允许在所需的 DLL 入口点设置断点。

### 图片
- 执行停止点和配置通过截图进行说明。

## **ARM & MIPS**
- 对于仿真，[arm_now](https://github.com/nongiach/arm_now) 是一个有用的资源。

## **Shellcodes**
### 调试技术
- **Blobrunner** 和 **jmp2it** 是用于在内存中分配 shellcodes 并使用 Ida 或 x64dbg 调试它们的工具。
- Blobrunner [发布](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [编译版本](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** 提供基于 GUI 的 shellcode 仿真和检查，突出显示作为文件与直接 shellcode 处理的差异。

### 反混淆和分析
- **scdbg** 提供对 shellcode 函数和反混淆能力的洞察。
%%%bash
scdbg.exe -f shellcode # 基本信息
scdbg.exe -f shellcode -r # 分析报告
scdbg.exe -f shellcode -i -r # 交互式钩子
scdbg.exe -f shellcode -d # 转储解码的 shellcode
scdbg.exe -f shellcode /findsc # 查找起始偏移
scdbg.exe -f shellcode /foff 0x0000004D # 从偏移执行
%%%

- **CyberChef** 用于反汇编 shellcode：[CyberChef 配方](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- 一种将所有指令替换为 `mov` 的混淆器。
- 有用的资源包括 [YouTube 解释](https://www.youtube.com/watch?v=2VF_wPkiBJY) 和 [PDF 幻灯片](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)。
- **demovfuscator** 可能会逆转 movfuscator 的混淆，需要依赖项如 `libcapstone-dev` 和 `libz3-dev`，并安装 [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)。

## **Delphi**
- 对于 Delphi 二进制文件，推荐使用 [IDR](https://github.com/crypto2011/IDR)。

# 课程

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(二进制反混淆\)



{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
