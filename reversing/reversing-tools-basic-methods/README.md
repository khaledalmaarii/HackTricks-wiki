# 反向工程工具和基本方法

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基于ImGui的反向工程工具

软件：

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm反编译器 / Wat编译器

在线工具：

* 使用[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)将wasm（二进制）反编译为wat（明文）
* 使用[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)将wat编译为wasm
* 你也可以尝试使用[https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)进行反编译

软件：

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net反编译器

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek是一个反编译器，可以反编译和检查多种格式，包括库（.dll）、Windows元数据文件（.winmd）和可执行文件（.exe）。一旦反编译，可以将程序集保存为Visual Studio项目（.csproj）。

这里的优点是，如果丢失的源代码需要从旧版程序集中恢复，这个操作可以节省时间。此外，dotPeek提供了方便的导航功能，使其成为**Xamarin算法分析**的完美工具之一。

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

.NET Reflector具有全面的插件模型和API，可以根据您的实际需求扩展工具，节省时间并简化开发。让我们来看看这个工具提供的众多逆向工程服务：

* 提供对数据在库或组件中的流动方式的洞察
* 提供对.NET语言和框架的实现和使用的洞察
* 发现未记录和未公开的功能，以更充分地利用所使用的API和技术。
* 查找依赖项和不同的程序集
* 追踪代码中错误、第三方组件和库的确切位置。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy Visual Studio Code插件](https://github.com/icsharpcode/ilspy-vscode)：你可以在任何操作系统中使用它（你可以直接从VSCode安装它，无需下载git。点击**Extensions**然后**搜索ILSpy**）。\
如果你需要**反编译**、**修改**和**重新编译**，你可以使用：[**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases)（**右键单击 -> 修改方法**来更改函数内部的内容）。\
你也可以尝试[https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### DNSpy日志记录

为了使**DNSpy记录一些信息到文件中**，你可以使用以下.NET代码行：
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy调试

为了使用DNSpy调试代码，您需要：

首先，更改与**调试**相关的**程序集属性**：

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
/hive/hacktricks/reversing/reversing-tools-basic-methods/README.md

# Reversing Tools Basic Methods

This section provides an overview of the basic methods used in reversing tools. These methods are essential for reverse engineering and analyzing software.

## Static Analysis

Static analysis involves examining the binary code of a program without executing it. This can be done using tools such as disassemblers and decompilers. Static analysis helps in understanding the structure and behavior of the program.

### Disassemblers

Disassemblers are tools that convert machine code into assembly code. They allow you to view the low-level instructions of a program. Some popular disassemblers include IDA Pro, Ghidra, and Radare2.

### Decompilers

Decompilers are tools that convert compiled code into a higher-level programming language. They help in understanding the logic and functionality of a program. Some popular decompilers include IDA Pro, Ghidra, and RetDec.

## Dynamic Analysis

Dynamic analysis involves running the program and observing its behavior in real-time. This can be done using tools such as debuggers and dynamic analysis frameworks. Dynamic analysis helps in understanding the runtime behavior and identifying vulnerabilities.

### Debuggers

Debuggers are tools that allow you to monitor and control the execution of a program. They provide features such as breakpoints, stepping through code, and inspecting variables. Some popular debuggers include GDB, WinDbg, and OllyDbg.

### Dynamic Analysis Frameworks

Dynamic analysis frameworks are tools that automate the process of analyzing software behavior. They provide features such as code instrumentation, memory monitoring, and network traffic analysis. Some popular dynamic analysis frameworks include Frida, Pin, and DynamoRIO.

## Other Tools

Apart from disassemblers, decompilers, debuggers, and dynamic analysis frameworks, there are several other tools that can be used in reverse engineering. These include:

- Hex Editors: Tools that allow you to view and edit binary files.
- Packers/Unpackers: Tools that compress or encrypt executable files to make reverse engineering more difficult.
- Patchers: Tools that modify the binary code of a program to change its behavior.
- Fuzzers: Tools that generate random inputs to test the robustness of a program.
- Profilers: Tools that analyze the performance of a program and identify bottlenecks.

## Conclusion

Understanding the basic methods used in reversing tools is essential for reverse engineering and analyzing software. By using a combination of static and dynamic analysis, along with other tools, you can gain insights into the inner workings of a program and identify vulnerabilities.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
然后点击**编译**：

![](<../../.gitbook/assets/image (314) (1) (1).png>)

然后将新文件保存在_**文件 >> 保存模块...**_：

![](<../../.gitbook/assets/image (279).png>)

这是必要的，因为如果不这样做，在**运行时**会对代码应用多个**优化**，可能会导致在调试时**断点永远不会触发**或某些**变量不存在**。

然后，如果你的.NET应用程序正在由**IIS**运行，你可以使用以下命令**重新启动**它：
```
iisreset /noforce
```
然后，为了开始调试，您应该关闭所有打开的文件，并在**调试选项卡**中选择**附加到进程...**：

![](<../../.gitbook/assets/image (280).png>)

然后选择**w3wp.exe**以附加到**IIS服务器**，然后点击**附加**：

![](<../../.gitbook/assets/image (281).png>)

现在我们正在调试进程，是时候停止它并加载所有模块了。首先点击_Debug >> Break All_，然后点击_**Debug >> Windows >> Modules**_：

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

在**Modules**中点击任何模块，然后选择**Open All Modules**：

![](<../../.gitbook/assets/image (284).png>)

右键单击**Assembly Explorer**中的任何模块，然后点击**Sort Assemblies**：

![](<../../.gitbook/assets/image (285).png>)

## Java反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试DLL

### 使用IDA

* **加载rundll32**（64位在C:\Windows\System32\rundll32.exe，32位在C:\Windows\SysWOW64\rundll32.exe）
* 选择**Windbg**调试器
* 选择“**在库加载/卸载时暂停**”

![](<../../.gitbook/assets/image (135).png>)

* 配置执行的**参数**，将**DLL的路径**和要调用的函数放入其中：

![](<../../.gitbook/assets/image (136).png>)

然后，当您开始调试时，**每次加载DLL时都会停止执行**，然后当rundll32加载您的DLL时，执行将停止。

但是，您如何获取已加载的DLL的代码？使用这种方法，我不知道如何。

### 使用x64dbg/x32dbg

* **加载rundll32**（64位在C:\Windows\System32\rundll32.exe，32位在C:\Windows\SysWOW64\rundll32.exe）
* **更改命令行**（_文件 --> 更改命令行_），设置dll的路径和要调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* 更改_Options --> Settings_，选择“**DLL Entry**”。
* 然后**开始执行**，调试器将在每个dll主函数处停止，最终您将**停在您的dll的dll Entry处**。从那里，只需搜索您想要设置断点的位置。

请注意，当执行由于任何原因停止时，在win64dbg中，您可以在**win64dbg窗口顶部**看到您所在的代码：

![](<../../.gitbook/assets/image (137).png>)

然后，查看此处，您可以看到执行停止在您要调试的dll中的位置。

## GUI应用程序/视频游戏

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)是一个有用的程序，可以找到正在运行的游戏内存中保存的重要值并进行更改。更多信息请参见：

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM和MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcode

### 使用blobrunner调试shellcode

[**Blobrunner**](https://github.com/OALabs/BlobRunner)将在内存空间中**分配shellcode**，并指示您shellcode分配的内存地址，并停止执行。\
然后，您需要将调试器（Ida或x64dbg）附加到进程，并在指示的内存地址处设置断点，然后恢复执行。这样，您将调试shellcode。

发布的github页面包含编译版本的zip文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
您可以在以下链接中找到稍微修改过的Blobrunner版本。为了编译它，只需在Visual Studio Code中**创建一个C/C++项目，复制并粘贴代码，然后构建**。

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### 使用jmp2it调试shellcode

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)与blobrunner非常相似。它将在内存空间中**分配shellcode**，并启动一个**无限循环**。然后，您需要将调试器附加到进程，**播放开始等待2-5秒，然后按停止**，您将发现自己处于**无限循环**中。跳转到无限循环的下一条指令，因为它将是对shellcode的调用，最后您将发现自己正在执行shellcode。

![](<../../.gitbook/assets/image (397).png>)

您可以在[发布页面下载编译版本的jmp2it](https://github.com/adamkramer/jmp2it/releases/)。

### 使用Cutter调试shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)是radare的图形界面。使用cutter，您可以动态地模拟和检查shellcode。

请注意，Cutter允许您“打开文件”和“打开shellcode”。在我的情况下，当我将shellcode作为文件打开时，它正确反编译了，但当我将其作为shellcode打开时，它没有：

![](<../../.gitbook/assets/image (400).png>)

为了从您想要的位置开始模拟，设置一个断点，然后cutter将自动从那里开始模拟：

![](<../../.gitbook/assets/image (399).png>)

您可以在十六进制转储中查看堆栈，例如：

![](<../../.gitbook/assets/image (402).png>)
### 反混淆 shellcode 并获取执行的函数

你可以尝试使用 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152)。\
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

![](<../../.gitbook/assets/image (398).png>)

如果对shellcode在内存中进行了任何动态更改（用于下载解码后的shellcode），则**Create Dump**选项将转储最终的shellcode。**start offset**可以用于在特定偏移处启动shellcode。**Debug Shell**选项可用于使用scDbg终端调试shellcode（但是我发现前面解释的任何选项对于此问题都更好，因为您将能够使用Ida或x64dbg）。

### 使用CyberChef进行反汇编

将shellcode文件上传为输入，并使用以下配方对其进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个混淆器**修改了所有的`mov`指令**（是的，非常酷）。它还使用中断来改变执行流程。有关其工作原理的更多信息：

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

如果您很幸运，[demovfuscator](https://github.com/kirschju/demovfuscator)将对二进制文件进行反混淆。它有几个依赖项。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
并且[安装keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

如果你在玩CTF，这个绕过方法可以帮助你找到flag: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要找到**入口点**，搜索函数中的`::main`，如下所示:

![](<../../.gitbook/assets/image (612).png>)

在这个例子中，二进制文件被称为authenticator，所以很明显这是一个有趣的主函数。\
知道被调用的函数的**名称**后，可以在**互联网**上搜索它们，了解它们的**输入**和**输出**。

## **Delphi**

对于Delphi编译的二进制文件，可以使用[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果你需要反向一个Delphi二进制文件，我建议你使用IDA插件[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

只需按下**ATL+f7**（在IDA中导入Python插件），然后选择Python插件。

该插件将在调试开始时执行二进制文件并动态解析函数名称。在开始调试后再次按下开始按钮（绿色按钮或f9），将在真正代码的开头触发断点。

这也非常有趣，因为如果你在图形应用程序中按下一个按钮，调试器将停在该按钮执行的函数中。

## Golang

如果你需要反向一个Golang二进制文件，我建议你使用IDA插件[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

只需按下**ATL+f7**（在IDA中导入Python插件），然后选择Python插件。

这将解析函数的名称。

## 编译的Python

在这个页面上，你可以找到如何从ELF/EXE Python编译的二进制文件中获取Python代码:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

如果你得到了一个GBA游戏的**二进制文件**，你可以使用不同的工具来**模拟**和**调试**它:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_下载调试版本_) - 包含一个带界面的调试器
* [**mgba** ](https://mgba.io)- 包含一个CLI调试器
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra插件
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra插件

在[**no$gba**](https://problemkaputt.de/gba.htm)中，在_**Options --> Emulation Setup --> Controls**_\*\* \*\*中可以看到如何按下Game Boy Advance的**按钮**

![](<../../.gitbook/assets/image (578).png>)

按下时，每个**键都有一个值**来识别它:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
所以，在这种程序中，一个有趣的部分将是**程序如何处理用户输入**。在地址**0x4000130**中，你会找到常见的函数：**KEYINPUT**。

![](<../../.gitbook/assets/image (579).png>)

在上面的图像中，你可以发现该函数是从**FUN\_080015a8**（地址：_0x080015fa_和_0x080017ac_）调用的。

在该函数中，在一些初始化操作之后（没有任何重要性）：
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
发现了这段代码：
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
最后的if语句检查**`uVar4`**是否在**最后的Keys**中，而不是当前的按键，也就是放开一个按钮（当前按键存储在**`uVar1`**中）。
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
在上面的代码中，我们可以看到我们正在将**uVar1**（按下按钮的值的位置）与一些值进行比较：

* 首先，它与**值4**（**SELECT**按钮）进行比较：在挑战中，该按钮清除屏幕
* 然后，它与**值8**（**START**按钮）进行比较：在挑战中，这将检查代码是否有效以获取标志。
* 在这种情况下，将变量**`DAT_030000d8`**与0xf3进行比较，如果值相同，则执行一些代码。
* 在其他任何情况下，将检查一些cont（`DAT_030000d4`）。它是一个cont，因为在进入代码后立即加1。
* 如果小于8，则执行涉及将值添加到**`DAT_030000d8`**的操作（基本上是将按下的键的值添加到此变量中，只要cont小于8）。

因此，在这个挑战中，知道按钮的值，你需要**按下一个长度小于8的组合，使得结果的加法等于0xf3**。

**本教程的参考资料：**[**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## 课程

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（二进制反混淆）

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
