# 逆向工具和基本方法

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基于ImGui的逆向工具

软件：

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm反编译器 / Wat编译器

在线工具：

* 使用[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)将wasm（二进制）反编译为wat（明文）
* 使用[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)将wat编译为wasm
* 您也可以尝试使用[https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)进行反编译

软件：

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net反编译器

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek是一个反编译器，可以**反编译和检查多种格式**，包括**库**（.dll）、**Windows元数据文件**（.winmd）和**可执行文件**（.exe）。反编译后，一个程序集可以保存为Visual Studio项目（.csproj）。

这里的优点是，如果需要从旧程序集中恢复丢失的源代码，此操作可以节省时间。此外，dotPeek提供了方便的导航功能，使其成为**Xamarin算法分析**的完美工具之一。

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

具有全面的插件模型和API，可以根据您的实际需求扩展工具，.NET Reflector节省时间并简化开发。让我们看看这个工具提供的众多逆向工程服务：

* 提供了数据如何在库或组件中流动的见解
* 提供了.NET语言和框架的实现和使用见解
* 查找未记录和未公开的功能，以更充分利用所使用的API和技术
* 查找依赖项和不同的程序集
* 追踪代码中所有.NET代码的源代码的确切位置
* 调试您使用的所有.NET代码的源代码。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code的ILSpy插件](https://github.com/icsharpcode/ilspy-vscode)：您可以在任何操作系统中使用它（您可以直接从VSCode安装，无需下载git。单击**扩展**，然后**搜索ILSpy**）。\
如果您需要**反编译**，**修改**和**重新编译**，您可以使用：[**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases)（**右键单击 -> 修改方法**以更改函数内部的内容）。\
您还可以尝试[https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### DNSpy日志记录

为了使**DNSpy在文件中记录一些信息**，您可以使用以下.NET代码行：
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy调试

要使用DNSpy调试代码，您需要：

首先，更改与**调试**相关的**程序集属性**：

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
至：
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

这是必要的，因为如果您不这样做，在**运行时**会对代码应用几种**优化**，可能会导致在调试时**断点永远不会被触发**或一些**变量不存在**。

然后，如果您的 .Net 应用程序正在由**IIS**运行，您可以使用以下方法**重新启动**它：
```
iisreset /noforce
```
然后，为了开始调试，您应该关闭所有已打开的文件，并在**调试选项卡**中选择**附加到进程...**：

![](<../../.gitbook/assets/image (280).png>)

然后选择**w3wp.exe**以附加到**IIS服务器**，然后单击**附加**：

![](<../../.gitbook/assets/image (281).png>)

现在我们正在调试该进程，是时候停止它并加载所有模块了。首先单击 _调试 >> 中断所有_，然后单击 _**调试 >> 窗口 >> 模块**_：

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

单击**模块**中的任何模块，然后选择**打开所有模块**：

![](<../../.gitbook/assets/image (284).png>)

右键单击**程序集资源管理器**中的任何模块，然后单击**排序程序集**：

![](<../../.gitbook/assets/image (285).png>)

## Java反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试DLLs

### 使用IDA

* **加载rundll32**（64位位于C:\Windows\System32\rundll32.exe，32位位于C:\Windows\SysWOW64\rundll32.exe）
* 选择**Windbg**调试器
* 选择“**在库加载/卸载时暂停**”

![](<../../.gitbook/assets/image (135).png>)

* 配置执行的**参数**，放入**DLL路径**和要调用的函数：

![](<../../.gitbook/assets/image (136).png>)

然后，当您开始调试时，**每次加载DLL时执行都会停止**，然后当rundll32加载您的DLL时，执行将会停止。

但是，您如何查看已加载的DLL的代码呢？使用这种方法，我不知道如何。

### 使用x64dbg/x32dbg

* **加载rundll32**（64位位于C:\Windows\System32\rundll32.exe，32位位于C:\Windows\SysWOW64\rundll32.exe）
* **更改命令行**（ _文件 --> 更改命令行_ ）并设置dll的路径和要调用的函数，例如：“C:\Windows\SysWOW64\rundll32.exe” “Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll”,DLLMain
* 更改 _选项 --> 设置_ 并选择“**DLL入口**”。
* 然后**开始执行**，调试器将在每个dll主函数处停止，最终您将**停在您的dll的dll入口**。从那里，只需搜索要设置断点的位置。

请注意，当win64dbg由于任何原因停止执行时，您可以在**win64dbg窗口顶部**看到您所在的**代码**：

![](<../../.gitbook/assets/image (137).png>)

然后，查看此处，您可以看到执行已在您要调试的dll中停止。

## GUI应用程序 / 视频游戏

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，可用于查找运行游戏内存中保存的重要值并更改它们。更多信息请参阅：

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM和MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcode

### 使用blobrunner调试shellcode

[**Blobrunner**](https://github.com/OALabs/BlobRunner) 将在内存空间中**分配shellcode**，并**指示**您shellcode分配的**内存地址**，然后**停止**执行。\
然后，您需要将调试器（Ida或x64dbg）**附加到进程**，在指示的内存地址处设置**断点**，然后**恢复**执行。这样您就可以调试shellcode了。

发布的github页面包含了编译版本的zip文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
您可以在以下链接中找到Blobrunner的稍作修改的版本。要编译它，只需**在Visual Studio Code中创建一个C/C++项目，复制并粘贴代码，然后构建**。

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### 使用jmp2it调试shellcode

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)与blobrunner非常相似。它将在内存空间中**分配shellcode**，然后启动一个**永久循环**。然后，您需要将调试器**附加到进程**，**开始播放等待2-5秒然后停止**，您将发现自己处于**永久循环**中。跳转到永久循环的下一条指令，因为它将是对shellcode的调用，最终您将发现自己正在执行shellcode。

![](<../../.gitbook/assets/image (397).png>)

您可以在[发布页面中下载jmp2it的编译版本](https://github.com/adamkramer/jmp2it/releases/)。

### 使用Cutter调试shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是radare的GUI。使用Cutter，您可以动态地模拟和检查shellcode。

请注意，Cutter允许您“打开文件”和“打开shellcode”。在我的情况下，当我将shellcode作为文件打开时，它正确反编译了，但当我将其作为shellcode打开时，它没有：

![](<../../.gitbook/assets/image (400).png>)

为了从您想要的位置开始模拟，设置一个断点，显然Cutter将自动从那里开始模拟：

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

您可以在十六进制转储中查看堆栈，例如：

![](<../../.gitbook/assets/image (402).png>)

### 解混淆shellcode并获取执行函数

您应该尝试[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152)。\
它将告诉您shellcode正在使用的**哪些函数**，以及shellcode是否在内存中**解码**自身。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg还配备了一个图形启动器，您可以在其中选择所需的选项并执行shellcode

![](<../../.gitbook/assets/image (398).png>)

**创建Dump**选项将在内存中动态更改shellcode时转储最终shellcode（有助于下载解码后的shellcode）。**起始偏移**对于在特定偏移处启动shellcode很有用。**调试Shell**选项可用于使用scDbg终端调试shellcode（但我发现前面解释的任何选项在这方面更好，因为您可以使用Ida或x64dbg）。

### 使用CyberChef进行反汇编

将shellcode文件上传为输入，并使用以下配方对其进行反编译：[https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个混淆器**修改所有`mov`指令**（是的，非常酷）。它还使用中断来改变执行流。有关其工作原理的更多信息：

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

如果您很幸运，[demovfuscator ](https://github.com/kirschju/demovfuscator)将对二进制文件进行反混淆。它有几个依赖项
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
并[安装keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

如果你在玩**CTF，这个绕过方法找到flag**可能非常有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要找到**入口点**，搜索函数中的`::main`，如下所示：

![](<../../.gitbook/assets/image (612).png>)

在这种情况下，二进制文件被称为authenticator，因此很明显这是一个有趣的主函数。\
有了被调用的**函数的名称**，在**互联网**上搜索它们，了解它们的**输入**和**输出**。

## **Delphi**

对于Delphi编译的二进制文件，可以使用[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果你需要反向一个Delphi二进制文件，我建议你使用IDA插件[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

只需按下**ATL+f7**（在IDA中导入Python插件），然后选择Python插件。

此插件将在调试开始时执行二进制文件并动态解析函数名称。开始调试后再次按下开始按钮（绿色按钮或f9），将在真实代码的开头触发断点。

这也非常有趣，因为如果在图形应用程序中按下按钮，调试器将停在由该按钮执行的函数中。

## Golang

如果你需要反向一个Golang二进制文件，我建议你使用IDA插件[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

只需按下**ATL+f7**（在IDA中导入Python插件），然后选择Python插件。

这将解析函数的名称。

## 编译的Python

在这个页面上，你可以找到如何从一个ELF/EXE Python编译的二进制文件中获取Python代码：

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

如果你得到一个GBA游戏的**二进制文件**，你可以使用不同的工具来**模拟**和**调试**它：

* [**no$gba**](https://problemkaputt.de/gba.htm)（_下载调试版本_）- 包含一个带界面的调试器
* [**mgba** ](https://mgba.io)- 包含一个CLI调试器
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra插件
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra插件

在[**no$gba**](https://problemkaputt.de/gba.htm)中，在_**Options --> Emulation Setup --> Controls**_\*\* \*\*你可以看到如何按下Game Boy Advance的**按钮**

![](<../../.gitbook/assets/image (578).png>)

按下时，每个**键都有一个值**来识别它：
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
因此，在这种程序中，一个有趣的部分将是**程序如何处理用户输入**。在地址**0x4000130**中，您将找到常见的函数：**KEYINPUT**。

![](<../../.gitbook/assets/image (579).png>)

在上图中，您可以发现该函数是从**FUN\_080015a8**（地址：_0x080015fa_ 和 _0x080017ac_）调用的。

在该函数中，在进行一些初始化操作之后（没有任何重要性）：
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
最后的if语句检查**`uVar4`**是否在**最后的Keys**中，而不是当前的密钥，也称为释放按钮（当前密钥存储在**`uVar1`**中）。
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
在前面的代码中，您可以看到我们正在将**uVar1**（按下按钮的**值所在的位置**）与一些值进行比较：

* 首先，它与**值4**（**SELECT**按钮）进行比较：在挑战中，此按钮清除屏幕
* 然后，将其与**值8**（**START**按钮）进行比较：在挑战中，这会检查代码是否有效以获取标志。
* 在这种情况下，将变量**`DAT_030000d8`**与0xf3进行比较，如果值相同，则执行一些代码。
* 在任何其他情况下，将检查一些cont（`DAT_030000d4`）。这是一个cont，因为在输入代码后立即加1。
* 如果小于8，则执行涉及向**`DAT_030000d8`**添加值的操作（基本上是将按下的键的值添加到此变量中，只要cont小于8）。

因此，在这个挑战中，了解按钮的值，您需要**按下长度小于8的组合，使得结果相加为0xf3**。

**本教程的参考资料：** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## 课程

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（二进制反混淆）

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
