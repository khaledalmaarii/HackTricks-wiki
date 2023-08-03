# AD CS证书盗窃

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 我可以用证书做什么

在查看如何窃取证书之前，这里有一些关于如何找到证书有什么用的信息：
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## 使用加密API导出证书 - THEFT1

提取用户或机器证书和私钥的最简单方法是通过**交互式桌面会话**。如果**私钥**是**可导出的**，可以在`certmgr.msc`中右键单击证书，然后转到`所有任务 → 导出`...以导出一个受密码保护的.pfx文件。\
也可以通过编程的方式实现。例如，PowerShell的`ExportPfxCertificate` cmdlet或[TheWover的CertStealer C#项目](https://github.com/TheWover/CertStealer)。

在底层，这些方法使用**Microsoft CryptoAPI**（CAPI）或更现代的密码学API：下一代密码学（CNG）与证书存储进行交互。这些API执行各种加密服务，用于证书存储和身份验证（以及其他用途）。

如果私钥是不可导出的，CAPI和CNG将不允许提取不可导出的证书。**Mimikatz的**`crypto::capi`和`crypto::cng`命令可以修补CAPI和CNG以允许私钥的导出。`crypto::capi`在当前进程中**修补**CAPI，而`crypto::cng`需要**修补**lsass.exe的内存。

## 通过DPAPI窃取用户证书 - THEFT2

有关DPAPI的更多信息，请参见：

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows使用DPAPI**存储证书私钥**。Microsoft将用户和机器私钥的存储位置分开。在手动解密加密的DPAPI blob时，开发人员需要了解操作系统使用的密码学API，因为私钥文件结构在这两个API之间有所不同。使用SharpDPAPI时，它会自动考虑这些文件格式差异。

Windows最常将用户证书存储在注册表中的键`HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`中，尽管某些用户的个人证书也存储在`%APPDATA%\Microsoft\SystemCertificates\My\Certificates`中。相关的用户**私钥位置**主要在`%APPDATA%\Microsoft\Crypto\RSA\User SID\`中用于**CAPI**密钥，以及`%APPDATA%\Microsoft\Crypto\Keys\`中用于**CNG**密钥。

要获取证书及其关联的私钥，需要执行以下操作：

1. 确定要从用户的证书存储中**窃取哪个证书**并提取密钥存储名称。
2. 找到解密相关私钥所需的**DPAPI主密钥**。
3. 获取明文DPAPI主密钥并使用它来**解密私钥**。

要**获取明文DPAPI主密钥**：
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
为了简化主密钥文件和私钥文件的解密过程，可以使用[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)的`certificates`命令，通过`/pvk`、`/mkfile`、`/password`或`{GUID}:KEY`参数来解密私钥和相关证书，并输出一个`.pem`文本文件。
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## 通过DPAPI窃取机器证书 - THEFT3

Windows将机器证书存储在注册表键`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`中，并将私钥存储在不同的位置，具体取决于帐户。\
尽管SharpDPAPI将搜索所有这些位置，但最有趣的结果往往来自`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（CAPI）和`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（CNG）。这些**私钥**与**机器证书**存储关联，并且Windows使用**机器的DPAPI主密钥**对其进行加密。\
无法使用域的DPAPI备份密钥解密这些密钥，而是必须使用**仅由SYSTEM用户访问的DPAPI\_SYSTEM LSA秘密**。&#x20;

您可以使用**Mimikatz**的**`lsadump::secrets`**命令手动执行此操作，然后使用提取的密钥**解密机器主密钥**。\
您还可以像以前一样修补CAPI/CNG，并使用**Mimikatz**的`crypto::certificates /export /systemstore:LOCAL_MACHINE`命令。\
**SharpDPAPI**的certificates命令使用**`/machine`**标志（提升权限）将自动**提升**到**SYSTEM**，**转储**DPAPI\_SYSTEM LSA秘密，使用此秘密**解密**并找到机器DPAPI主密钥，并将密钥明文用作查找表以解密任何机器证书私钥。

## 查找证书文件 - THEFT4

有时，**证书只是存在于文件系统中**，例如文件共享或下载文件夹中。\
我们见过的最常见的以Windows为重点的证书文件类型是**`.pfx`**和**`.p12`**文件，偶尔会出现**`.pkcs12`**和**`.pem`**。\
其他有趣的与证书相关的文件扩展名包括：**`.key`**（私钥）、**`.crt/.cer`**（仅证书）、**`.csr`**（证书签名请求，不包含证书或私钥）、**`.jks/.keystore/.keys`**（Java密钥库。可能包含Java应用程序使用的证书和私钥）。

要查找这些文件，只需使用PowerShell或cmd搜索这些扩展名。

如果找到一个**PKCS#12**证书文件，并且它是**受密码保护的**，您可以使用[pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html)提取哈希并使用JohnTheRipper进行破解。

## 通过PKINIT窃取NTLM凭据 - THEFT5

> 为了支持应用程序连接到不支持Kerberos身份验证的网络服务的NTLM身份验证\[MS-NLMP]，当使用PKCA时，KDC会在特权属性证书（PAC）**`PAC_CREDENTIAL_INFO`**缓冲区中返回用户的NTLM单向函数（OWF）

因此，如果帐户通过PKINIT进行身份验证并获得TGT，那么存在一种内置的“故障保护”机制，允许当前主机从TGT中**解密**一个**`PAC_CREDENTIAL_DATA`**结构，该结构是NTLM明文的网络数据表示（NDR）序列化表示。

可以使用[**Kekeo**](https://github.com/gentilkiwi/kekeo)来请求带有此信息的TGT并检索用户的NTML哈希
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
Kekeo的实现也适用于当前插入的受智能卡保护的证书，如果您能够恢复pin码。它也将在Rubeus中得到支持。

## 参考资料

* 所有信息均来自[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
