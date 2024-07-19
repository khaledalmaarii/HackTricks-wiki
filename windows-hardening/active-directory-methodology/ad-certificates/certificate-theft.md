# AD CS 证书盗窃

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

**这是来自 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) 的精彩研究中盗窃章节的小总结**

## 我可以用证书做什么

在检查如何盗取证书之前，这里有一些关于如何找到证书用途的信息：
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
## Exporting Certificates Using the Crypto APIs – THEFT1

在**交互式桌面会话**中，提取用户或机器证书及其私钥非常简单，特别是如果**私钥是可导出的**。可以通过导航到`certmgr.msc`中的证书，右键单击并选择`所有任务 → 导出`来生成一个受密码保护的.pfx文件。

对于**编程方法**，可以使用PowerShell的`ExportPfxCertificate` cmdlet或像[TheWover的CertStealer C#项目](https://github.com/TheWover/CertStealer)这样的项目。这些工具利用**Microsoft CryptoAPI** (CAPI)或加密API：下一代 (CNG)与证书存储进行交互。这些API提供了一系列加密服务，包括证书存储和身份验证所需的服务。

然而，如果私钥被设置为不可导出，CAPI和CNG通常会阻止提取此类证书。为了绕过此限制，可以使用**Mimikatz**等工具。Mimikatz提供`crypto::capi`和`crypto::cng`命令来修补相应的API，从而允许导出私钥。具体而言，`crypto::capi`修补当前进程中的CAPI，而`crypto::cng`则针对**lsass.exe**的内存进行修补。

## User Certificate Theft via DPAPI – THEFT2

有关DPAPI的更多信息，请参见：

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

在Windows中，**证书私钥由DPAPI保护**。重要的是要认识到**用户和机器私钥的存储位置**是不同的，文件结构根据操作系统使用的加密API而有所不同。**SharpDPAPI**是一个可以在解密DPAPI blobs时自动导航这些差异的工具。

**用户证书**主要存放在注册表中的`HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`下，但有些也可以在目录`%APPDATA%\Microsoft\SystemCertificates\My\Certificates`中找到。这些证书的相应**私钥**通常存储在`%APPDATA%\Microsoft\Crypto\RSA\User SID\`中用于**CAPI**密钥，而`%APPDATA%\Microsoft\Crypto\Keys\`中用于**CNG**密钥。

要**提取证书及其相关私钥**，过程包括：

1. **从用户的存储中选择目标证书**并检索其密钥存储名称。
2. **定位所需的DPAPI主密钥**以解密相应的私钥。
3. **利用明文DPAPI主密钥解密私钥**。

对于**获取明文DPAPI主密钥**，可以使用以下方法：
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
为了简化主密钥文件和私钥文件的解密，来自 [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 的 `certificates` 命令非常有用。它接受 `/pvk`、`/mkfile`、`/password` 或 `{GUID}:KEY` 作为参数，以解密私钥和相关证书，随后生成一个 `.pem` 文件。
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Machine Certificate Theft via DPAPI – THEFT3

Windows 在注册表中存储的机器证书位于 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`，相关的私钥位于 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（用于 CAPI）和 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（用于 CNG），这些证书使用机器的 DPAPI 主密钥进行加密。这些密钥无法使用域的 DPAPI 备份密钥解密；相反，需要 **DPAPI_SYSTEM LSA 密钥**，只有 SYSTEM 用户可以访问。

手动解密可以通过在 **Mimikatz** 中执行 `lsadump::secrets` 命令来提取 DPAPI_SYSTEM LSA 密钥，然后使用该密钥解密机器主密钥。或者，在修补 CAPI/CNG 后，可以使用 Mimikatz 的 `crypto::certificates /export /systemstore:LOCAL_MACHINE` 命令。

**SharpDPAPI** 提供了一种更自动化的方法，通过其证书命令。当使用 `/machine` 标志并具有提升的权限时，它会提升到 SYSTEM，转储 DPAPI_SYSTEM LSA 密钥，使用它解密机器 DPAPI 主密钥，然后将这些明文密钥用作查找表以解密任何机器证书私钥。

## Finding Certificate Files – THEFT4

证书有时可以直接在文件系统中找到，例如在文件共享或下载文件夹中。针对 Windows 环境的最常见证书文件类型是 `.pfx` 和 `.p12` 文件。虽然不太常见，但扩展名为 `.pkcs12` 和 `.pem` 的文件也会出现。其他值得注意的与证书相关的文件扩展名包括：
- `.key` 用于私钥，
- `.crt`/`.cer` 仅用于证书，
- `.csr` 用于证书签名请求，不包含证书或私钥，
- `.jks`/`.keystore`/`.keys` 用于 Java 密钥库，可能包含 Java 应用程序使用的证书和私钥。

可以使用 PowerShell 或命令提示符通过查找上述扩展名来搜索这些文件。

如果找到 PKCS#12 证书文件并且它受密码保护，可以通过使用 `pfx2john.py` 提取哈希，该工具可在 [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) 获取。随后，可以使用 JohnTheRipper 尝试破解密码。
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

给定的内容解释了一种通过 PKINIT 进行 NTLM 凭证盗窃的方法，特别是通过标记为 THEFT5 的盗窃方法。以下是被动语态的重新解释，内容经过匿名化和总结：

为了支持不便于 Kerberos 认证的应用程序的 NTLM 认证 [MS-NLMP]，KDC 被设计为在使用 PKCA 时返回用户的 NTLM 单向函数 (OWF)，具体在 `PAC_CREDENTIAL_INFO` 缓冲区中。因此，如果一个账户通过 PKINIT 进行身份验证并获取票证授权票 (TGT)，则固有地提供了一种机制，使当前主机能够从 TGT 中提取 NTLM 哈希，以支持传统认证协议。此过程涉及对 `PAC_CREDENTIAL_DATA` 结构的解密，该结构本质上是 NTLM 明文的 NDR 序列化表示。

工具 **Kekeo**，可在 [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) 获取，被提及为能够请求包含此特定数据的 TGT，从而便于检索用户的 NTLM。用于此目的的命令如下：
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
此外，值得注意的是，Kekeo 可以处理智能卡保护的证书，只要可以检索到 PIN，参考 [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)。同样的功能也被 **Rubeus** 支持，地址为 [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)。

此解释概述了通过 PKINIT 进行 NTLM 凭据盗窃的过程和工具，重点是通过使用 PKINIT 获取的 TGT 检索 NTLM 哈希，以及促进此过程的实用程序。

{% hint style="success" %}
学习与实践 AWS 黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
