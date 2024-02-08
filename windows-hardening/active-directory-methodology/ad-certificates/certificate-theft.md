# AD CS 证书窃取

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) 上**关注**我。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

**这是来自[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)出色研究中窃取章节的简要总结**


## 我可以用证书做什么

在查看如何窃取证书之前，您可以了解一些关于证书用途的信息：
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
## 使用加密API导出证书 – THEFT1

在**交互式桌面会话**中，提取用户或计算机证书以及私钥可以很容易地完成，特别是如果**私钥是可导出的**。这可以通过导航到`certmgr.msc`中的证书，在其上右键单击，然后选择`所有任务 → 导出`来生成一个受密码保护的 .pfx 文件来实现。

对于**编程方法**，可以使用诸如PowerShell的`ExportPfxCertificate` cmdlet或项目如[TheWover的CertStealer C#项目](https://github.com/TheWover/CertStealer)。这些工具利用**Microsoft CryptoAPI**（CAPI）或Cryptography API: Next Generation (CNG)与证书存储进行交互。这些API提供一系列加密服务，包括证书存储和认证所需的服务。

然而，如果私钥被设置为不可导出，CAPI和CNG通常会阻止提取这样的证书。为了绕过这一限制，可以使用像**Mimikatz**这样的工具。Mimikatz提供`crypto::capi`和`crypto::cng`命令来修补相应的API，允许导出私钥。具体来说，`crypto::capi`修补了当前进程中的CAPI，而`crypto::cng`则针对**lsass.exe**的内存进行修补。

## 通过DPAPI窃取用户证书 – THEFT2

有关DPAPI的更多信息：

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

在Windows中，**证书私钥受DPAPI保护**。重要的是要认识到**用户和计算机私钥的存储位置**是不同的，并且文件结构取决于操作系统所使用的加密API。**SharpDPAPI**是一个工具，可以在解密DPAPI blobs时自动处理这些差异。

**用户证书**主要存储在注册表中的`HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`下，但有些证书也可以在目录`%APPDATA%\Microsoft\SystemCertificates\My\Certificates`中找到。这些证书的**私钥**通常存储在`%APPDATA%\Microsoft\Crypto\RSA\User SID\`（对于**CAPI**密钥）和`%APPDATA%\Microsoft\Crypto\Keys\`（对于**CNG**密钥）中。

要**提取证书及其关联的私钥**，该过程涉及：

1. 从用户存储中**选择目标证书**并检索其密钥存储名称。
2. **定位所需的DPAPI主密钥**以解密相应的私钥。
3. 通过使用明文DPAPI主密钥**解密私钥**。

要**获取明文DPAPI主密钥**，可以使用以下方法：
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
为了简化主密钥文件和私钥文件的解密过程，来自[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)的`certificates`命令非常有用。它接受`/pvk`、`/mkfile`、`/password`或`{GUID}:KEY`作为参数，用于解密私钥和关联证书，随后生成一个`.pem`文件。
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## 通过DPAPI窃取机器证书 - THEFT3

Windows在注册表中的`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`存储的机器证书以及位于`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（对于CAPI）和`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（对于CNG）中的相关私钥，都是使用机器的DPAPI主密钥加密的。这些密钥无法使用域的DPAPI备份密钥解密；而是需要使用只有SYSTEM用户可以访问的**DPAPI_SYSTEM LSA secret**。

可以通过在**Mimikatz**中执行`lsadump::secrets`命令来手动解密，提取DPAPI_SYSTEM LSA secret，然后使用该密钥解密机器主密钥。另外，也可以在修补CAPI/CNG后，使用Mimikatz的`crypto::certificates /export /systemstore:LOCAL_MACHINE`命令。

**SharpDPAPI**提供了更自动化的方法，其certificates命令。当使用`/machine`标志并具有提升的权限时，它会升级到SYSTEM，转储DPAPI_SYSTEM LSA secret，使用它来解密机器DPAPI主密钥，然后使用这些明文密钥作为查找表来解密任何机器证书私钥。


## 查找证书文件 - THEFT4

有时可以直接在文件系统中找到证书，例如在文件共享或下载文件夹中。针对Windows环境最常见的证书文件类型是`.pfx`和`.p12`文件。虽然不太常见，但也会出现扩展名为`.pkcs12`和`.pem`的文件。其他值得注意的与证书相关的文件扩展名包括：
- `.key`用于私钥，
- `.crt`/`.cer`用于仅包含证书的文件，
- `.csr`用于证书签名请求，不包含证书或私钥，
- `.jks`/`.keystore`/`.keys`用于Java密钥库，可能包含Java应用程序使用的证书和私钥。

可以使用PowerShell或命令提示符搜索这些文件，查找上述扩展名。

如果找到受密码保护的PKCS#12证书文件，并且想要提取哈希值，可以使用`pfx2john.py`，可在[fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html)找到。随后，可以使用JohnTheRipper尝试破解密码。
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## 通过PKINIT进行NTLM凭证窃取 - THEFT5

提供的内容解释了通过PKINIT进行NTLM凭证窃取的方法，特别是通过标记为THEFT5的窃取方法。以下是使用被动语态重新解释的内容，其中适用的情况下进行了匿名化和总结：

为了支持不支持Kerberos身份验证的应用程序的NTLM身份验证[MS-NLMP]，KDC被设计为在特权属性证书（PAC）中返回用户的NTLM单向函数（OWF），特别是在使用PKCA时的`PAC_CREDENTIAL_INFO`缓冲区中。因此，如果一个帐户通过PKINIT进行身份验证并获得票据授予票据（TGT），则会自动提供一种机制，使当前主机能够从TGT中提取NTLM哈希以支持传统的身份验证协议。该过程涉及解密`PAC_CREDENTIAL_DATA`结构，这实质上是NTLM明文的NDR序列化描述。

提到了名为**Kekeo**的实用工具，可在[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)获取包含此特定数据的TGT，从而方便检索用户的NTLM。用于此目的的命令如下：
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
此外，值得注意的是，Kekeo可以处理受智能卡保护的证书，只要可以检索到PIN码，参考[https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)。相同的功能也被指出由**Rubeus**支持，可在[https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)找到。

这段说明概括了通过PKINIT进行NTLM凭据窃取的过程和涉及的工具，重点是通过使用PKINIT获得的TGT检索NTLM哈希，并促进此过程的实用工具。
