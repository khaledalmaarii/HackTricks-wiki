# AD CS 证书盗窃

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 我可以用证书做什么

在检查如何窃取证书之前，这里有一些信息可以帮助您了解证书有什么用途：
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
## 使用 Crypto APIs 导出证书 – THEFT1

通过**交互式桌面会话**提取用户或机器证书和私钥是最简单的方法。如果**私钥**是**可导出的**，可以在 `certmgr.msc` 中右键点击证书，然后选择 `All Tasks → Export`… 来导出一个密码保护的 .pfx 文件。\
这也可以通过**编程方式**完成。示例包括 PowerShell 的 `ExportPfxCertificate` cmdlet 或 [TheWover 的 CertStealer C# 项目](https://github.com/TheWover/CertStealer)。

这些方法底层使用 **Microsoft CryptoAPI**（CAPI）或更现代的 Cryptography API: Next Generation (CNG) 与证书存储进行交互。这些 APIs 执行各种加密服务，这些服务对于证书存储和认证（以及其他用途）是必需的。

如果私钥是不可导出的，CAPI 和 CNG 将不允许提取不可导出的证书。**Mimikatz 的** `crypto::capi` 和 `crypto::cng` 命令可以修补 CAPI 和 CNG 以**允许导出**私钥。`crypto::capi` **修补**当前进程中的 **CAPI**，而 `crypto::cng` 需要**修补** **lsass.exe 的**内存。

## 通过 DPAPI 进行用户证书盗窃 – THEFT2

有关 DPAPI 的更多信息，请参见：

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows **使用 DPAPI 存储证书私钥**。Microsoft 区分了用户和机器私钥的存储位置。当手动解密加密的 DPAPI 数据块时，开发者需要了解操作系统使用了哪种加密 API，因为两种 API 的私钥文件结构不同。使用 SharpDPAPI 时，它会自动处理这些文件格式的差异。&#x20;

Windows 最**常见的用户证书存储位置**是在注册表的 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`，尽管一些用户的个人证书**也**存储在 `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`。关联的用户**私钥位置**主要在 `%APPDATA%\Microsoft\Crypto\RSA\User SID\`（对于 **CAPI** 密钥）和 `%APPDATA%\Microsoft\Crypto\Keys\`（对于 **CNG** 密钥）。

要获取证书及其关联的私钥，需要：

1. 确定**想要从用户的证书存储中盗取哪个证书**并提取密钥存储名称。
2. 找到解密关联私钥所需的**DPAPI 主密钥**。
3. 获取明文 DPAPI 主密钥并使用它来**解密私钥**。

要**获取明文 DPAPI 主密钥**：
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
为了简化主密钥文件和私钥文件的解密，可以使用 [**SharpDPAPI’s**](https://github.com/GhostPack/SharpDPAPI) 的 `certificates` 命令，并结合 `/pvk`、`/mkfile`、`/password` 或 `{GUID}:KEY` 参数来解密私钥和相关证书，输出一个 `.pem` 文本文件。
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## 通过 DPAPI 窃取机器证书 – THEFT3

Windows 在注册表键 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` 中存储机器证书，并根据账户在几个不同的位置存储私钥。\
虽然 SharpDPAPI 会搜索所有这些位置，但最有趣的结果往往来自 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（CAPI）和 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（CNG）。这些**私钥**与**机器证书**存储相关联，Windows 使用**机器的 DPAPI 主密钥**对其加密。\
不能使用域的 DPAPI 备份密钥解密这些密钥，而**必须**使用系统上的**DPAPI\_SYSTEM LSA 秘密**，该秘密**只能由 SYSTEM 用户访问**。&#x20;

您可以手动使用 **Mimikatz’** 的 **`lsadump::secrets`** 命令，然后使用提取的密钥来**解密机器主密钥**。 \
您也可以像之前一样修补 CAPI/CNG，并使用 **Mimikatz’** 的 `crypto::certificates /export /systemstore:LOCAL_MACHINE` 命令。 \
**SharpDPAPI** 的 certificates 命令加上 **`/machine`** 标志（在提升权限时）将自动**提升**为**SYSTEM**，**转储** **DPAPI\_SYSTEM** LSA 秘密，使用它来**解密**找到的机器 DPAPI 主密钥，并使用密钥明文作为查找表来解密任何机器证书私钥。

## 查找证书文件 – THEFT4

有时**证书就在文件系统中**，比如在文件共享或下载文件夹中。\
我们见过的最常见的 Windows-focused 证书文件类型是 **`.pfx`** 和 **`.p12`** 文件，**`.pkcs12`** 和 ** `.pem` ** 有时也会出现，但不太常见。\
其他有趣的与证书相关的文件扩展名包括：**`.key`**（_私钥_），**`.crt/.cer`**（_仅证书_），**`.csr`**（_证书签名请求，不包含证书或私钥_），**`.jks/.keystore/.keys`**（_Java 密钥库。可能包含 Java 应用程序使用的证书 + 私钥_）。

要找到这些文件，只需使用 powershell 或 cmd 搜索这些扩展名。

如果您找到一个**PKCS#12**证书文件，并且它是**密码保护**的，您可以使用 [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) 提取哈希并使用 JohnTheRipper **破解**它。

## 通过 PKINIT 窃取 NTLM 凭据 – THEFT5

> 为了**支持 NTLM 身份验证** \[MS-NLMP]，对于不**支持 Kerberos** 身份验证的网络服务连接的应用程序，当使用 PKCA 时，KDC 在特权属性证书（PAC）**`PAC_CREDENTIAL_INFO`** 缓冲区中返回**用户的 NTLM**单向函数（OWF）

因此，如果账户通过 PKINIT 认证并获得**TGT**，则有一个内置的“故障安全”允许当前主机**从 TGT 获取我们的 NTLM 哈希**以支持传统认证。这涉及**解密**一个**`PAC_CREDENTIAL_DATA`** **结构**，它是 NTLM 明文的网络数据表示（NDR）序列化表示。

可以使用 [**Kekeo**](https://github.com/gentilkiwi/kekeo) 请求带有此信息的 TGT 并检索用户的 NTML。
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
Kekeo的实现也适用于当前插入的智能卡保护证书，如果你能[**恢复密码**](https://github.com/CCob/PinSwipe)**。** 它也将在 [**Rubeus**](https://github.com/GhostPack/Rubeus) 中得到支持。

## 参考资料

* 所有信息取自 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧。

</details>
