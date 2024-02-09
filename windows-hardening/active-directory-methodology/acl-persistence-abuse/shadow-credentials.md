# 影子凭证

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord群组**](https://discord.gg/hRep4RUj7f) 或**电报群组**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## 简介 <a href="#3f17" id="3f17"></a>

**查看原始帖子获取有关此技术的[所有信息](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**

总结：如果您可以写入用户/计算机的**msDS-KeyCredentialLink**属性，则可以检索该对象的**NT哈希**。

在帖子中，概述了一种设置**公钥-私钥身份验证凭据**以获取包含目标NTLM哈希的唯一**服务票证**的方法。此过程涉及特权属性证书（PAC）中的加密NTLM_SUPPLEMENTAL_CREDENTIAL，可以解密。

### 要求

要应用此技术，必须满足一定条件：
- 需要至少一个Windows Server 2016域控制器。
- 域控制器必须安装有服务器身份验证数字证书。
- Active Directory必须处于Windows Server 2016功能级别。
- 需要具有委派权限以修改目标对象的msDS-KeyCredentialLink属性的帐户。

## 滥用

对计算机对象的密钥信任滥用包括超出获取票据授予票证（TGT）和NTLM哈希的步骤。选项包括：
1. 创建一个**RC4 silver ticket**以充当预期主机上的特权用户。
2. 使用TGT进行**S4U2Self**，以模拟**特权用户**，需要对服务票证进行更改以向服务名称添加服务类。

密钥信任滥用的一个重要优势是其限制于攻击者生成的私钥，避免委派给可能存在漏洞的帐户，并且不需要创建计算机帐户，这可能难以删除。

## 工具

### [**Whisker**](https://github.com/eladshamir/Whisker)

它基于DSInternals，提供了用于此攻击的C#接口。Whisker及其Python对应工具**pyWhisker**，使得可以操纵`msDS-KeyCredentialLink`属性以控制Active Directory帐户。这些工具支持添加、列出、删除和清除目标对象中的密钥凭据等各种操作。

**Whisker**的功能包括：
- **Add**：生成一对密钥并添加密钥凭据。
- **List**：显示所有密钥凭据条目。
- **Remove**：删除指定的密钥凭据。
- **Clear**：清除所有密钥凭据，可能会干扰合法的WHfB使用。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

它将 Whisker 功能扩展到 **基于 UNIX 的系统**，利用 Impacket 和 PyDSInternals 实现全面的利用功能，包括列出、添加和删除 KeyCredentials，以及以 JSON 格式导入和导出它们。
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray旨在利用广泛用户组可能对域对象具有的GenericWrite/GenericAll权限来广泛应用ShadowCredentials。它涉及登录到域，验证域的功能级别，枚举域对象，并尝试添加KeyCredentials以获取TGT并揭示NT哈希。清理选项和递归利用策略增强了其效用。


## 参考资料

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中被广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的 **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
