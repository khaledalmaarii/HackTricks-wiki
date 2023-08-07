# 影子凭证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 PDF 格式的 HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## 简介 <a href="#3f17" id="3f17"></a>

查看原始帖子以获取有关此技术的[**所有信息**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。

简而言之：如果你可以写入用户/计算机的**msDS-KeyCredentialLink**属性，你可以检索该对象的**NT哈希**。

这是因为你将能够为该对象设置**公私钥身份验证凭据**，并使用它们获取一个包含其NTLM哈希的**特殊服务票证**，该票证在加密的NTLM\_SUPPLEMENTAL\_CREDENTIAL实体中，你可以解密它。

### 要求 <a href="#2de4" id="2de4"></a>

此技术需要以下条件：

* 至少一个 Windows Server 2016 域控制器。
* 在域控制器上安装用于服务器身份验证的数字证书。
* 在 Active Directory 中具有 Windows Server 2016 功能级别。
* 窃取具有写入目标对象的msDS-KeyCredentialLink属性的委派权限的帐户。

## 滥用

滥用计算机对象的密钥信任需要在获取 TGT 和帐户的 NTLM 哈希之后执行其他步骤。通常有两个选项：

1. 伪造一个**RC4 silver ticket**以冒充特权用户登录到相应的主机。
2. 使用 TGT 调用**S4U2Self**以冒充特权用户登录到相应的主机。此选项需要修改获取的服务票证，以在服务名称中包含服务类。

密钥信任滥用的附加好处是它不会委派访问权限给可能被入侵的另一个帐户——它仅限于攻击者生成的私钥。此外，它不需要创建一个可能难以清理的计算机帐户，直到实现特权升级。

Whisker

在本文发布之际，我发布了一个名为“[Whisker](https://github.com/eladshamir/Whisker)”的工具。基于 Michael 的 DSInternals 代码，Whisker 提供了一个 C# 封装，用于在渗透测试中执行此攻击。Whisker 使用 LDAP 更新目标对象，而 DSInternals 允许使用 LDAP 和 Directory Replication Service (DRS) 远程协议的 Directory Replication Service (DRS) 远程协议更新对象。

[Whisker](https://github.com/eladshamir/Whisker) 有四个功能：

* Add — 此功能生成一个公私钥对，并将一个新的密钥凭据添加到目标对象，就像用户从新设备注册到 WHfB 一样。
* List — 此功能列出目标对象的 msDS-KeyCredentialLink 属性的所有条目。
* Remove — 此功能从目标对象中删除由 DeviceID GUID 指定的密钥凭据。
* Clear — 此功能从目标对象的 msDS-KeyCredentialLink 属性中删除所有值。如果目标对象正在合法使用 WHfB，则会中断。

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker 是一个用于接管 Active Directory 用户和计算机帐户的 C# 工具，通过操纵它们的 `msDS-KeyCredentialLink` 属性，有效地向目标帐户添加“影子凭证”。

[**Whisker**](https://github.com/eladshamir/Whisker) 有四个功能：

* **Add** — 此功能生成一个公私钥对，并将一个新的密钥凭据添加到目标对象，就像用户从新设备注册到 WHfB 一样。
* **List** — 此功能列出目标对象的 msDS-KeyCredentialLink 属性的所有条目。
* **Remove** — 此功能从目标对象中删除由 DeviceID GUID 指定的密钥凭据。
* **Clear** — 此功能从目标对象的 msDS-KeyCredentialLink 属性中删除所有值。如果目标对象正在合法使用 WHfB，则会中断。

### Add

向目标对象的 **`msDS-KeyCredentialLink`** 属性添加一个新值：

* `/target:<samAccountName>`：必填。设置目标名称。计算机对象应以'$'符号结尾。
* `/domain:<FQDN>`：可选。设置目标的完全限定域名 (FQDN)。如果未提供，将尝试解析当前用户的 FQDN。
* `/dc:<IP/HOSTNAME>`：可选。设置目标域控制器 (DC)。如果未提供，将尝试定位主域控制器 (PDC)。
* `/path:<PATH>`：可选。设置存储生成的自签名证书用于身份验证的路径。如果未提供，证书将以 Base64 blob 的形式打印出来。
* `/password:<PASWORD>`：可选。设置存储的自签名证书的密码。如果未提供，将生成一个随机密码。

示例：**`Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1`**

{% hint style="info" %}
更多选项请参阅[**自述文件**](https://github.com/eladshamir/Whisker)。
{% endhint %}
## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker是Elad Shamir制作的Whisker的Python版本，原版是用C#编写的。该工具允许用户操纵目标用户/计算机的msDS-KeyCredentialLink属性，从而完全控制该对象。

它基于Impacket和Michael Grafnetter的DSInternals的Python版本PyDSInternals（由podalirius制作）。
此工具与Dirk-jan的PKINITtools一起，仅在基于UNIX的系统上进行完整的原始利用。

pyWhisker可用于对目标的msDs-KeyCredentialLink属性执行各种操作

- *list*：列出所有当前KeyCredentials的ID和创建时间
- *info*：打印KeyCredential结构中包含的所有信息
- *add*：向msDs-KeyCredentialLink添加新的KeyCredential
- *remove*：从msDs-KeyCredentialLink中删除KeyCredential
- *clear*：从msDs-KeyCredentialLink中删除所有KeyCredentials
- *export*：将msDs-KeyCredentialLink中的所有KeyCredentials导出为JSON
- *import*：使用JSON文件中的KeyCredentials覆盖msDs-KeyCredentialLink


pyWhisker支持以下身份验证方式：
- （NTLM）明文密码
- （NTLM）传递哈希
- （Kerberos）明文密码
- （Kerberos）传递密钥/越权哈希
- （Kerberos）传递缓存（票据传递的一种类型）

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)


{% hint style="info" %}
更多选项请参阅[**Readme**](https://github.com/ShutdownRepo/pywhisker)。
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

在某些情况下，“Everyone” / “Authenticated Users” / “Domain Users”或其他**广泛的组**包含域中几乎所有用户在域中的其他对象上具有一些`GenericWrite`/`GenericAll` DACLs。[**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/)试图因此滥用所有这些对象上的**ShadowCredentials**

大致过程如下：

1. 使用提供的凭据登录到域（或使用当前会话）。
2. 检查**域功能级别是否为2016**（否则停止，因为Shadow Credentials攻击将无法工作）
3. 从LDAP中收集域中所有对象（用户和计算机）的**列表**。
4. 对于列表中的**每个对象**，执行以下操作：
1. 尝试向对象的`msDS-KeyCredentialLink`属性**添加KeyCredential**。
2. 如果上述操作**成功**，则使用**PKINIT**使用添加的KeyCredential请求**TGT**。
3. 如果上述操作**成功**，执行**UnPACTheHash**攻击以显示用户/计算机的**NT哈希**。
4. 如果指定了**`--RestoreShadowCred`**：删除添加的KeyCredential（清理操作...）
5. 如果指定了**`--Recursive`**：使用我们成功拥有的每个用户/计算机**账户**执行**相同的过程**。

## 参考资料

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
