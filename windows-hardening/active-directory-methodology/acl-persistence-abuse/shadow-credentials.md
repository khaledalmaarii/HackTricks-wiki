# 影子凭证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？想要在 HackTricks 中看到您的**公司广告**？或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组** 或在 **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)** 上** **关注**我。
* 通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来**分享您的黑客技巧**。

</details>

## 简介 <a href="#3f17" id="3f17"></a>

查看原始帖子获取有关[**此技术的所有信息**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。

简而言之：如果您可以写入用户/计算机的 **msDS-KeyCredentialLink** 属性，则可以检索该对象的 **NT 哈希**。

这是因为您将能够为对象设置 **公钥-私钥身份验证凭据**，并使用它们获取包含其 NTLM 哈希的 **特殊服务票证**，该票证在加密的 NTLM\_SUPPLEMENTAL\_CREDENTIAL 实体中包含在特权属性证书 (PAC) 中，您可以解密。

### 要求 <a href="#2de4" id="2de4"></a>

此技术需要以下内容：

* 至少一个 Windows Server 2016 域控制器。
* 在域控制器上安装用于服务器身份验证的数字证书。
* Active Directory 中的 Windows Server 2016 功能级别。
* 窃取具有写入目标对象 **msDS-KeyCredentialLink** 属性委派权限的帐户。

## 滥用

滥用计算机对象的密钥信任需要在获取 TGT 和帐户的 NTLM 哈希之后执行附加步骤。通常有两个选项：

1. 伪造一个 **RC4 银票证** 以冒充特权用户访问相应的主机。
2. 使用 TGT 调用 **S4U2Self** 以冒充 **特权用户** 访问相应的主机。此选项需要修改获得的服务票证以在服务名称中包含服务类。

密钥信任滥用的附加好处是它不会委派访问权限给可能被入侵的另一个帐户 — 它**限制在攻击者生成的私钥**。此外，它不需要创建一个可能难以清理的计算机帐户，直到实现特权升级。

Whisker

除了本帖外，我发布了一个名为“[Whisker](https://github.com/eladshamir/Whisker)”的工具。基于 Michael 的 DSInternals 代码，Whisker 提供了一个用于在参与中执行此攻击的 C# 封装。Whisker 使用 LDAP 更新目标对象，而 DSInternals 允许使用 LDAP 和 RPC 与目录复制服务 (DRS) 远程协议更新对象。

[Whisker](https://github.com/eladshamir/Whisker) 有四个功能：

* Add — 此功能生成公钥-私钥对，并将新的密钥凭据添加到目标对象，就好像用户从新设备注册到 WHfB 一样。
* List — 此功能列出目标对象的 **msDS-KeyCredentialLink** 属性的所有条目。
* Remove — 此功能从由 DeviceID GUID 指定的目标对象中删除密钥凭据。
* Clear — 此功能从目标对象的 **msDS-KeyCredentialLink** 属性中删除所有值。如果目标对象正在合法使用 WHfB，则会中断。

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker 是一个用于接管 Active Directory 用户和计算机帐户的 C# 工具，通过操纵它们的 `msDS-KeyCredentialLink` 属性，有效地向目标帐户添加“影子凭证”。

[**Whisker**](https://github.com/eladshamir/Whisker) 有四个功能：

* **Add** — 此功能生成公钥-私钥对，并将新的密钥凭据添加到目标对象，就好像用户从新设备注册到 WHfB 一样。
* **List** — 此功能列出目标对象的 **msDS-KeyCredentialLink** 属性的所有条目。
* **Remove** — 此功能从由 DeviceID GUID 指定的目标对象中删除密钥凭据。
* **Clear** — 此功能从目标对象的 **msDS-KeyCredentialLink** 属性中删除所有值。如果目标对象正在合法使用 WHfB，则会中断。

### Add

向目标对象的 **`msDS-KeyCredentialLink`** 属性添加新值：

* `/target:<samAccountName>`: 必需。设置目标名称。计算机对象应以 '$' 符号结尾。
* `/domain:<FQDN>`: 可选。设置目标的完全限定域名 (FQDN)。如果未提供，将尝试解析当前用户的 FQDN。
* `/dc:<IP/HOSTNAME>`: 可选。设置目标域控制器 (DC)。如果未提供，将尝试定位主域控制器 (PDC)。
* `/path:<PATH>`: 可选。设置用于身份验证的生成的自签名证书的路径。如果未提供，证书将作为 Base64 blob 打印。
* `/password:<PASWORD>`: 可选。设置存储的自签名证书的密码。如果未提供，将生成随机密码。

示例：**`Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1`**

{% hint style="info" %}
有关更多选项，请查看[**自述文件**](https://github.com/eladshamir/Whisker)。
{% endhint %}

## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker 是由 Elad Shamir 制作的原始 Whisker 的 Python 等效版本，用 C# 编写。此工具允许用户操纵目标用户/计算机的 `msDS-KeyCredentialLink` 属性，以完全控制该对象。

它基于 Impacket 和 Michael Grafnetter 的 DSInternals 的 Python 等效版本，称为 PyDSInternals，由 podalirius 制作。
此工具与 Dirk-jan 的 PKINITtools 一起，仅允许在基于 UNIX 的系统上进行完整的原始利用。

pyWhisker 可用于对目标的 **msDs-KeyCredentialLink** 属性执行各种操作

- *list*: 列出所有当前的 KeyCredentials ID 和创建时间
- *info*: 打印 KeyCredential 结构中包含的所有信息
- *add*: 向 msDs-KeyCredentialLink 添加新的 KeyCredential
- *remove*: 从 msDs-KeyCredentialLink 中删除 KeyCredential
- *clear*: 从 msDs-KeyCredentialLink 中删除所有 KeyCredentials
- *export*: 以 JSON 格式导出 msDs-KeyCredentialLink 中的所有 KeyCredentials
- *import*: 使用 JSON 文件覆盖 msDs-KeyCredentialLink 中的 KeyCredentials


pyWhisker 支持以下身份验证方式：
- (NTLM) 明文密码
- (NTLM) 传递哈希
- (Kerberos) 明文密码
- (Kerberos) 传递密钥 / 越过哈希
- (Kerberos) 传递缓存 (票证传递的一种类型)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)

{% hint style="info" %}
有关更多选项，请查看[**自述文件**](https://github.com/ShutdownRepo/pywhisker)。
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

在几种情况下，组 "Everyone" / "Authenticated Users" / "Domain Users" 或其他一些**广泛组**包含几乎所有域中的用户，具有一些对象中的 `GenericWrite`/`GenericAll` DACLs **权限**。[**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) 尝试因此对所有这些对象**滥用** **影子凭证**

操作步骤如下：

1. 使用提供的凭据登录到域 (或使用当前会话)。
2. 检查**域功能级别是否为 2016** (否则停止，因为影子凭证攻击将无效)。
3. 从 LDAP 中收集域中的所有对象 (用户和计算机) 的**列表**。
4. 对列表中的**每个对象**执行以下操作：
1. 尝试向对象的 `msDS-KeyCredentialLink` 属性**添加 KeyCredential**。
2. 如果上述操作**成功**，使用 **PKINIT** 使用添加的 KeyCredential 请求 **TGT**。
3. 如果上述操作**成功**，执行 **UnPACTheHash** 攻击以显示用户/计算机的 **NT 哈希**。
4. 如果指定了 **`--RestoreShadowCred`**：删除添加的 KeyCredential (清理操作...)
5. 如果指定了 **`--Recursive`**：使用我们成功拥有的每个用户/计算机**帐户**执行**相同的过程**。

## 参考

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/) 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？想要在 HackTricks 中看到您的**公司广告**？或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组** 或在 **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)** 上** **关注**我。
* 通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来**分享您的黑客技巧**。

</details>
