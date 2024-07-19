# Shadow Credentials

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Intro <a href="#3f17" id="3f17"></a>

**查看原始帖子以获取[有关此技术的所有信息](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**

作为**总结**：如果您可以写入用户/计算机的**msDS-KeyCredentialLink**属性，则可以检索该对象的**NT哈希**。

在帖子中，概述了一种设置**公钥-私钥身份验证凭据**的方法，以获取包含目标NTLM哈希的唯一**服务票证**。此过程涉及特权属性证书（PAC）中的加密NTLM_SUPPLEMENTAL_CREDENTIAL，可以解密。

### Requirements

要应用此技术，必须满足某些条件：
- 需要至少一个Windows Server 2016域控制器。
- 域控制器必须安装服务器身份验证数字证书。
- Active Directory必须处于Windows Server 2016功能级别。
- 需要一个具有修改目标对象的msDS-KeyCredentialLink属性的委派权限的帐户。

## Abuse

对计算机对象的Key Trust滥用包括获取票证授予票证（TGT）和NTLM哈希之外的步骤。选项包括：
1. 创建一个**RC4银票证**以在目标主机上充当特权用户。
2. 使用TGT与**S4U2Self**进行**特权用户**的冒充，需要对服务票证进行更改以将服务类添加到服务名称。

Key Trust滥用的一个显著优势是其限制在攻击者生成的私钥上，避免了对潜在易受攻击帐户的委派，并且不需要创建计算机帐户，这可能难以删除。

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

它基于DSInternals，提供此攻击的C#接口。Whisker及其Python对应物**pyWhisker**使得可以操纵`msDS-KeyCredentialLink`属性，以控制Active Directory帐户。这些工具支持各种操作，如添加、列出、删除和清除目标对象的密钥凭据。

**Whisker**功能包括：
- **Add**: 生成密钥对并添加密钥凭据。
- **List**: 显示所有密钥凭据条目。
- **Remove**: 删除指定的密钥凭据。
- **Clear**: 擦除所有密钥凭据，可能会干扰合法的WHfB使用。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

它扩展了 Whisker 的功能到 **基于 UNIX 的系统**，利用 Impacket 和 PyDSInternals 提供全面的利用能力，包括列出、添加和删除 KeyCredentials，以及以 JSON 格式导入和导出它们。
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray 旨在 **利用广泛用户组可能对域对象拥有的 GenericWrite/GenericAll 权限** 来广泛应用 ShadowCredentials。它包括登录到域，验证域的功能级别，枚举域对象，并尝试添加 KeyCredentials 以获取 TGT 和 NT hash 的揭示。清理选项和递归利用策略增强了其实用性。

## References

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
