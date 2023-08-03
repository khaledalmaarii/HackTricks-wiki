# Linux特权升级清单

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密货币赏金计划的家园。**

**即时获得奖励**\
HackenProof的赏金计划只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其崛起之时掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声望积分，并占据每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register)开始从您的黑客行动中获利！

{% embed url="https://hackenproof.com/register" %}

### **寻找Linux本地特权升级向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/#system-information)

* [ ] 获取**操作系统信息**
* [ ] 检查[**PATH**](privilege-escalation/#path)，是否有**可写入的文件夹**？
* [ ] 检查[**环境变量**](privilege-escalation/#env-info)，是否有敏感信息？
* [ ] 使用脚本搜索[**内核漏洞**](privilege-escalation/#kernel-exploits)（DirtyCow等）
* [ ] **检查**[**sudo版本**是否存在漏洞](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**签名验证失败](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 更多系统枚举（日期、系统统计、CPU信息、打印机等）（privilege-escalation/#more-system-enumeration）
* [ ] [枚举更多防御措施](privilege-escalation/#enumerate-possible-defenses)

### [驱动器](privilege-escalation/#drives)

* [ ] 列出已挂载的驱动器
* [ ] 是否有未挂载的驱动器？
* [ ] fstab中是否有凭据？

### [**已安装的软件**](privilege-escalation/#installed-software)

* [ ] 检查是否安装了[**有用的软件**](privilege-escalation/#useful-software)
* [ ] 检查是否安装了[**存在漏洞的软件**](privilege-escalation/#vulnerable-software-installed)

### [进程](privilege-escalation/#processes)

* [ ] 是否有运行的**未知软件**？
* [ ] 是否有以**比应有权限更高的权限**运行的软件？
* [ ] 搜索正在运行的进程的**漏洞**（特别是正在运行的版本）。
* [ ] 是否可以**修改**任何正在运行的进程的二进制文件？
* [ ] **监视进程**，检查是否频繁运行某个有趣的进程。
* [ ] 是否可以**读取**一些有趣的**进程内存**（可能保存密码的位置）？

### [计划任务/定时任务？](privilege-escalation/#scheduled-jobs)

* [ ] 是否有某个cron修改了[**PATH** ](privilege-escalation/#cron-path)，并且您可以在其中**写入**？
* [ ] 定时任务中是否有[**通配符** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)？
* [ ] 是否有正在**执行的可修改脚本**，或者位于**可修改文件夹**中的脚本？
* [ ] 是否已经发现某个脚本可能正在被[**频繁执行**](privilege-escalation/#frequent-cron-jobs)？（每1、2或5分钟）

### [服务](privilege-escalation/#services)

* [ ] 是否有可写的.service文件？
* [ ] 是否有由服务执行的可写二进制文件？
* [ ] systemd PATH中是否有可写文件夹？
### [定时器](privilege-escalation/#timers)

* [ ] 有**可写的定时器**吗？

### [套接字](privilege-escalation/#sockets)

* [ ] 有**可写的 .socket 文件**吗？
* [ ] 可以**与任何套接字进行通信**吗？
* [ ] 有包含有趣信息的**HTTP套接字**吗？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] 可以**与任何D-Bus进行通信**吗？

### [网络](privilege-escalation/#network)

* [ ] 枚举网络以了解自己的位置
* [ ] 在机器内部获取shell之前，是否**打开了以前无法访问的端口**？
* [ ] 可以使用 `tcpdump` **嗅探流量**吗？

### [用户](privilege-escalation/#users)

* [ ] 通用用户/组**枚举**
* [ ] 拥有**非常大的UID**吗？机器是否**存在漏洞**？
* [ ] 可以通过所属的组[**提升权限**](privilege-escalation/interesting-groups-linux-pe/)吗？
* [ ] **剪贴板**数据？
* [ ] 密码策略？
* [ ] 尝试使用之前发现的每个已知密码以**登录每个**可能的**用户**。也尝试不使用密码登录。

### [可写的路径](privilege-escalation/#writable-path-abuses)

* [ ] 如果对PATH中的某个文件夹具有**写权限**，则可能能够提升权限

### [SUDO和SUID命令](privilege-escalation/#sudo-and-suid)

* [ ] 可以使用sudo执行**任何命令**吗？可以用它作为root用户**读取、写入或执行任何内容**吗？([**GTFOBins**](https://gtfobins.github.io))
* [ ] 是否存在**可利用的SUID二进制文件**？([**GTFOBins**](https://gtfobins.github.io))
* [ ] [**sudo命令是否受到路径限制**？可以**绕过**这些限制吗](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**没有指定命令路径的SUID二进制文件**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**指定路径的SUID二进制文件**](privilege-escalation/#suid-binary-with-command-path)? 绕过
* [ ] [**LD\_PRELOAD漏洞**](privilege-escalation/#ld\_preload)
* [ ] [**SUID二进制文件中缺少.so库**](privilege-escalation/#suid-binary-so-injection)来自可写文件夹？
* [ ] [**可用的SUDO令牌**](privilege-escalation/#reusing-sudo-tokens)? [**可以创建SUDO令牌**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)吗？
* [ ] 可以[**读取或修改sudoers文件**](privilege-escalation/#etc-sudoers-etc-sudoers-d)吗？
* [ ] 可以[**修改/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)吗？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas)命令

### [权限](privilege-escalation/#capabilities)

* [ ] 任何二进制文件具有**意外的权限**吗？

### [ACLs](privilege-escalation/#acls)

* [ ] 任何文件具有**意外的ACL**吗？

### [打开的Shell会话](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL可预测PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH有趣的配置值**](privilege-escalation/#ssh-interesting-configuration-values)

### [有趣的文件](privilege-escalation/#interesting-files)

* [ ] **配置文件** - 读取敏感数据？写入提权？
* [ ] **passwd/shadow文件** - 读取敏感数据？写入提权？
* [ ] 检查常见的有趣文件夹是否存在敏感数据
* [ ] **奇怪的位置/拥有的文件**，您可能可以访问或更改可执行文件
* [ ] **最近几分钟内修改**
* [ ] **Sqlite数据库文件**
* [ ] **隐藏文件**
* [ ] **路径中的脚本/二进制文件**
* [ ] **Web文件**（密码？）
* [ ] **备份**？
* [ ] **已知包含密码的文件**：使用**Linpeas**和**LaZagne**
* [ ] **通用搜索**

### [**可写文件**](privilege-escalation/#writable-files)

* [ ] **修改python库**以执行任意命令？
* [ ] 可以**修改日志文件**吗？**Logtotten**漏洞利用
* [ ] 可以**修改/etc/sysconfig/network-scripts/**吗？Centos/Redhat漏洞利用
* [ ] 可以在**ini、int.d、systemd或rc.d文件中写入**吗？

### [**其他技巧**](privilege-escalation/#other-tricks)

* [ ] 可以使用NFS进行提权吗？[**滥用NFS以提升权限**](privilege-escalation/#nfs-privilege-escalation)？
* [ ] 需要从限制性shell中**逃脱**吗？[**逃脱限制性shell**](privilege-escalation/#escaping-from-restricted-shells)？

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密漏洞赏金的家园。**

**即时获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞经过验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！掌握web3安全的崛起之日。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声誉积分，并占据每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register)开始从您的黑客行动中获利！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [💬](https://emojipedia.org/speech-balloon/) [Discord 群组](https://discord.gg/hRep4RUj7f) 或 [Telegram 群组](https://t.me/peass) 或 **关注**我的 **Twitter** [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks\_live)**。**
* **通过向** [hacktricks 仓库](https://github.com/carlospolop/hacktricks) **和** [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
