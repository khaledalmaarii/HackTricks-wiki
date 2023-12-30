# 清单 - Linux 权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果你在**网络安全公司**工作，想在**HackTricks**中看到你的**公司广告**，或者想要获取**PEASS最新版本或下载HackTricks的PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**推特**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**HackTricks仓库**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks云仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
深入探讨黑客的刺激和挑战

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！

### **寻找Linux本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/#system-information)

* [ ] 获取 **操作系统信息**
* [ ] 检查 [**PATH**](privilege-escalation/#path)，有任何**可写文件夹**？
* [ ] 检查 [**环境变量**](privilege-escalation/#env-info)，有任何敏感细节？
* [ ] 使用脚本搜索 [**内核漏洞**](privilege-escalation/#kernel-exploits)（DirtyCow？）
* [ ] **检查** [**sudo版本** 是否存在漏洞](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** 签名验证失败](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 更多系统枚举（[日期，系统统计，CPU信息，打印机](privilege-escalation/#more-system-enumeration)）
* [ ] [枚举更多防御](privilege-escalation/#enumerate-possible-defenses)

### [驱动器](privilege-escalation/#drives)

* [ ] **列出已挂载**的驱动器
* [ ] **有未挂载的驱动器吗？**
* [ ] **fstab中有任何凭证吗？**

### [**已安装软件**](privilege-escalation/#installed-software)

* [ ] **检查是否安装了**[ **有用的软件**](privilege-escalation/#useful-software)
* [ ] **检查是否安装了** [**存在漏洞的软件**](privilege-escalation/#vulnerable-software-installed)

### [进程](privilege-escalation/#processes)

* [ ] 有任何**未知软件在运行**吗？
* [ ] 有没有软件以**比它应有的更高权限**运行？
* [ ] 搜索**正在运行的进程的漏洞**（尤其是运行的版本）。
* [ ] 你能**修改任何正在运行的进程的二进制文件**吗？
* [ ] **监控进程**并检查是否有任何有趣的进程频繁运行。
* [ ] 你能否**读取**一些有趣的**进程内存**（可能保存了密码）？

### [计划/定时任务？](privilege-escalation/#scheduled-jobs)

* [ ] 有没有cron在修改 [**PATH**](privilege-escalation/#cron-path)，你可以**写入**它？
* [ ] 有没有cron任务中的 [**通配符**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)？
* [ ] 有没有**可修改的脚本**正在**执行**，或者在**可修改的文件夹**内？
* [ ] 你是否发现有些**脚本**可能或正在[**非常频繁地执行**](privilege-escalation/#frequent-cron-jobs)？（每1、2或5分钟）

### [服务](privilege-escalation/#services)

* [ ] 有任何**可写的.service**文件？
* [ ] 有任何**可写的二进制文件**被**服务**执行？
* [ ] 有任何**systemd PATH中的可写文件夹**？

### [定时器](privilege-escalation/#timers)

* [ ] 有任何**可写的定时器**？

### [套接字](privilege-escalation/#sockets)

* [ ] 有任何**可写的.socket**文件？
* [ ] 你能否**与任何套接字通信**？
* [ ] **HTTP套接字**有有趣的信息吗？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] 你能否**与任何D-Bus通信**？

### [网络](privilege-escalation/#network)

* [ ] 枚举网络以了解你所在的位置
* [ ] **在机器内部获取shell之前你无法访问的开放端口**？
* [ ] 你能否使用`tcpdump`**嗅探流量**？

### [用户](privilege-escalation/#users)

* [ ] 通用用户/组**枚举**
* [ ] 你有一个**非常大的UID**吗？**机器**是否**易受攻击**？
* [ ] 你能否[**由于所属的组而提升权限**](privilege-escalation/interesting-groups-linux-pe/)？
* [ ] **剪贴板**数据？
* [ ] 密码策略？
* [ ] 尝试**使用**你之前发现的每一个**已知密码**登录**每一个**可能的**用户**。也尝试不使用密码登录。

### [可写PATH](privilege-escalation/#writable-path-abuses)

* [ ] 如果你对PATH中的某些文件夹有**写权限**，你可能能够提升权限

### [SUDO和SUID命令](privilege-escalation/#sudo-and-suid)

* [ ] 你能执行**任何命令使用sudo**吗？你能用它来作为root读取、写入或执行任何东西吗？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] 有任何**可利用的SUID二进制文件**吗？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] [**sudo** 命令是否**受路径限制**？你能否**绕过**限制](privilege-escalation/#sudo-execution-bypassing-paths)？
* [ ] [**Sudo/SUID二进制文件没有指定路径**](privilege-escalation/#sudo-command-suid-binary-without-command-path)？
* [ ] [**SUID二进制文件指定路径**](privilege-escalation/#suid-binary-with-command-path)？绕过
* [ ] [**LD\_PRELOAD漏洞**](privilege-escalation/#ld\_preload)
* [ ] [**SUID二进制文件缺少.so库**](privilege-escalation/#suid-binary-so-injection) 来自可写文件夹？
* [ ] [**SUDO令牌可用**](privilege-escalation/#reusing-sudo-tokens)？[**你能创建SUDO令牌**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)？
* [ ] 你能否[**读取或修改sudoers文件**](privilege-escalation/#etc-sudoers-etc-sudoers-d)？
* [ ] 你能否[**修改/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) 命令

### [能力](privilege-escalation/#capabilities)

* [ ] 有没有二进制文件具有**意外的能力**？

### [ACLs](privilege-escalation/#acls)

* [ ] 有没有文件具有**意外的ACL**？

### [开放的Shell会话](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL可预测的PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH配置值有趣**](privilege-escalation/#ssh-interesting-configuration-values)

### [有趣的文件](privilege-escalation/#interesting-files)

* [ ] **配置文件** - 读取敏感数据？写入提升权限？
* [ ] **passwd/shadow文件** - 读取敏感数据？写入提升权限？
* [ ] **检查通常有趣的文件夹**寻找敏感数据
* [ ] **位置/所有权奇怪的文件**，你可能可以访问或修改可执行文件
* [ ] **最近几分钟修改过的**
* [ ] **Sqlite数据库文件**
* [ ] **隐藏文件**
* [ ] **PATH中的脚本/二进制文件**
* [ ] **Web文件**（密码？）
* [ ] **备份**？
* [ ] **已知包含密码的文件**：使用**Linpeas**和**LaZagne**
* [ ] **通用搜索**

### [**可写文件**](privilege-escalation/#writable-files)

* [ ] **修改python库**来执行任意命令？
* [ ] 你能否**修改日志文件**？**Logtotten**漏洞
* [ ] 你能否**修改/etc/sysconfig/network-scripts/**？Centos/Redhat漏洞
* [ ] 你能否[**写入ini, int.d, systemd或rc.d文件**](privilege-escalation/#init-init-d-systemd-and-rc-d)？

### [**其他技巧**](privilege-escalation/#other-tricks)

* [ ] 你能否[**滥用NFS来提升权限**](privilege-escalation/#nfs-privilege-escalation)？
* [ ] 你需要[**从限制性shell中逃脱**](privilege-escalation/#escaping-from-restricted-shells)？

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
深入探讨黑客的刺激和挑战

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks**中看到你的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**推特**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库**提交PR来分享你的黑客技巧。**

</details>
