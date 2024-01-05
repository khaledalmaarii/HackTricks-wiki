# 清单 - Linux 权限提升

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
参与深入探讨黑客攻击的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！

### **寻找 Linux 本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/#system-information)

* [ ] 获取 **操作系统信息**
* [ ] 检查 [**PATH**](privilege-escalation/#path)，有任何**可写文件夹**？
* [ ] 检查 [**环境变量**](privilege-escalation/#env-info)，有任何敏感细节？
* [ ] 使用脚本搜索 [**内核漏洞**](privilege-escalation/#kernel-exploits)（DirtyCow？）
* [ ] **检查** [**sudo 版本** 是否存在漏洞](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** 签名验证失败](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 更多系统枚举（[日期、系统统计、CPU 信息、打印机](privilege-escalation/#more-system-enumeration)）
* [ ] [枚举更多防御](privilege-escalation/#enumerate-possible-defenses)

### [驱动器](privilege-escalation/#drives)

* [ ] **列出已挂载**的驱动器
* [ ] **有未挂载的驱动器吗？**
* [ ] **fstab 中有任何凭证吗？**

### [**已安装的软件**](privilege-escalation/#installed-software)

* [ ] **检查是否安装了**[ **有用的软件**](privilege-escalation/#useful-software)
* [ ] **检查是否安装了** [**存在漏洞的软件**](privilege-escalation/#vulnerable-software-installed)

### [进程](privilege-escalation/#processes)

* [ ] 有任何**未知软件在运行**吗？
* [ ] 有没有软件以**比它应有的更高权限**运行？
* [ ] 搜索**正在运行的进程的漏洞**（尤其是运行的版本）。
* [ ] 你能**修改任何正在运行的进程的二进制文件**吗？
* [ ] **监控进程**并检查是否有任何有趣的进程频繁运行。
* [ ] 你能**读取**一些有趣的**进程内存**（可能保存了密码）吗？

### [计划/定时任务？](privilege-escalation/#scheduled-jobs)

* [ ] 有没有[**PATH**](privilege-escalation/#cron-path)被某些 cron 修改并且你可以**写入**？
* [ ] 有没有 cron 任务中的[**通配符**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)？
* [ ] 有没有[**可修改的脚本**](privilege-escalation/#cron-script-overwriting-and-symlink)正在**执行**或在**可修改的文件夹**内？
* [ ] 你是否发现有些**脚本**可能或正在[**非常频繁地执行**](privilege-escalation/#frequent-cron-jobs)？（每 1、2 或 5 分钟）

### [服务](privilege-escalation/#services)

* [ ] 有任何**可写的 .service** 文件？
* [ ] 有任何**可写的二进制文件**被**服务**执行？
* [ ] 有任何**systemd PATH 中的可写文件夹**？

### [定时器](privilege-escalation/#timers)

* [ ] 有任何**可写的定时器**？

### [套接字](privilege-escalation/#sockets)

* [ ] 有任何**可写的 .socket** 文件？
* [ ] 你能**与任何套接字通信**吗？
* [ ] **HTTP 套接字**有有趣的信息吗？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] 你能**与任何 D-Bus 通信**吗？

### [网络](privilege-escalation/#network)

* [ ] 枚举网络以了解你所在的位置
* [ ] **在机器内部获得 shell 之前你无法访问的开放端口**？
* [ ] 你能使用 `tcpdump` **嗅探流量**吗？

### [用户](privilege-escalation/#users)

* [ ] 通用用户/组**枚举**
* [ ] 你有一个**非常大的 UID** 吗？**机器**是否**易受攻击**？
* [ ] 你能否[**由于所属的组而提升权限**](privilege-escalation/interesting-groups-linux-pe/)？
* [ ] **剪贴板**数据？
* [ ] 密码策略？
* [ ] 尝试**使用**你之前发现的每一个**已知密码**登录**每一个**可能的**用户**。也尝试不使用密码登录。

### [可写的 PATH](privilege-escalation/#writable-path-abuses)

* [ ] 如果你对 PATH 中的某些文件夹有**写权限**，你可能能够提升权限

### [SUDO 和 SUID 命令](privilege-escalation/#sudo-and-suid)

* [ ] 你能以 sudo 执行**任何命令**吗？你能用它来作为 root 读取、写入或执行任何东西吗？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] 有任何**可利用的 SUID 二进制文件**吗？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] [**sudo** 命令是否**受路径限制**？你能**绕过**限制吗](privilege-escalation/#sudo-execution-bypassing-paths)？
* [ ] [**没有指定路径的 Sudo/SUID 二进制文件**](privilege-escalation/#sudo-command-suid-binary-without-command-path)？
* [ ] [**指定路径的 SUID 二进制文件**](privilege-escalation/#suid-binary-with-command-path)？绕过
* [ ] [**LD\_PRELOAD 漏洞**](privilege-escalation/#ld\_preload)
* [ ] [**SUID 二进制文件中缺少 .so 库**](privilege-escalation/#suid-binary-so-injection) 来自可写文件夹？
* [ ] [**可用的 SUDO 令牌**](privilege-escalation/#reusing-sudo-tokens)？[**你能创建一个 SUDO 令牌**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)？
* [ ] 你能[**读取或修改 sudoers 文件**](privilege-escalation/#etc-sudoers-etc-sudoers-d)吗？
* [ ] 你能[**修改 /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) 吗？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) 命令

### [能力](privilege-escalation/#capabilities)

* [ ] 有任何二进制文件具有**意外的能力**吗？

### [ACLs](privilege-escalation/#acls)

* [ ] 有任何文件具有**意外的 ACL**吗？

### [开放的 Shell 会话](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL 可预测的 PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH 配置值有趣**](privilege-escalation/#ssh-interesting-configuration-values)

### [有趣的文件](privilege-escalation/#interesting-files)

* [ ] **配置文件** - 读取敏感数据？写入提升权限？
* [ ] **passwd/shadow 文件** - 读取敏感数据？写入提升权限？
* [ ] **检查常见的有趣文件夹**以获取敏感数据
* [ ] **位置/所有权奇怪的文件**，你可能可以访问或修改可执行文件
* [ ] **最近几分钟内修改的**
* [ ] **Sqlite DB 文件**
* [ ] **隐藏文件**
* [ ] **PATH 中的脚本/二进制文件**
* [ ] **Web 文件**（密码？）
* [ ] **备份**？
* [ ] **已知包含密码的文件**：使用 **Linpeas** 和 **LaZagne**
* [ ] **通用搜索**

### [**可写文件**](privilege-escalation/#writable-files)

* [ ] **修改 python 库**以执行任意命令？
* [ ] 你能**修改日志文件**吗？**Logtotten** 漏洞
* [ ] 你能**修改 /etc/sysconfig/network-scripts/** 吗？Centos/Redhat 漏洞
* [ ] 你能[**写入 ini, int.d, systemd 或 rc.d 文件**](privilege-escalation/#init-init-d-systemd-and-rc-d) 吗？

### [**其他技巧**](privilege-escalation/#other-tricks)

* [ ] 你能[**滥用 NFS 来提升权限**](privilege-escalation/#nfs-privilege-escalation)吗？
* [ ] 你需要[**从限制性 shell 中逃脱**](privilege-escalation/#escaping-from-restricted-shells)吗？

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
参与深入探讨黑客攻击的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
