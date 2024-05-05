# 检查表 - Linux权限提升

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

加入[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)服务器，与经验丰富的黑客和赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和见解及时了解快节奏的黑客世界

**最新公告**\
随时了解最新的赏金任务发布和重要平台更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！

### **查找Linux本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/#system-information)

* [ ] 获取**操作系统信息**
* [ ] 检查[**PATH**](privilege-escalation/#path)，是否有**可写入的文件夹**？
* [ ] 检查[**环境变量**](privilege-escalation/#env-info)，是否有敏感信息？
* [ ] 使用脚本搜索[**内核漏洞**](privilege-escalation/#kernel-exploits)（DirtyCow等）
* [ ] **检查**[**sudo版本是否有漏洞**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**签名验证失败](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 更多系统枚举（[日期，系统统计，CPU信息，打印机](privilege-escalation/#more-system-enumeration)）
* [ ] [枚举更多防御措施](privilege-escalation/#enumerate-possible-defenses)

### [驱动器](privilege-escalation/#drives)

* [ ] **列出已挂载的**驱动器
* [ ] **有未挂载的驱动器吗？**
* [ ] **在fstab中有凭据吗？**

### [**已安装软件**](privilege-escalation/#installed-software)

* [ ] **检查是否安装了**[**有用的软件**](privilege-escalation/#useful-software)
* [ ] **检查是否安装了**[**易受攻击的软件**](privilege-escalation/#vulnerable-software-installed)

### [进程](privilege-escalation/#processes)

* [ ] 是否有**未知软件正在运行**？
* [ ] 是否有以**比应有的更高权限运行的软件**？
* [ ] 搜索正在运行进程的**利用漏洞**（特别是正在运行的版本）。
* [ ] 是否可以**修改**任何正在运行进程的**二进制文件**？
* [ ] **监视进程**，检查是否有任何有趣的进程经常运行。
* [ ] 是否可以**读取**一些有趣的**进程内存**（可能保存密码的地方）？

### [定时/计划任务？](privilege-escalation/#scheduled-jobs)

* [ ] 一些cron是否修改了[**PATH** ](privilege-escalation/#cron-path)，您可以在其中**写入**吗？
* [ ] 任何cron作业中的[**通配符** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)？
* [ ] 一些[**可修改的脚本** ](privilege-escalation/#cron-script-overwriting-and-symlink)是否正在**执行**或位于**可修改的文件夹**中？
* [ ] 您是否发现某些**脚本**可能正在或经常[**执行**](privilege-escalation/#frequent-cron-jobs)？（每1、2或5分钟）

### [服务](privilege-escalation/#services)

* [ ] 任何**可写的 .service** 文件？
* [ ] 任何由**服务**执行的**可写入的二进制文件**？
* [ ] systemd PATH中是否有任何**可写入的文件夹**？

### [定时器](privilege-escalation/#timers)

* [ ] 任何**可写的定时器**？

### [套接字](privilege-escalation/#sockets)

* [ ] 任何**可写的 .socket** 文件？
* [ ] 您能否与任何套接字**通信**？
* [ ] 具有有趣信息的**HTTP套接字**？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] 您能否与任何D-Bus**通信**？

### [网络](privilege-escalation/#network)

* [ ] 枚举网络以了解您所在的位置
* [ ] 在获取机器内部shell之前，是否可以访问之前无法访问的**开放端口**？
* [ ] 是否可以使用`tcpdump`**嗅探流量**？

### [用户](privilege-escalation/#users)

* [ ] 通用用户/组**枚举**
* [ ] 您是否有一个**非常大的UID**？机器**易受攻击**吗？
* [ ] 您是否可以通过所属的组[**提升权限**](privilege-escalation/interesting-groups-linux-pe/)？
* [ ] **剪贴板**数据？
* [ ] 密码策略？
* [ ] 尝试使用您之前发现的每个**已知密码**登录每个可能的**用户**。也尝试无密码登录。

### [可写入的PATH](privilege-escalation/#writable-path-abuses)

* [ ] 如果您对PATH中的某个文件夹具有**写权限**，则可能可以提升权限

### [SUDO和SUID命令](privilege-escalation/#sudo-and-suid)

* [ ] 您是否可以使用**sudo执行任何命令**？您能否将其用于以root身份**读取、写入或执行**任何内容？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] 是否有**可利用的SUID二进制文件**？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] [**sudo**命令是否受**路径**限制？您能否**绕过**限制](privilege-escalation/#sudo-execution-bypassing-paths)？
* [ ] [**未指定路径的Sudo/SUID二进制文件**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**指定路径的SUID二进制文件**](privilege-escalation/#suid-binary-with-command-path)? 绕过
* [ ] [**LD\_PRELOAD漏洞**](privilege-escalation/#ld\_preload)
* [ ] 来自可写文件夹的SUID二进制文件中是否存在[**.so库缺失**](privilege-escalation/#suid-binary-so-injection)？
* [ ] 是否有[**可重用的SUDO令牌**](privilege-escalation/#reusing-sudo-tokens)？[**您能否创建SUDO令牌**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)？
* [ ] 您是否可以[**读取或修改sudoers文件**](privilege-escalation/#etc-sudoers-etc-sudoers-d)？
* [ ] 您是否可以[**修改/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) 命令
### [Capabilities](权限提升/#capabilities)

* [ ] 任何二进制文件具有**意外的能力**吗？

### [ACLs](权限提升/#acls)

* [ ] 任何文件具有**意外的ACL**吗？

### [Open Shell sessions](权限提升/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](权限提升/#ssh)

* [ ] **Debian** [**OpenSSL可预测PRNG - CVE-2008-0166**](权限提升/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH有趣的配置数值**](权限提升/#ssh-interesting-configuration-values)

### [有趣的文件](权限提升/#interesting-files)

* [ ] **配置文件** - 读取敏感数据？写入权限提升？
* [ ] **passwd/shadow文件** - 读取敏感数据？写入权限提升？
* [ ] **检查常见有趣的文件夹**以查找敏感数据
* [ ] **奇怪的位置/拥有的文件**，您可能可以访问或更改可执行文件
* [ ] **最近修改**的文件
* [ ] **Sqlite数据库文件**
* [ ] **隐藏文件**
* [ ] **路径中的脚本/二进制文件**
* [ ] **Web文件**（密码？）
* [ ] **备份**？
* [ ] **已知包含密码的文件**：使用**Linpeas**和**LaZagne**
* [ ] **通用搜索**

### [**可写文件**](权限提升/#writable-files)

* [ ] **修改Python库**以执行任意命令？
* [ ] 您可以**修改日志文件**吗？**Logtotten**漏洞利用
* [ ] 您可以**修改/etc/sysconfig/network-scripts/**吗？Centos/Redhat漏洞利用
* [ ] 您可以在[**ini、int.d、systemd或rc.d文件中编写**](权限提升/#init-init-d-systemd-and-rc-d)吗？

### [**其他技巧**](权限提升/#other-tricks)

* [ ] 您可以滥用NFS以升级权限吗？[**滥用NFS以升级权限**](权限提升/#nfs-privilege-escalation)
* [ ] 您需要从受限制的shell中**逃逸**吗？[**逃逸受限制的shell**](权限提升/#escaping-from-restricted-shells)

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

加入[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)服务器，与经验丰富的黑客和赏金猎人交流！

**黑客见解**\
参与深入探讨黑客活动的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和见解了解快节奏的黑客世界

**最新公告**\
通过最新的赏金计划发布和重要平台更新保持信息更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客合作！
