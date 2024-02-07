# Linux权限提升清单

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)服务器，与经验丰富的黑客和赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和见解及时了解快节奏的黑客世界

**最新公告**\
随时了解最新的赏金任务发布和重要平台更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，立即与顶尖黑客合作！

### **查找Linux本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/#system-information)

* [ ] 获取**操作系统信息**
* [ ] 检查[**PATH**](privilege-escalation/#path)，是否有**可写入的文件夹**？
* [ ] 检查[**环境变量**](privilege-escalation/#env-info)，是否有敏感信息？
* [ ] 使用脚本搜索[**内核漏洞**](privilege-escalation/#kernel-exploits)（DirtyCow等）
* [ ] **检查**[**sudo版本是否有漏洞**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**签名验证失败](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 更多系统枚举（日期、系统统计、CPU信息、打印机等）（[privilege-escalation/#more-system-enumeration](privilege-escalation/#more-system-enumeration)）
* [ ] [枚举更多防御措施](privilege-escalation/#enumerate-possible-defenses)

### [驱动器](privilege-escalation/#drives)

* [ ] 列出已挂载的驱动器
* [ ] 有未挂载的驱动器吗？
* [ ] 在fstab中有凭据吗？

### [**已安装软件**](privilege-escalation/#installed-software)

* [ ] 检查已安装的[**有用软件**](privilege-escalation/#useful-software)
* [ ] 检查已安装的[**易受攻击的软件**](privilege-escalation/#vulnerable-software-installed)

### [进程](privilege-escalation/#processes)

* [ ] 是否有运行的**未知软件**？
* [ ] 是否有以**比应有权限更高的权限**运行的软件？
* [ ] 搜索运行进程的**漏洞**（特别是正在运行的版本）。
* [ ] 是否可以**修改**任何正在运行进程的**二进制文件**？
* [ ] **监视进程**，检查是否有任何有趣的进程频繁运行。
* [ ] 是否可以**读取**一些有趣的**进程内存**（可能保存密码的地方）？

### [定时/Cron作业？](privilege-escalation/#scheduled-jobs)

* [ ] 是否有一些cron修改了[**PATH**](privilege-escalation/#cron-path)，您可以在其中**写入**吗？
* [ ] 任何cron作业中有[**通配符**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)吗？
* [ ] 一些[**可修改的脚本**](privilege-escalation/#cron-script-overwriting-and-symlink)正在被**执行**或位于**可修改的文件夹**中吗？
* [ ] 您是否发现某些**脚本**可能正在或已经[**非常频繁地执行**](privilege-escalation/#frequent-cron-jobs)？（每1、2或5分钟）

### [服务](privilege-escalation/#services)

* [ ] 有**可写的.service**文件吗？
* [ ] 有**由服务执行的可写二进制文件**吗？
* [ ] 在systemd PATH中有**可写的文件夹**吗？

### [定时器](privilege-escalation/#timers)

* [ ] 有**可写的定时器**吗？

### [套接字](privilege-escalation/#sockets)

* [ ] 有**可写的.socket**文件吗？
* [ ] 您可以与任何套接字**通信**吗？
* [ ] 有**包含有趣信息的HTTP套接字**吗？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] 您可以与任何D-Bus**通信**吗？

### [网络](privilege-escalation/#network)

* [ ] 枚举网络以了解您所在的位置
* [ ] 在获取机器内部shell之前无法访问的**打开端口**？
* [ ] 您可以使用`tcpdump`**嗅探流量**吗？

### [用户](privilege-escalation/#users)

* [ ] 通用用户/组**枚举**
* [ ] 您有一个**非常大的UID**吗？机器**易受攻击**吗？
* [ ] 您可以通过所属的组[**提升权限**](privilege-escalation/interesting-groups-linux-pe/)吗？
* [ ] **剪贴板**数据？
* [ ] 密码策略？
* [ ] 尝试使用您之前发现的每个可能的**用户**的**已知密码**登录。也尝试无密码登录。

### [可写的PATH](privilege-escalation/#writable-path-abuses)

* [ ] 如果您对PATH中的某个文件夹具有**写权限**，则可能可以提升权限

### [SUDO和SUID命令](privilege-escalation/#sudo-and-suid)

* [ ] 您可以使用**sudo执行任何命令**吗？可以用它作为root用户**读取、写入或执行任何内容**吗？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] 是否有**可利用的SUID二进制文件**？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] [**sudo命令是否受到路径限制**？您可以**绕过**限制吗](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**未指定路径的Sudo/SUID二进制文件**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**指定路径的SUID二进制文件**](privilege-escalation/#suid-binary-with-command-path)? 绕过
* [ ] [**LD\_PRELOAD漏洞**](privilege-escalation/#ld\_preload)
* [ ] 来自可写文件夹的SUID二进制文件中是否**缺少.so库**？（[privilege-escalation/#suid-binary-so-injection](privilege-escalation/#suid-binary-so-injection)）
* [ ] 是否有**可重用的SUDO令牌**（[privilege-escalation/#reusing-sudo-tokens](privilege-escalation/#reusing-sudo-tokens)）？您可以创建SUDO令牌吗（[privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)）？
* [ ] 您可以[**读取或修改sudoers文件**](privilege-escalation/#etc-sudoers-etc-sudoers-d)吗？
* [ ] 您可以[**修改/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)吗？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas)命令

### [功能](privilege-escalation/#capabilities)

* [ ] 任何二进制文件具有**意外功能**吗？

### [ACLs](privilege-escalation/#acls)

* [ ] 任何文件具有**意外ACL**吗？

### [打开Shell会话](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL可预测PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH有趣的配置值**](privilege-escalation/#ssh-interesting-configuration-values)

### [有趣的文件](privilege-escalation/#interesting-files)

* [ ] **配置文件** - 读取敏感数据？写入提权？
* [ ] **passwd/shadow文件** - 读取敏感数据？写入提权？
* [ ] 检查通常包含敏感数据的文件夹
* [ ] **奇怪的位置/拥有的文件**，您可能可以访问或更改可执行文件
* [ ] **最近修改**的文件
* [ ] **Sqlite数据库文件**
* [ ] **隐藏文件**
* [ ] **路径中的脚本/二进制文件**
* [ ] **Web文件**（密码？）
* [ ] **备份**？
* [ ] **包含密码的已知文件**：使用**Linpeas**和**LaZagne**
* [ ] **通用搜索**

### [**可写文件**](privilege-escalation/#writable-files)

* [ ] **修改Python库**以执行任意命令？
* [ ] 您可以**修改日志文件**吗？**Logtotten**漏洞
* [ ] 您可以**修改/etc/sysconfig/network-scripts/**吗？Centos/Redhat漏洞
* [ ] 您可以在[**ini、int.d、systemd或rc.d文件中写入**](privilege-escalation/#init-init-d-systemd-and-rc-d)吗？

### [**其他技巧**](privilege-escalation/#other-tricks)

* [ ] 您可以[**滥用NFS提升权限**](privilege-escalation/#nfs-privilege-escalation)吗？
* [ ] 您需要[**从受限制的shell中逃脱**](privilege-escalation/#escaping-from-restricted-shells)吗？
