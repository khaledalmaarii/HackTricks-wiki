# PsExec/Winexec/ScExec

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 它们是如何工作的

以下步骤概述了服务二进制文件如何被操纵以通过SMB在目标机器上实现远程执行：

1. 通过SMB将服务二进制文件**复制到ADMIN$共享**。
2. 通过指向二进制文件**在远程机器上创建一个服务**。
3. **远程启动服务**。
4. 退出时，**停止服务并删除二进制文件**。

### **手动执行PsExec的过程**

假设存在一个可执行载荷（使用msfvenom创建，并使用Veil进行混淆以规避杀毒软件检测），名为'met8888.exe'，代表一个meterpreter reverse_http载荷，采取以下步骤：

- **复制二进制文件**：可执行文件从命令提示符复制到ADMIN$共享，尽管它可以放置在文件系统的任何位置以保持隐藏。

- **创建服务**：利用Windows `sc`命令，允许远程查询、创建和删除Windows服务，创建一个名为"meterpreter"的服务，指向上传的二进制文件。

- **启动服务**：最后一步涉及启动服务，这可能会导致"超时"错误，因为二进制文件不是真正的服务二进制文件，无法返回预期的响应代码。这个错误不重要，因为主要目标是执行二进制文件。

观察Metasploit监听器将显示会话已成功启动。

[了解更多关于`sc`命令的信息](https://technet.microsoft.com/en-us/library/bb490995.aspx)。

在[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)中找到更详细的步骤。

**您也可以使用Windows Sysinternals二进制文件PsExec.exe：**

![](<../../.gitbook/assets/image (165).png>)

您也可以使用[**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
