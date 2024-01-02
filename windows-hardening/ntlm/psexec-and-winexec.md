# PsExec/Winexec/ScExec

<details>

<summary><strong>从零到英雄学习AWS黑客技术，参加</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>课程！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 它们是如何工作的

1. 通过SMB将服务二进制文件复制到ADMIN$共享
2. 在远程计算机上创建指向该二进制文件的服务
3. 远程启动服务
4. 退出时，停止服务并删除二进制文件

## **手动执行PsExec**

首先，假设我们有一个用msfvenom生成并用Veil混淆的有效载荷可执行文件（这样AV就不会标记它）。在这个例子中，我创建了一个名为'met8888.exe'的meterpreter reverse_http有效载荷

**复制二进制文件**。从我们的"jarrieta"命令提示符，简单地将二进制文件复制到ADMIN$。实际上，它可以被复制并隐藏在文件系统的任何地方。

![](../../.gitbook/assets/copy\_binary\_admin.png)

**创建服务**。Windows的`sc`命令用于查询、创建、删除等Windows服务，并且可以远程使用。在这里阅读更多关于它的信息[这里](https://technet.microsoft.com/en-us/library/bb490995.aspx)。从我们的命令提示符，我们将远程创建一个名为"meterpreter"的服务，指向我们上传的二进制文件：

![](../../.gitbook/assets/sc\_create.png)

**启动服务**。最后一步是启动服务并执行二进制文件。_注意：_ 当服务启动时，它会"超时"并生成错误。这是因为我们的meterpreter二进制文件不是实际的服务二进制文件，不会返回预期的响应代码。这没关系，因为我们只需要它执行一次以触发：

![](../../.gitbook/assets/sc\_start\_error.png)

如果我们查看我们的Metasploit监听器，我们会看到会话已经开启。

**清理服务。**

![](../../.gitbook/assets/sc\_delete.png)

从这里提取：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**您也可以使用Windows Sysinternals二进制文件PsExec.exe：**

![](<../../.gitbook/assets/image (165).png>)

您也可以使用[**SharpLateral**](https://github.com/mertdas/SharpLateral)：

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
