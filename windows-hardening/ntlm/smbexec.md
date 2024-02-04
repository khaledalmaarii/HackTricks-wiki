# SmbExec/ScExec

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## How it Works

**Smbexec** 以类似于**Psexec**的方式运行，针对受害者系统上的**cmd.exe**或**powershell.exe**进行后门执行，避免使用恶意可执行文件。

## **SMBExec**
```bash
smbexec.py WORKGROUP/username:password@10.10.10.10
```
Smbexec的功能涉及在目标机器上创建一个临时服务（例如，“BTOBTO”），以执行命令而不会释放二进制文件。该服务被构建为通过cmd.exe的路径（%COMSPEC%）运行命令，将输出重定向到临时文件，并在执行后删除自身。这种方法隐蔽，但为每个命令生成事件日志，通过为每个从攻击者端发出的命令重复此过程，提供一个非交互式“shell”。

## 在没有二进制文件的情况下执行命令

这种方法允许通过服务binPaths直接执行命令，无需二进制文件。这对于在Windows目标上执行一次性命令特别有用。例如，使用Metasploit的`web_delivery`模块与针对PowerShell的反向Meterpreter有效载荷可以建立一个监听器，提供必要的执行命令。在攻击者的Windows机器上创建并启动一个远程服务，binPath设置为通过cmd.exe执行此命令，即使可能出现服务响应错误，也可以在Metasploit监听器端实现回调和有效载荷执行。

### 命令示例

可以使用以下命令创建并启动服务：
```cmd
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
# 参考资料
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
