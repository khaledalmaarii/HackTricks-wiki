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

## 工作原理

**Smbexec**是一种用于在Windows系统上进行远程命令执行的工具，类似于**Psexec**，但它避免在目标系统上放置任何恶意文件。

### **SMBExec**的关键要点

- 它通过在目标机器上创建一个临时服务（例如，“BTOBTO”）来执行命令，通过cmd.exe（%COMSPEC%）执行命令，而不会释放任何二进制文件。
- 尽管采用了隐蔽的方法，但它确实为执行的每个命令生成事件日志，提供一种非交互式的“shell”形式。
- 使用**Smbexec**连接的命令如下所示：
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### 在没有二进制文件的情况下执行命令

- **Smbexec** 通过服务的 binPaths 实现直接命令执行，无需在目标上使用物理二进制文件。
- 这种方法适用于在 Windows 目标上执行一次性命令。例如，将其与 Metasploit 的 `web_delivery` 模块配对，可以执行针对 PowerShell 的反向 Meterpreter 负载。
- 通过在攻击者的机器上创建一个远程服务，将 binPath 设置为通过 cmd.exe 运行提供的命令，可以成功执行有效载荷，使用 Metasploit 监听器实现回调和有效载荷执行，即使服务响应错误也会发生。

### 命令示例

可以使用以下命令创建并启动服务：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
## 参考资料
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
