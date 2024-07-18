{% hint style="success" %}
学习和实践AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 **HackTricks** 和 **HackTricks Cloud** 的 github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


## smss.exe

**会话管理器**。\
会话 0 启动 **csrss.exe** 和 **wininit.exe**（**操作系统服务**），而会话 1 启动 **csrss.exe** 和 **winlogon.exe**（**用户会话**）。但是，您应该在进程树中看到该**二进制文件的一个进程**，没有子进程。

此外，除了 0 和 1 会话外，可能表示正在发生 RDP 会话。


## csrss.exe

**客户端/服务器运行子系统进程**。\
它管理**进程**和**线程**，使**Windows API**可用于其他进程，还**映射驱动器号**，创建**临时文件**，处理**关机过程**。

在会话 0 中有一个，会话 1 中有另一个（因此在进程树中有**2个进程**）。每个新会话都会创建另一个。


## winlogon.exe

**Windows 登录进程**。\
负责用户**登录**/**注销**。它启动 **logonui.exe** 以请求用户名和密码，然后调用 **lsass.exe** 进行验证。

然后启动指定在 **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** 中的 **Userinit** 键的 **userinit.exe**。

此外，前面的注册表中应该在 **Shell 键** 中有 **explorer.exe**，否则可能被滥用为**恶意软件持久性方法**。


## wininit.exe

**Windows 初始化进程**。\
在会话 0 中启动 **services.exe**、**lsass.exe** 和 **lsm.exe**。应该只有 1 个进程。


## userinit.exe

**Userinit 登录应用程序**。\
加载 **HKCU** 中的 **ntduser.dat** 并初始化**用户环境**，运行**登录脚本**和**GPO**。

它启动 **explorer.exe**。


## lsm.exe

**本地会话管理器**。\
它与 smss.exe 一起操作用户会话：登录/注销、启动 shell、锁定/解锁桌面等。

在 W7 之后，lsm.exe 被转换为一个服务（lsm.dll）。

在 W7 中应该只有 1 个进程，其中一个服务运行 DLL。


## services.exe

**服务控制管理器**。\
**加载**配置为**自动启动**的**服务**和**驱动程序**。

它是 **svchost.exe**、**dllhost.exe**、**taskhost.exe**、**spoolsv.exe** 等的父进程。

服务在 `HKLM\SYSTEM\CurrentControlSet\Services` 中定义，此进程在内存中维护服务信息的数据库，可以通过 sc.exe 查询。

请注意，**一些** **服务**将在**自己的进程中运行**，而其他服务将**共享 svchost.exe 进程**。

应该只有 1 个进程。


## lsass.exe

**本地安全机构子系统**。\
负责用户**身份验证**和创建**安全令牌**。它使用位于 `HKLM\System\CurrentControlSet\Control\Lsa` 中的身份验证包。

它写入**安全** **事件** **日志**，应该只有 1 个进程。

请记住，这个进程经常受到攻击以转储密码。


## svchost.exe

**通用服务主机进程**。\
在一个共享进程中托管多个 DLL 服务。

通常，您会发现 **svchost.exe** 是带有 `-k` 标志启动的。这将启动对注册表 **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** 的查询，其中将包含带有 `-k` 中提到的参数的键，该键将包含要在同一进程中启动的服务。

例如：`-k UnistackSvcGroup` 将启动：`PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

如果还使用了 **`-s` 标志** 并带有参数，则要求 svchost 仅启动此参数中指定的服务。

将会有几个 `svchost.exe` 进程。如果其中任何一个**没有使用 `-k` 标志**，那就非常可疑。如果发现**services.exe 不是父进程**，那也非常可疑。


## taskhost.exe

此进程充当从 DLL 运行的进程的主机。它还加载从 DLL 运行的服务。

在 W8 中称为 taskhostex.exe，在 W10 中称为 taskhostw.exe。


## explorer.exe

这是负责**用户桌面**和通过文件扩展名启动文件的进程。

**每个已登录用户**应该生成**仅 1 个进程**。

这是从 **userinit.exe** 运行的，应该被终止，因此此进程的**父进程**中不应该出现任何内容。


# 捕获恶意进程

* 它是否从预期路径运行？（没有 Windows 二进制文件从临时位置运行）
* 它是否与奇怪的 IP 进行通信？
* 检查数字签名（Microsoft 的工件应该是签名的）
* 拼写正确吗？
* 是否在预期的 SID 下运行？
* 父进程是否是预期的（如果有的话）？
* 子进程是否是预期的？（没有 cmd.exe、wscript.exe、powershell.exe..？）


{% hint style="success" %}
学习和实践AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 **HackTricks** 和 **HackTricks Cloud** 的 github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
