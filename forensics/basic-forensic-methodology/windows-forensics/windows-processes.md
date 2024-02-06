<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


## smss.exe

**会话管理器**。\
会话0启动**csrss.exe**和**wininit.exe**（**操作系统服务**），而会话1启动**csrss.exe**和**winlogon.exe**（**用户会话**）。但是，您应该在进程树中看到**只有一个该二进制文件的进程**，没有子进程。

此外，除了0和1之外的会话可能意味着正在发生RDP会话。


## csrss.exe

**客户端/服务器运行子系统进程**。\
它管理**进程**和**线程**，使**Windows API**可用于其他进程，还**映射驱动器**，创建**临时文件**，处理**关机过程**。

在会话0中有一个，在会话1中有另一个（因此在进程树中有**2个进程**）。每个新会话都会创建另一个。


## winlogon.exe

**Windows登录进程**。\
它负责用户**登录**/**注销**。它启动**logonui.exe**以请求用户名和密码，然后调用**lsass.exe**来验证它们。

然后它启动在**`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**中指定的**userinit.exe**，键为**Userinit**。

此外，前面的注册表中应该在**Shell键**中有**explorer.exe**，否则可能被滥用为**恶意软件持久性方法**。


## wininit.exe

**Windows初始化进程**。\
在会话0中启动**services.exe**，**lsass.exe**和**lsm.exe**。应该只有1个进程。


## userinit.exe

**用户登录应用程序**。\
加载**HKCU**中的**ntduser.dat**，初始化**用户环境**，运行**登录脚本**和**GPO**。

它启动**explorer.exe**。


## lsm.exe

**本地会话管理器**。\
它与smss.exe一起操作用户会话：登录/注销，启动shell，锁定/解锁桌面等。

在W7之后，lsm.exe被转换为一个服务（lsm.dll）。

在W7中应该只有1个进程，其中一个服务运行该DLL。


## services.exe

**服务控制管理器**。\
它**加载**配置为**自动启动**的**服务**和**驱动程序**。

它是**svchost.exe**，**dllhost.exe**，**taskhost.exe**，**spoolsv.exe**等的父进程。

服务在`HKLM\SYSTEM\CurrentControlSet\Services`中定义，此进程在内存中维护服务信息的数据库，可以通过sc.exe查询。

请注意，**一些** **服务**将在**自己的进程中运行**，而其他服务将在**共享的svchost.exe进程中运行**。

应该只有1个进程。


## lsass.exe

**本地安全机构子系统**。\
它负责用户**身份验证**和创建**安全** **令牌**。它使用位于`HKLM\System\CurrentControlSet\Control\Lsa`中的身份验证包。

它写入**安全** **事件** **日志**，应该只有1个进程。

请记住，这个进程经常受到攻击以转储密码。


## svchost.exe

**通用服务主机进程**。\
它在一个共享进程中托管多个DLL服务。

通常，您会发现**svchost.exe**是使用`-k`标志启动的。这将启动对注册表**HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**的查询，其中将包含一个带有-k参数的键，其中包含要在同一进程中启动的服务。

例如：`-k UnistackSvcGroup`将启动：`PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

如果还使用了**`-s`标志**并带有参数，则要求svchost仅在此参数中启动指定的服务。

将会有几个`svchost.exe`进程。如果其中任何一个**没有使用`-k`标志**，那就非常可疑。如果发现**services.exe不是父进程**，那也非常可疑。


## taskhost.exe

此进程充当运行自DLL的进程的主机。它还加载从DLL运行的服务。

在W8中称为taskhostex.exe，在W10中称为taskhostw.exe。


## explorer.exe

这是负责**用户桌面**和通过文件扩展名启动文件的进程。

**每个已登录用户**应该生成**只有1个**进程。

这是从**userinit.exe**运行的，应该被终止，因此此进程的**没有父进程**应该出现。


# 捕获恶意进程

* 它是否从预期路径运行？（没有Windows二进制文件从临时位置运行）
* 它是否与奇怪的IP通信？
* 检查数字签名（Microsoft工件应该被签名）
* 拼写正确吗？
* 是否在预期SID下运行？
* 父进程是否是预期的（如果有的话）？
* 子进程是否是预期的？（没有cmd.exe、wscript.exe、powershell.exe..？）

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
