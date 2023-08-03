<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


## smss.exe

**会话管理器**。\
会话0启动**csrss.exe**和**wininit.exe**（**操作系统服务**），而会话1启动**csrss.exe**和**winlogon.exe**（**用户会话**）。然而，在进程树中，你应该只看到一个没有子进程的该二进制文件的进程。

此外，除了0和1之外的会话可能意味着正在发生RDP会话。


## csrss.exe

**客户端/服务器运行子系统进程**。\
它管理**进程**和**线程**，为其他进程提供**Windows API**，还**映射驱动器字母**，创建**临时文件**，处理**关机过程**。

在会话0和会话1中各有一个（因此进程树中有2个进程）。每个新会话都会创建另一个进程。


## winlogon.exe

**Windows登录进程**。\
它负责用户的**登录**/**注销**。它启动**logonui.exe**以请求用户名和密码，然后调用**lsass.exe**进行验证。

然后它启动**userinit.exe**，该文件在**`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**中的**Userinit**键中指定。

此外，上述注册表中的**Shell键**应该包含**explorer.exe**，否则可能被滥用为**恶意软件持久化方法**。


## wininit.exe

**Windows初始化进程**。\
它在会话0中启动**services.exe**、**lsass.exe**和**lsm.exe**。应该只有一个进程。


## userinit.exe

**Userinit登录应用程序**。\
加载**HKCU**中的**ntuser.dat**，初始化**用户环境**，运行**登录脚本**和**GPO**。

它启动**explorer.exe**。


## lsm.exe

**本地会话管理器**。\
它与smss.exe一起操作用户会话：登录/注销、启动shell、锁定/解锁桌面等。

在Windows 7之后，lsm.exe被转换为一个服务（lsm.dll）。

在Windows 7中应该只有一个进程，其中一个服务运行该DLL。


## services.exe

**服务控制管理器**。\
它**加载**配置为**自动启动**的**服务**和**驱动程序**。

它是**svchost.exe**、**dllhost.exe**、**taskhost.exe**、**spoolsv.exe**等进程的父进程。

服务在`HKLM\SYSTEM\CurrentControlSet\Services`中定义，该进程在内存中维护一个服务信息的数据库，可以通过sc.exe查询。

请注意，**某些服务**将在**自己的进程中运行**，而其他服务将在**共享的svchost.exe进程中运行**。

应该只有一个进程。


## lsass.exe

**本地安全机构子系统**。\
它负责用户的**身份验证**并创建**安全令牌**。它使用位于`HKLM\System\CurrentControlSet\Control\Lsa`中的身份验证包。

它将写入**安全事件日志**，应该只有一个进程。

请记住，这个进程很容易受到密码转储的攻击。


## svchost.exe

**通用服务主机进程**。\
它在一个共享进程中托管多个DLL服务。

通常，你会发现**svchost.exe**是以`-k`标志启动的。这将在注册表**HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**中发起一个查询，其中将有一个带有-k参数的键，其中包含要在同一进程中启动的服务。

例如：`-k UnistackSvcGroup`将启动：`PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

如果还使用了**`-s`标志**和一个参数，那么svchost将被要求**仅启动指定的服务**。

将会有多个`svchost.exe`进程。如果其中任何一个**没有使用`-k`标志**，那就非常可疑。如果你发现**services.exe不是父进程**，那也非常可疑。
## taskhost.exe

此进程作为从DLL运行的进程的主机。它还加载从DLL运行的服务。

在W8中，它被称为taskhostex.exe，在W10中被称为taskhostw.exe。


## explorer.exe

这个进程负责**用户的桌面**和通过文件扩展名启动文件。

**每个登录的用户**只应该生成**一个**进程。

这是从**userinit.exe**运行的，应该被终止，所以这个进程**不应该有父进程**。


# 捕获恶意进程

* 它是否从预期的路径运行？（没有Windows二进制文件从临时位置运行）
* 它是否与奇怪的IP通信？
* 检查数字签名（Microsoft的工件应该是有签名的）
* 拼写是否正确？
* 是否在预期的SID下运行？
* 父进程是否是预期的（如果有的话）？
* 子进程是否是预期的？（没有cmd.exe，wscript.exe，powershell.exe等）


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
