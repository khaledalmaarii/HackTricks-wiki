<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>




# 开始

[你需要编译它](https://github.com/GhostPack/Seatbelt) 或者 [使用预编译的二进制文件（由我提供）](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)
```text
SeatbeltNet3.5x64.exe all
SeatbeltNet3.5x64.exe all full #Without filtering
```
我真的很喜欢所进行的过滤。

# 检查

这个工具更注重信息收集而不是权限提升，但它有一些非常好的检查，并查找一些密码。

**SeatBelt.exe system** 收集以下系统数据：
```text
BasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)
RebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13
TokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)
UACSystemPolicies     -   UAC system policies via the registry
PowerShellSettings    -   PowerShell versions and security settings
AuditSettings         -   Audit settings via the registry
WEFSettings           -   Windows Event Forwarding (WEF) settings via the registry
LSASettings           -   LSA settings (including auth packages)
UserEnvVariables      -   Current user environment variables
SystemEnvVariables    -   Current system environment variables
UserFolders           -   Folders in C:\Users\
NonstandardServices   -   Services with file info company names that don't contain 'Microsoft'
InternetSettings      -   Internet settings including proxy configs
LapsSettings          -   LAPS settings, if installed
LocalGroupMembers     -   Members of local admins, RDP, and DCOM
MappedDrives          -   Mapped drives
RDPSessions           -   Current incoming RDP sessions
WMIMappedDrives       -   Mapped drives via WMI
NetworkShares         -   Network shares
FirewallRules         -   Deny firewall rules, "full" dumps all
AntiVirusWMI          -   Registered antivirus (via WMI)
InterestingProcesses  -   "Interesting" processes- defensive products and admin tools
RegistryAutoRuns      -   Registry autoruns
RegistryAutoLogon     -   Registry autologon information
DNSCache              -   DNS cache entries (via WMI)
ARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)
AllTcpConnections     -   Lists current TCP connections and associated processes
AllUdpConnections     -   Lists current UDP connections and associated processes
NonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'
*  If the user is in high integrity, the following additional actions are run:
SysmonConfig          -   Sysmon configuration from the registry
```
**SeatBelt.exe user** 收集以下用户数据：

```plaintext
- 用户名
- 用户SID
- 用户组
- 用户主目录
- 用户配置文件路径
- 用户登录时间
- 用户上次登录时间
- 用户密码过期时间
- 用户是否是管理员
- 用户是否是域用户
- 用户是否是内置管理员
- 用户是否是内置用户
- 用户是否是内置Guest
- 用户是否是内置ASPNET
- 用户是否是内置IUSR
- 用户是否是内置IWAM
- 用户是否是内置SERVICE
- 用户是否是内置LOCAL SERVICE
- 用户是否是内置NETWORK SERVICE
- 用户是否是内置SYSTEM
- 用户是否是内置LOCAL
- 用户是否是内置REMOTE
- 用户是否是内置INTERACTIVE
- 用户是否是内置CONSOLE LOGON
- 用户是否是内置ANONYMOUS
- 用户是否是内置AUTHENTICATED USERS
- 用户是否是内置TERMINAL SERVER USER
- 用户是否是内置TERMINAL SERVER LICENSE SERVER
- 用户是否是内置TERMINAL SERVER ADMINISTRATORS
- 用户是否是内置TERMINAL SERVER USERS
- 用户是否是内置TERMINAL SERVER GATEWAY SERVER
- 用户是否是内置TERMINAL SERVER LICENSE SERVER WORKSTATION
- 用户是否是内置TERMINAL SERVER REMOTE CONNECT
- 用户是否是内置TERMINAL SERVER REMOTE INTERACTIVE
- 用户是否是内置TERMINAL SERVER REMOTE USERS
- 用户是否是内置TERMINAL SERVER REMOTE CONTROL
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE ACTIVATE
- 用户是否是内置TERMINAL SERVER REMOTE
```text
SavedRDPConnections   -   Saved RDP connections
TriageIE              -   Internet Explorer bookmarks and history (last 7 days)
DumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb
RecentRunCommands     -   Recent "run" commands
PuttySessions         -   Interesting settings from any saved Putty configurations
PuttySSHHostKeys      -   Saved putty SSH host keys
CloudCreds            -   AWS/Google/Azure cloud credential files (SharpCloud)
RecentFiles           -   Parsed "recent files" shortcuts (last 7 days)
MasterKeys            -   List DPAPI master keys
CredFiles             -   List Windows credential DPAPI blobs
RDCManFiles           -   List Windows Remote Desktop Connection Manager settings files
*  If the user is in high integrity, this data is collected for ALL users instead of just the current user
```
非默认的收集选项：

```plaintext
- **Seatbelt** is a tool developed by SpecterOps that gathers information about the current user's environment and configuration. It can be used to identify potential vulnerabilities and misconfigurations that could lead to local privilege escalation.

- By default, Seatbelt collects a wide range of information, including user privileges, installed applications, network configurations, scheduled tasks, and more. However, it also provides the option to customize the collection by specifying specific modules or categories to gather information from.

- When using Seatbelt for local privilege escalation, it is recommended to review and modify the collection options to focus on the areas of interest. This allows for a more targeted approach and reduces the noise generated by irrelevant information.

- To modify the collection options, simply run Seatbelt with the desired module or category flags. For example, to only collect information related to user privileges, the command would be: `Seatbelt.exe --userprivs`.

- By customizing the collection options, you can streamline the output and focus on the specific information needed for local privilege escalation. This can save time and make the analysis process more efficient.
```

非默认的收集选项：

```plaintext
- **Seatbelt** 是由SpecterOps开发的一款工具，用于收集有关当前用户环境和配置的信息。它可以用于识别潜在的漏洞和配置错误，从而导致本地权限提升。

- 默认情况下，Seatbelt会收集各种信息，包括用户权限、已安装的应用程序、网络配置、计划任务等等。然而，它还提供了自定义收集选项，可以指定特定的模块或类别来收集信息。

- 在使用Seatbelt进行本地权限提升时，建议审查和修改收集选项，以便关注感兴趣的领域。这样可以更有针对性地进行分析，并减少无关信息带来的干扰。

- 要修改收集选项，只需使用所需的模块或类别标志运行Seatbelt。例如，仅收集与用户权限相关的信息的命令为：`Seatbelt.exe --userprivs`。

- 通过自定义收集选项，您可以简化输出并专注于本地权限提升所需的特定信息。这可以节省时间并使分析过程更高效。
```
```text
CurrentDomainGroups   -   The current user's local and domain groups
Patches               -   Installed patches via WMI (takes a bit on some systems)
LogonSessions         -   User logon session data
KerberosTGTData       -   ALL TEH TGTZ!
InterestingFiles      -   "Interesting" files matching various patterns in the user's folder
IETabs                -   Open Internet Explorer tabs
TriageChrome          -   Chrome bookmarks and history
TriageFirefox         -   Firefox history (no bookmarks)
RecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
4624Events            -   4624 logon events from the security event log
4648Events            -   4648 explicit logon events from the security event log
KerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
