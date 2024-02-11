<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


Daar is verskeie blogs op die internet wat **die gevaar van printers wat gekonfigureer is met LDAP met verstek/swak** aanmeldingslegitimasie beklemtoon.\
Dit is omdat 'n aanvaller die printer kan **mislei om teen 'n valse LDAP-bediener te verifieer** (tipies is 'n `nc -vv -l -p 444` genoeg) en om die drukker se **legitimasie-inligting in duidelike teks vas te vang**.

Verder sal verskeie drukkers **logs met gebruikersname bevat** of selfs in staat wees om **alle gebruikersname af te laai** van die domeinbeheerder.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak drukkers baie interessant vir aanvallers.

Sommige blogs oor die onderwerp:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Drukkerkonfigurasie
- **Plek**: Die LDAP-bedienerlys word gevind by: `Netwerk > LDAP-instelling > LDAP instellen`.
- **Gedrag**: Die koppelvlak maak dit moontlik om LDAP-bedienerveranderings aan te bring sonder om legitimasie-inligting weer in te voer, met die doel om gebruikersgerief te bied, maar dit stel sekuriteitsrisiko's.
- **Uitbuit**: Die uitbuit behels die omleiding van die LDAP-bedieneradres na 'n beheerde masjien en die benutting van die "Toets Verbinding" funksie om legitimasie-inligting vas te vang.

## Vasvang van Legitimasie-inligting

**Vir meer gedetailleerde stappe, verwys na die oorspronklike [bron](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metode 1: Netcat Luisteraar
'n Eenvoudige netcat luisteraar mag voldoende wees:
```bash
sudo nc -k -v -l -p 386
```
### Metode 2: Volledige LDAP-bediener met Slapd
'n Meer betroubare benadering behels die opstel van 'n volledige LDAP-bediener omdat die drukker 'n nul-bind en 'n navraag uitvoer voordat hy poog om legitimasie te bind.

1. **Opstel van LDAP-bediener**: Die gids volg stappe vanaf [hierdie bron](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Belangrike stappe**:
- Installeer OpenLDAP.
- Stel die administrateur wagwoord in.
- Importeer basiese skemas.
- Stel domeinnaam in op LDAP DB.
- Stel LDAP TLS in.
3. **Uitvoering van LDAP-diens**: Sodra dit opgestel is, kan die LDAP-diens uitgevoer word deur gebruik te maak van:
```bash
slapd -d 2
```
## Verwysings
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
