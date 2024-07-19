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


Daar is verskeie blogs op die Internet wat **die gevare van die gebruik van printers met LDAP met standaard/ swak** aanmeldbesonderhede beklemtoon.\
Dit is omdat 'n aanvaller **die printer kan mislei om teen 'n kwaadwillige LDAP-bediener te verifieer** (tipies is 'n `nc -vv -l -p 444` genoeg) en om die printer **aanmeldbesonderhede in duidelike teks** te vang.

Ook, verskeie printers sal **logs met gebruikersname** bevat of kan selfs in staat wees om **alle gebruikersname** van die Domeinbeheerder te **aflaai**.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak printers baie interessant vir aanvallers.

Sommige blogs oor die onderwerp:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Printer Konfigurasie
- **Ligging**: Die LDAP-bedienerlys is te vind by: `Network > LDAP Setting > Setting Up LDAP`.
- **Gedrag**: Die koppelvlak laat LDAP-bedienerwysigings toe sonder om aanmeldbesonderhede weer in te voer, wat op gebruikersgerief gemik is, maar sekuriteitsrisiko's inhou.
- **Eksploiteer**: Die eksploitasie behels die herleiding van die LDAP-bedieneradres na 'n beheerde masjien en die gebruik van die "Toets Verbinding" kenmerk om aanmeldbesonderhede te vang.

## Vang Aanmeldbesonderhede

**Vir meer gedetailleerde stappe, verwys na die oorspronklike [bron](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metode 1: Netcat Luisteraar
'n Eenvoudige netcat luisteraar mag genoeg wees:
```bash
sudo nc -k -v -l -p 386
```
However, hierdie metode se sukses verskil.

### Metode 2: Volledige LDAP-bediener met Slapd
'n Meer betroubare benadering behels die opstelling van 'n volledige LDAP-bediener omdat die drukker 'n null bind uitvoer gevolg deur 'n navraag voordat dit probeer om geloofsbriewe te bind.

1. **LDAP-bedieneropstelling**: Die gids volg stappe van [hierdie bron](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Belangrike Stappe**:
- Installeer OpenLDAP.
- Konfigureer admin wagwoord.
- Importeer basiese skemas.
- Stel domeinnaam op LDAP DB.
- Konfigureer LDAP TLS.
3. **LDAP-diensuitvoering**: Sodra dit opgestel is, kan die LDAP-diens uitgevoer word met:
```bash
slapd -d 2
```
## Verwysings
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
