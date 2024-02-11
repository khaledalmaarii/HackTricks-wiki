<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


Vir 'n phising-assessering kan dit soms nuttig wees om 'n webwerf heeltemal te **kloneer**.

Let daarop dat jy ook sekere ladinge by die gekloonde webwerf kan voeg, soos 'n BeEF-haak om die tabblad van die gebruiker te "beheer".

Daar is verskillende gereedskap wat jy vir hierdie doel kan gebruik:

## wget
```text
wget -mk -nH
```
## gokloon

Hierdie hulpmiddel word gebruik om 'n webwerf te kloon en 'n identiese kopie daarvan te skep. Dit kan gebruik word vir phising-aanvalle waar 'n aanvaller 'n nagemaakte weergawe van 'n legitieme webwerf skep om gebruikers se inligting te bekom.

### Gebruik

1. Installeer die `goclone`-hulpmiddel deur die opdrag `go get github.com/muhammadmuzzammil1998/goclone` uit te voer.
2. Voer die opdrag `goclone -url <URL> -output <UITSET>` uit, waar `<URL>` die URL van die te kloon webwerf is en `<UITSET>` die uitsetgids is waarin die gekloonde webwerf gestoor moet word.
3. Die hulpmiddel sal die webwerf kloon en al die nodige lêers en bronne in die opgegeven uitsetgids stoor.

### Voorbeelde

- Kloon 'n webwerf en stoor dit in die huidige gids:
  ```
  goclone -url https://www.example.com -output .
  ```

- Kloon 'n webwerf en stoor dit in 'n spesifieke gids:
  ```
  goclone -url https://www.example.com -output /path/to/output
  ```

### Waarskuwing

Dit is belangrik om te onthou dat die kloning van 'n webwerf sonder toestemming van die eienaar onwettig is. Hierdie hulpmiddel moet slegs gebruik word vir wettige doeleindes, soos toegelaat deur die wet.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosiale Ingenieurswese Gereedskapskis

### Kloon 'n Webwerf

Hierdie metode behels die kloning van 'n bestaande webwerf om gebruikers se inligting te verkry deur middel van sosiale ingenieurswese. Hier is die stappe wat gevolg kan word om 'n webwerf te kloon:

1. Identifiseer die teikenwebwerf wat jy wil kloon.
2. Skep 'n nuwe webwerf of subdomein wat soortgelyk is aan die teikenwebwerf.
3. Kry toegang tot die bronkode van die teikenwebwerf.
4. Analiseer die bronkode om die struktuur en funksionaliteit van die webwerf te verstaan.
5. Skep 'n kopie van die webwerf se ontwerp en inhoud.
6. Pas die gekloonde webwerf aan om dit soortgelyk aan die teikenwebwerf te maak.
7. Stel 'n valse aanmeldingsbladsy op wat gebruikers se inligting sal onderskep.
8. Stuur 'n phising-e-pos na die teikengebruikers om hulle na die gekloonde webwerf te lok.
9. Monitor die gekloonde webwerf vir inkomende aanmeldingsinligting.
10. Onttrek die verkrygde inligting en gebruik dit vir verdere aanvalle of identiteitsdiefstal.

Dit is belangrik om te onthou dat die kloning van 'n webwerf sonder toestemming onwettig is en ernstige gevolge kan hê. Hierdie metode moet slegs gebruik word vir wettige doeleindes, soos om bewusmaking oor sosiale ingenieurswese te skep of om sekuriteitslekke in 'n webwerf te identifiseer.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
