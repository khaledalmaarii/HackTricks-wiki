# ZIP-truuks

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

**Opdraglynhulpmiddels** vir die bestuur van **zip-lêers** is noodsaaklik vir die diagnose, herstel en kraak van zip-lêers. Hier is 'n paar sleutelhulpprogramme:

- **`unzip`**: Onthul waarom 'n zip-lêer nie gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied 'n gedetailleerde analise van die velds van die zip-lêerformaat.
- **`zipinfo`**: Lys die inhoud van 'n zip-lêer sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer om beskadigde zip-lêers te herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n Hulpmiddel vir bruto-kragkraak van zip-wagwoorde, effektief vir wagwoorde tot ongeveer 7 karakters.

Die [Zip-lêerformaat spesifikasie](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bied omvattende besonderhede oor die struktuur en standaarde van zip-lêers.

Dit is belangrik om daarop te let dat wagwoord-beskermde zip-lêers **nie lêernaam of lêergroottes versleutel nie**, 'n veiligheidsgebrek wat nie gedeel word met RAR- of 7z-lêers wat hierdie inligting versleutel nie. Verder is zip-lêers wat met die ouer ZipCrypto-metode versleutel is, vatbaar vir 'n **platte tekst-aanval** as 'n onversleutelde kopie van 'n saamgedrukte lêer beskikbaar is. Hierdie aanval maak gebruik van die bekende inhoud om die wagwoord van die zip te kraak, 'n kwesbaarheid wat in [HackThis se artikel](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beskryf word en verder verduidelik word in [hierdie akademiese artikel](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Tog is zip-lêers wat met **AES-256**-versleuteling beveilig is, immuun teen hierdie platte tekst-aanval, wat die belangrikheid van die keuse van veilige versleutelingsmetodes vir sensitiewe data beklemtoon.

## Verwysings
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
