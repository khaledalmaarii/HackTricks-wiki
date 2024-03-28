# macOS Bundels

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

Bundels in macOS dien as houers vir 'n verskeidenheid bronne insluitend toepassings, biblioteke, en ander nodige lêers, wat hulle laat voorkom as enkel voorwerpe in Finder, soos die bekende `*.app` lêers. Die mees algemeen aangetrefte bundel is die `.app` bundel, alhoewel ander tipes soos `.framework`, `.systemextension`, en `.kext` ook algemeen voorkom.

### Essensiële Komponente van 'n Bundel

Binne 'n bundel, veral binne die `<toepassing>.app/Contents/` gids, word 'n verskeidenheid belangrike bronne gehuisves:

* **\_CodeSignature**: Hierdie gids stoor kode-ondertekeningsbesonderhede wat noodsaaklik is vir die verifikasie van die toepassing se integriteit. Jy kan die kode-ondertekeningsinligting inspekteer met bevele soos: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Bevat die uitvoerbare binêre van die toepassing wat loop wanneer die gebruiker interaksie het.
* **Hulpbronne**: 'n Berging vir die toepassing se gebruikerskoppelvlakkomponente insluitend beelde, dokumente, en koppelvlakbeskrywings (nib/xib lêers).
* **Info.plist**: Tree op as die toepassing se hoofkonfigurasie-lêer, noodsaaklik vir die stelsel om die toepassing toepaslik te herken en mee te interageer.

#### Belangrike Sleutels in Info.plist

Die `Info.plist` lêer is 'n hoeksteen vir toepassingskonfigurasie, wat sleutels soos bevat:

* **CFBundleExecutable**: Spesifiseer die naam van die hoofuitvoerbare lêer wat in die `Contents/MacOS` gids geleë is.
* **CFBundleIdentifier**: Verskaf 'n globale identifiseerder vir die toepassing, wat wyd deur macOS gebruik word vir toepassingsbestuur.
* **LSMinimumSystemVersion**: Dui die minimum weergawe van macOS aan wat vir die toepassing nodig is om te loop.

### Verken Bundels

Om die inhoud van 'n bundel te verken, soos `Safari.app`, kan die volgende bevel gebruik word: `bash ls -lR /Applications/Safari.app/Contents`

Hierdie verkenning onthul gids soos `_CodeSignature`, `MacOS`, `Hulpbronne`, en lêers soos `Info.plist`, wat elk 'n unieke doel dien van die beveiliging van die toepassing tot die definisie van sy gebruikerskoppelvlak- en operasionele parameters.

#### Addisionele Bundelgidse

Verder as die algemene gidse, kan bundels ook insluit:

* **Raamwerke**: Bevat gebundelde raamwerke wat deur die toepassing gebruik word. Raamwerke is soos dylibs met ekstra bronne.
* **Inproppe**: 'n Gids vir inproppe en uitbreidings wat die toepassing se vermoëns verbeter.
* **XPC-dienste**: Hou XPC-dienste wat deur die toepassing vir buiteproseskommunikasie gebruik word.

Hierdie struktuur verseker dat alle nodige komponente binne die bundel ingesluit is, wat 'n modulêre en veilige toepassingsomgewing fasiliteer.

Vir meer gedetailleerde inligting oor `Info.plist` sleutels en hul betekenisse, bied die Apple-ontwikkelaardokumentasie uitgebreide bronne: [Apple Info.plist Sleutelverwysing](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
