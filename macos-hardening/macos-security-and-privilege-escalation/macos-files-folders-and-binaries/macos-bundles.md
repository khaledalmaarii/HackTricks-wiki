# macOS Bundels

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Basiese Inligting

Bundels in macOS dien as houers vir 'n verskeidenheid hulpbronne, insluitend toepassings, biblioteke en ander nodige lêers, wat dit laat voorkom as enkele voorwerpe in Finder, soos die bekende `*.app`-lêers. Die mees algemeen aangetroffe bundel is die `.app`-bundel, alhoewel ander tipes soos `.framework`, `.systemextension` en `.kext` ook algemeen voorkom.

### Essensiële Komponente van 'n Bundel

Binne 'n bundel, veral binne die `<toepassing>.app/Contents/`-gids, word 'n verskeidenheid belangrike hulpbronne gehuisves:

- **_CodeSignature**: Hierdie gids stoor kode-ondertekendetails wat noodsaaklik is vir die verifikasie van die integriteit van die toepassing. Jy kan die kode-ondertekeningsinligting inspekteer deur opdragte soos die volgende te gebruik:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Bevat die uitvoerbare binêre lêer van die toepassing wat uitgevoer word wanneer die gebruiker interaksie het.
- **Resources**: 'n Bergplek vir die toepassing se gebruikerskoppelvlakkomponente, insluitend beelde, dokumente en koppelvlakbeskrywings (nib/xib-lêers).
- **Info.plist**: Tree op as die toepassing se hoofkonfigurasie-lêer, wat noodsaaklik is vir die stelsel om die toepassing behoorlik te herken en mee te interaksieer.

#### Belangrike Sleutels in Info.plist

Die `Info.plist`-lêer is 'n hoeksteen vir toepassingskonfigurasie en bevat sleutels soos:

- **CFBundleExecutable**: Spesifiseer die naam van die hoofuitvoerbare lêer wat in die `Contents/MacOS`-gids geleë is.
- **CFBundleIdentifier**: Verskaf 'n globale identifiseerder vir die toepassing, wat uitgebreid deur macOS gebruik word vir toepassingsbestuur.
- **LSMinimumSystemVersion**: Dui die minimum weergawe van macOS aan wat vereis word vir die uitvoering van die toepassing.

### Verkenning van Bundels

Om die inhoud van 'n bundel, soos `Safari.app`, te verken, kan die volgende opdrag gebruik word:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Hierdie verkenning onthul gidsname soos `_CodeSignature`, `MacOS`, `Resources`, en lêernaam soos `Info.plist`, wat elk 'n unieke doel dien, van die beveiliging van die toepassing tot die definisie van sy gebruikerskoppelvlak en operasionele parameters.

#### Addisionele Bundelgidse

Buiten die algemene gidse kan bundels ook die volgende insluit:

- **Frameworks**: Bevat gebundelde raamwerke wat deur die toepassing gebruik word.
- **PlugIns**: 'n Gids vir invoegtoepassings en uitbreidings wat die vermoëns van die toepassing verbeter.
- **XPCServices**: Hou XPC-diens wat deur die toepassing gebruik word vir buiteproseskommunikasie.

Hierdie struktuur verseker dat alle nodige komponente binne die bundel gekapsuleer is, wat 'n modulêre en veilige toepassingsomgewing fasiliteer.

Vir meer gedetailleerde inligting oor `Info.plist`-sleutels en hul betekenisse, bied die Apple-ontwikkelaarsdokumentasie uitgebreide hulpbronne: [Apple Info.plist Sleutelverwys](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
