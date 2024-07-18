# macOS Bundels

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Basiese Inligting

Bundels in macOS dien as houers vir 'n verskeidenheid bronne insluitend toepassings, biblioteke, en ander nodige lêers, wat hulle laat voorkom as enkel voorwerpe in Finder, soos die bekende `*.app` lêers. Die mees algemeen aangetrefte bundel is die `.app` bundel, alhoewel ander tipes soos `.framework`, `.systemextension`, en `.kext` ook algemeen voorkom.

### Essensiële Komponente van 'n Bundel

Binne 'n bundel, veral binne die `<toepassing>.app/Contents/` gids, word 'n verskeidenheid belangrike bronne gehuisves:

* **\_CodeSignature**: Hierdie gids stoor kode-ondertekeningsbesonderhede wat noodsaaklik is vir die verifikasie van die toepassing se integriteit. Jy kan die kode-ondertekeningsinligting inspekteer met bevele soos: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Bevat die uitvoerbare binêre van die toepassing wat hardloop wanneer die gebruiker interaksie het.
* **Hulpbronne**: 'n Berging vir die toepassing se gebruikerskoppelvlakkomponente insluitend beelde, dokumente, en koppelvlakbeskrywings (nib/xib lêers).
* **Info.plist**: Tree op as die toepassing se hoofkonfigurasie lêer, noodsaaklik vir die stelsel om die toepassing toepaslik te herken en mee te interageer.

#### Belangrike Sleutels in Info.plist

Die `Info.plist` lêer is 'n hoeksteen vir toepassingskonfigurasie, wat sleutels soos bevat:

* **CFBundleExecutable**: Spesifiseer die naam van die hoofuitvoerbare lêer wat in die `Contents/MacOS` gids geleë is.
* **CFBundleIdentifier**: Verskaf 'n globale identifiseerder vir die toepassing, wat wyd deur macOS gebruik word vir toepassingsbestuur.
* **LSMinimumSystemVersion**: Dui die minimum weergawe van macOS aan wat vir die toepassing benodig word om te hardloop.

### Verken Bundels

Om die inhoud van 'n bundel te verken, soos `Safari.app`, kan die volgende bevel gebruik word: `bash ls -lR /Applications/Safari.app/Contents`

Hierdie verkenning onthul gids soos `_CodeSignature`, `MacOS`, `Hulpbronne`, en lêers soos `Info.plist`, wat elk 'n unieke doel dien vanaf die beveiliging van die toepassing tot die definisie van sy gebruikerskoppelvlak en operasionele parameters.

#### Addisionele Bundelgidse

Verder as die algemene gidse, kan bundels ook insluit:

* **Raamwerke**: Bevat gebundelde raamwerke wat deur die toepassing gebruik word. Raamwerke is soos dylibs met ekstra bronne.
* **Inproppe**: 'n Gids vir inproppe en uitbreidings wat die toepassing se vermoëns verbeter.
* **XPC-dienste**: Hou XPC-dienste wat deur die toepassing vir buiteproseskommunikasie gebruik word.

Hierdie struktuur verseker dat alle nodige komponente binne die bundel ingesluit is, wat 'n modulêre en veilige toepassingsomgewing fasiliteer.

Vir meer gedetailleerde inligting oor `Info.plist` sleutels en hul betekenisse, bied die Apple-ontwikkelaardokumentasie uitgebreide bronne: [Apple Info.plist Sleutelverwysing](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
