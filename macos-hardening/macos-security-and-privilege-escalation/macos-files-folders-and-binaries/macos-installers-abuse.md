# macOS Installer Misbruik

{% hint style="success" %}
Leer en oefen AWS Hacken: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP Hacken: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan bij de** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of de [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Basiese Inligting

'n macOS **installeerpakket** (ook bekend as 'n `.pkg` lêer) is 'n lêerformaat wat deur macOS gebruik word om **sagteware te versprei**. Hierdie lêers is soos 'n **kas wat alles bevat wat 'n stuk sagteware** nodig het om korrek te installeer en te hardloop.

Die pakketlêer self is 'n argief wat 'n **hiërargie van lêers en gideons bevat wat op die teikenrekenaar geïnstalleer sal word**. Dit kan ook **skripte** insluit om take voor en na die installasie uit te voer, soos die opstel van konfigurasie lêers of die skoonmaak van ou weergawes van die sagteware.

### Hiërargie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Verspreiding (xml)**: Aanpassings (titel, welkomsteks...) en skrip/installasie kontroles
* **PackageInfo (xml)**: Inligting, installeer vereistes, installeer ligging, paaie na skripte om uit te voer
* **Materiaalstaat (bom)**: Lys van lêers om te installeer, op te dateer of te verwyder met lêerregte
* **Vrag (CPIO argief gzip saamgedruk)**: Lêers om in die `installeer-ligging` van PackageInfo te installeer
* **Skripte (CPIO argief gzip saamgedruk)**: Voor en na installasie skripte en meer bronne wat na 'n tydelike gids onttrek word vir uitvoering.

### Dekomprimeer
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Om die inhoud van die installateur te visualiseer sonder om dit handmatig te dekomprimeer, kan jy ook die gratis gereedskap [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) gebruik.

## DMG Basiese Inligting

DMG-lêers, of Apple Skyfafbeeldings, is 'n lêerformaat wat deur Apple se macOS vir skyfafbeeldings gebruik word. 'n DMG-lêer is essensieel 'n **monteerbare skyfafbeelding** (dit bevat sy eie lêersisteem) wat rou blokdata bevat wat tipies gecomprimeer en soms versleutel is. Wanneer jy 'n DMG-lêer oopmaak, **monteer macOS dit asof dit 'n fisiese skyf was**, wat jou in staat stel om by sy inhoud te kom.

{% hint style="danger" %}
Let daarop dat **`.dmg`** installateurs **so baie formate** ondersteun dat in die verlede sommige van hulle wat kwesbaarhede bevat het, misbruik is om **kernel-kode-uitvoering** te verkry.
{% endhint %}

### Hiërargie

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Die hiërargie van 'n DMG-lêer kan verskil op grond van die inhoud. Vir aansoek-DMGs volg dit gewoonlik hierdie struktuur:

* Bo-vlak: Dit is die wortel van die skyfafbeelding. Dit bevat dikwels die aansoek en moontlik 'n skakel na die Toepassings-vouer.
* Aansoek (.app): Dit is die werklike aansoek. In macOS is 'n aansoek tipies 'n pakkie wat baie individuele lêers en vouers bevat wat die aansoek uitmaak.
* Toepassingskakel: Dit is 'n kortpad na die Toepassings-vouer in macOS. Die doel hiervan is om dit vir jou maklik te maak om die aansoek te installeer. Jy kan die .app-lêer na hierdie kortpad sleep om die aansoek te installeer.

## Privesc via pkg-misbruik

### Uitvoering vanaf openbare gids

As 'n voor- of na-installasieskrip byvoorbeeld uitgevoer word vanaf **`/var/tmp/Installerutil`**, en 'n aanvaller daardie skrip kan beheer, kan hy voorregte eskaleer wanneer dit uitgevoer word. Of 'n ander soortgelyke voorbeeld:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dit is 'n [openbare funksie](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) wat verskeie installateurs en opdateringsoproep om iets as root uit te voer. Hierdie funksie aanvaar die **pad** van die **lêer** om as parameter **uit te voer**, maar as 'n aanvaller hierdie lêer kon **verander**, sal hy in staat wees om sy uitvoering met root te **misbruik** om voorregte te **eskaleer**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Uitvoering deur montering

Indien 'n installeerder skryf na `/tmp/fixedname/bla/bla`, is dit moontlik om **'n montering te skep** oor `/tmp/fixedname` met geen eienaars, sodat jy **enige lêer tydens die installasie kan wysig** om die installasieproses te misbruik.

'n Voorbeeld hiervan is **CVE-2021-26089** wat daarin geslaag het om 'n periodieke skripsie te **oorwryf om uitvoering as 'n hoofgebruiker te kry**. Vir meer inligting, kyk na die aanbieding: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as skadelike sagteware

### Leë Vrag

Dit is moontlik om net 'n **`.pkg`** lêer te genereer met **voor- en na-installeer skripte** sonder enige vrag.

### JS in Verspreidings-xml

Dit is moontlik om **`<script>`** etikette by die **verspreidings-xml** lêer van die pakkie te voeg en daardie kode sal uitgevoer word en dit kan **opdragte uitvoer** deur **`system.run`** te gebruik:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Verwysings

* [**DEF CON 27 - Ontpakkings Pkgs 'n Blik Binne-in Macos Installer-pakkette en Algemene Sekuriteitsfoute**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Die Wildernis van macOS-installeerders" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Ontpakkings Pkgs 'n Blik Binne-in MacOS Installer-pakkette**](https://www.youtube.com/watch?v=kCXhIYtODBg)
