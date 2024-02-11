# macOS Installerse Misbruik

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Pkg Basiese Inligting

'n macOS **installasiepakkie** (ook bekend as 'n `.pkg`-lêer) is 'n lêerformaat wat deur macOS gebruik word om sagteware te **versprei**. Hierdie lêers is soos 'n **boks wat alles bevat wat 'n stuk sagteware** nodig het om korrek te installeer en te loop.

Die pakkie-lêer self is 'n argief wat 'n **hiërargie van lêers en gide bevat wat op die teikenrekenaar geïnstalleer sal word**. Dit kan ook **skripte** insluit om take voor en na die installasie uit te voer, soos die opstel van konfigurasie-lêers of die skoonmaak van ou weergawes van die sagteware.

### Hiërargie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Aanpassings (titel, welkomstekst...) en skrips/installasiekontroles
* **PackageInfo (xml)**: Inligting, installasievereistes, installasieplek, paaie na skripte om uit te voer
* **Bill of materials (bom)**: Lys van lêers om te installeer, op te dateer of te verwyder met lêerregte
* **Payload (CPIO-argief gzip-gekomprimeer)**: Lêers om te installeer in die `install-location` van PackageInfo
* **Skripte (CPIO-argief gzip-gekomprimeer)**: Voor- en na-installasieskripte en meer hulpbronne wat onttrek word na 'n tydelike gids vir uitvoering.

### Ontkomprimeer
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
## DMG Basiese Inligting

DMG-lêers, of Apple Disk Images, is 'n lêerformaat wat deur Apple se macOS gebruik word vir skyfafbeeldings. 'n DMG-lêer is in wese 'n **monteerbare skyfafbeelding** (dit bevat sy eie lêersisteem) wat gewoonlik saamgedruk en soms versleutelde rou blokdata bevat. Wanneer jy 'n DMG-lêer oopmaak, monteer macOS dit asof dit 'n fisiese skyf is, sodat jy toegang tot sy inhoud kan verkry.

### Hiërargie

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Die hiërargie van 'n DMG-lêer kan verskil afhangende van die inhoud. Vir toepassings-DMGs volg dit gewoonlik hierdie struktuur:

* Topvlak: Dit is die wortel van die skyfafbeelding. Dit bevat dikwels die toepassing en moontlik 'n skakel na die Toepassings-vouer.
* Toepassing (.app): Dit is die werklike toepassing. In macOS is 'n toepassing tipies 'n pakkie wat baie individuele lêers en vouers bevat wat die toepassing uitmaak.
* Toepassingskakel: Dit is 'n skakel na die Toepassings-vouer in macOS. Die doel hiervan is om dit maklik te maak om die toepassing te installeer. Jy kan die .app-lêer na hierdie skakel sleep om die app te installeer.

## Privesc via pkg-misbruik

### Uitvoering vanaf openbare gids

As 'n voor- of na-installasieskrip byvoorbeeld uitgevoer word vanaf **`/var/tmp/Installerutil`**, kan 'n aanvaller daardie skrip beheer en voorregte verhoog wanneer dit uitgevoer word. Of 'n ander soortgelyke voorbeeld:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dit is 'n [openbare funksie](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) wat verskeie installeerders en opdateringsoproep om iets as root uit te voer. Hierdie funksie aanvaar die **pad** van die **lêer** wat as parameter **uitgevoer** moet word, maar as 'n aanvaller hierdie lêer kon **verander**, sal hy in staat wees om die uitvoering daarvan met root te **misbruik** om voorregte te verhoog.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Vir meer inligting, kyk na hierdie praatjie: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Uitvoering deur montering

As 'n installeerder skryf na `/tmp/fixedname/bla/bla`, is dit moontlik om **'n montering te skep** oor `/tmp/fixedname` sonder eienaars sodat jy enige lêer tydens die installasie kan wysig om die installasieproses te misbruik.

'n Voorbeeld hiervan is **CVE-2021-26089** wat daarin geslaag het om 'n periodieke skripsie te **oorwrite** om uitvoering as root te verkry. Vir meer inligting, kyk na die praatjie: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as kwaadwillige sagteware

### Leë Nutslading

Dit is moontlik om net 'n **`.pkg`** lêer te genereer met **voor- en na-installasie skripsies** sonder enige nutslading.

### JS in Distribution xml

Dit is moontlik om **`<script>`** etikette by die **distribusie-xml** lêer van die pakkie te voeg en daardie kode sal uitgevoer word en dit kan **opdragte uitvoer** deur gebruik te maak van **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Verwysings

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
