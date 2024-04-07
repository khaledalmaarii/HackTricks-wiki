# macOS Sekuriteit & Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutbeloningsjagters te kommunikeer!

**Hakinsigte**\
Gaan in gesprek met inhoud wat die opwinding en uitdagings van hakken ondersoek

**Nuutste Haknuus**\
Bly op hoogte van die snelveranderende hakwêreld deur middel van nuus en insigte in werklikheid

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en noodsaaklike platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

## Basiese MacOS

As jy nie vertroud is met macOS nie, moet jy begin om die basiese beginsels van macOS te leer:

* Spesiale macOS **lêers & toestemmings:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Gewone macOS **gebruikers**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Die **argitektuur** van die k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Gewone macOS n**etwerkdienste & protokolle**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Om 'n `tar.gz` af te laai, verander 'n URL soos [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In maatskappye is **macOS**-stelsels hoogs waarskynlik om **bestuur te word met 'n MDM**. Daarom is dit vir 'n aanvaller interessant om te weet **hoe dit werk**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspekteer, Foutopsporing en Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Sekuriteitsbeskerming

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Aanvalsoppervlak

### Lêertoestemmings

As 'n **proses wat as root loop 'n lêer skryf** wat deur 'n gebruiker beheer kan word, kan die gebruiker dit misbruik om **voorregte te verhoog**.\
Dit kan in die volgende situasies gebeur:

* Lêer wat reeds deur 'n gebruiker geskep is (behoort aan die gebruiker)
* Lêer wat deur die gebruiker skryfbaar is weens 'n groep
* Lêer wat binne 'n gids behoort aan die gebruiker is (die gebruiker kan die lêer skep)
* Lêer wat binne 'n gids behoort aan root is, maar die gebruiker skryftoegang het daaroor weens 'n groep (die gebruiker kan die lêer skep)

Om 'n **lêer te skep** wat deur root gaan word **gebruik**, stel dit 'n gebruiker in staat om voordeel te trek uit die inhoud daarvan of selfs **simbole/harde skakels** te skep om dit na 'n ander plek te verwys.

Vir hierdie soort kwesbaarhede, moenie vergeet om kwesbare `.pkg`-installeerders te **ondersoek** nie:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Lêeruitbreiding & URL-skema-toepassingshanteraars

Vreemde toepassings wat geregistreer is deur lêeruitbreidings kan misbruik word en verskillende toepassings kan geregistreer word om spesifieke protokolle oop te maak

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Voorregverhoging

In macOS kan **toepassings en bineêre lêers toestemmings** hê om toegang tot lêers of instellings te verkry wat hulle bevoorregter maak as ander.

Daarom sal 'n aanvaller wat 'n macOS-rekenaar suksesvol wil kompromiteer, sy TCC-voorregte moet **verhoog** (of selfs **SIP omseil**, afhangende van sy behoeftes).

Hierdie voorregte word gewoonlik gegee in die vorm van **toekennings** waarvoor die toepassing onderteken is, of die toepassing kan toegang tot sekere dinge versoek en nadat die **gebruiker dit goedgekeur het**, kan dit in die **TCC-databasisse** gevind word. 'n Ander manier waarop 'n proses hierdie voorregte kan verkry, is deur 'n **kind van 'n proses** met daardie **voorregte** te wees aangesien hulle gewoonlik **oorerf** word.

Volg hierdie skakels om verskillende maniere te vind om [**voorregte in TCC te verhoog**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), om TCC te **omseil**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) en hoe in die verlede [**SIP omseil is**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradisionele Voorregverhoging

Natuurlik moet jy as 'n rooi span ook belangstel om na root te verhoog. Kyk na die volgende pos vir 'n paar wenke:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Verwysings

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutbeloningsjagters te kommunikeer!

**Hack-insigte**\
Gaan in gesprek met inhoud wat die opwinding en uitdagings van hack bekyk

**Hack Nuus in Werklikheid**\
Bly op hoogte van die snelveranderende hackwêreld deur middel van werklikheidsnuus en insigte

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en noodsaaklike platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
