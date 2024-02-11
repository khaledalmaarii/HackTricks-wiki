# macOS Sekuriteit & Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en foutjagters!

**Hacking Insights**\
Gaan in gesprek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Real-Time Hack News**\
Bly op hoogte van die vinnige wêreld van hacking deur middel van nuus en insigte in werklikheid

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutjagbounties wat begin en belangrike platformopdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

## Basiese MacOS

As jy nie bekend is met macOS nie, moet jy begin om die basiese beginsels van macOS te leer:

* Spesiale macOS **lêers & toestemmings:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Algemene macOS **gebruikers**

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

* Algemene macOS-n**etwerkdienste & protokolle**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Om 'n `tar.gz` af te laai, verander 'n URL soos [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In maatskappye word **macOS**-stelsels hoogstwaarskynlik **bestuur met 'n MDM**. Daarom is dit interessant vir 'n aanvaller om te weet **hoe dit werk**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspekteer, Debuksie en Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Sekuriteitsbeskerming

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Aanvalsoppervlak

### Lêertoestemmings

As 'n **proses wat as root loop** 'n lêer skryf wat deur 'n gebruiker beheer kan word, kan die gebruiker dit misbruik om **voorregte te verhoog**.\
Dit kan in die volgende situasies gebeur:

* Die gebruikte lêer is reeds deur 'n gebruiker geskep (behoort aan die gebruiker)
* Die gebruikte lêer is skryfbaar deur die gebruiker as gevolg van 'n groep
* Die gebruikte lêer is binne 'n gids wat aan die gebruiker behoort (die gebruiker kan die lêer skep)
* Die gebruikte lêer is binne 'n gids wat aan root behoort, maar die gebruiker het skryftoegang daartoe as gevolg van 'n groep (die gebruiker kan die lêer skep)

Om 'n lêer te **skep** wat deur root gebruik gaan word, stel 'n gebruiker in staat om van die inhoud daarvan gebruik te maak of selfs **simboliese skakels/harde skakels** te skep om dit na 'n ander plek te verwys.

Vir hierdie soort kwesbaarhede, moenie vergeet om kwesbare `.pkg`-installeerders te **ondersoek** nie:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Lêeruitbreiding & URL-skema-apphanteraars

Vreemde programme wat geregistreer is deur lêeruitbreidings, kan misbruik word en verskillende toepassings kan geregistreer word om spesifieke protokolle oop te maak

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Voorregverhoging

In macOS **kan programme en binnerwerke toestemmings hê** om toegang tot lêers of instellings te verkry wat hulle bevoorregter maak as ander.

Daarom sal 'n aanvaller wat 'n macOS-rekenaar suksesvol wil kompromitteer, sy TCC-voorregte moet **verhoog** (of selfs **SIP omseil**, afhangende van sy behoeftes).

Hierdie voorregte word gewoonlik gegee in die vorm van **toekennings** waarvoor die toepassing onderteken is, of die toepassing kan toegang versoek en nadat die **gebruiker dit goedgekeur** het, kan dit in die **TCC-databasisse** gevind word. 'n Proses kan hierdie voorregte ook verkry deur 'n **kind van 'n proses** te wees met daardie **voorregte**, aangesien hulle gewoonlik **oorerf** word.

Volg hierdie skakels om verskillende maniere te vind om [**voorregte in TCC te verhoog**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), om [**TCC te omseil**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) en hoe in die verlede [**SIP omseil is**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradisionele Voorregverhoging

Natuurlik moet jy as 'n rooi span ook belangstel om na root te verhoog. Kyk na die volgende berig vir 'n paar wenke:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Verwysings

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutbeloningsjagters te kommunikeer!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hacking ondersoek

**Real-Time Hack News**\
Bly op hoogte van die vinnige wêreld van hacking deur middel van real-time nuus en insigte

**Nuutste aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en belangrike platform-opdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
