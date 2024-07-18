# macOS Sekuriteit & Voorregverhoging

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutbeloningsjagters te kommunikeer!

**Hack-insigte**\
Betrokkenheid by inhoud wat die opwinding en uitdagings van hack weergee

**Nuutste Hack-nuus**\
Bly op hoogte van die snelveranderende hackwêreld deur middel van nuus en insigte in werklikheid

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en noodsaaklike platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

## Basiese MacOS

As jy nie vertroud is met macOS nie, moet jy begin om die basiese van macOS te leer:

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
* Lêer wat binne 'n gids behoort aan root is, maar die gebruiker het skryftoegang daaroor weens 'n groep (die gebruiker kan die lêer skep)

Om 'n **lêer te skep** wat deur root gaan word **gebruik**, laat 'n gebruiker toe om van die inhoud daarvan te **profiteer** of selfs **simbole/harde skakels** te skep om dit na 'n ander plek te verwys.

Vir hierdie soort kwesbaarhede, moenie vergeet om kwesbare `.pkg`-installeerders te **kontroleer**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Lêeruitbreiding & URL-skema-toepassingshanteraars

Vreemde toepassings wat geregistreer is deur lêeruitbreidings kan misbruik word en verskillende toepassings kan geregistreer word om spesifieke protokolle te open

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Voorregverhoging

In macOS **kan aansoeke en bineêre lêers toestemmings** hê om toegang tot lêers of instellings te verkry wat hulle bevoorregter maak as ander.

Daarom sal 'n aanvaller wat 'n macOS-rekenaar suksesvol wil kompromiteer, sy TCC-voorregte moet **verhoog** (of selfs **SIP omseil**, afhangende van sy behoeftes).

Hierdie voorregte word gewoonlik gegee in die vorm van **toekennings** waarvoor die aansoek onderteken is, of die aansoek kan toegang tot sekere dinge versoek en nadat die **gebruiker dit goedgekeur het**, kan dit in die **TCC-databasisse** gevind word. 'n Ander manier waarop 'n proses hierdie voorregte kan verkry, is deur 'n **kind van 'n proses** met daardie **voorregte** te wees, aangesien hulle gewoonlik **oorervarings** is.

Volg hierdie skakels om verskillende maniere te vind om [**voorregte in TCC te verhoog**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), om **TCC te omseil**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) en hoe in die verlede [**SIP omseil is**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradisionele Voorregverhoging

Natuurlik moet jy as 'n rooi span ook belangstel om na root te verhoog. Kontroleer die volgende pos vir 'n paar wenke:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Verwysings

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutbeloningsjagters te kommunikeer!

**Hack-insigte**\
Gaan in gesprek met inhoud wat die opwinding en uitdagings van hack bekyk

**Hack Nuus in Werklikheid**\
Bly op hoogte van die snelveranderende hackwêreld deur werklikheidsnuus en insigte

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en kritieke platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

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
