# macOS Kernel & Stelseluitbreidings

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## XNU Kernel

Die **kern van macOS is XNU**, wat staan vir "X is Not Unix". Hierdie kern bestaan ​​hoofsaaklik uit die **Mach-mikrokern** (wat later bespreek sal word), **en** elemente van die Berkeley Software Distribution (**BSD**). XNU bied ook 'n platform vir **kernbestuurders deur 'n stelsel genaamd die I/O Kit**. Die XNU-kern is deel van die Darwin oopbronprojek, wat beteken dat **sy bronkode vrylik toeganklik is**.

Vanuit die oogpunt van 'n sekuriteitsnavorsers of 'n Unix-ontwikkelaar, kan **macOS** redelik **soortgelyk** voel aan 'n **FreeBSD**-sisteem met 'n elegante GUI en 'n verskeidenheid aangepaste toepassings. Die meeste toepassings wat vir BSD ontwikkel is, sal op macOS kompilasie en uitvoering sonder om wysigings nodig te hê, aangesien die opdraggelynhulpmiddels wat bekend is aan Unix-gebruikers almal teenwoordig is in macOS. Tog, omdat die XNU-kern Mach inkorporeer, is daar 'n paar belangrike verskille tussen 'n tradisionele Unix-soortgelyke stelsel en macOS, en hierdie verskille kan potensiële probleme veroorsaak of unieke voordele bied.

Oopbronweergawe van XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is 'n **mikrokern** wat ontwerp is om **UNIX-verenigbaar** te wees. Een van sy sleutelontwerpbeginsels was om die hoeveelheid **kode** wat in die **kern**-ruimte uitgevoer word, te **minimeer** en eerder baie tipiese kernfunksies, soos lêersisteem, netwerk en I/O, as **gebruikervlak-take** te laat uitvoer.

In XNU is Mach **verantwoordelik vir baie van die kritieke lae-vlak-operasies** wat 'n kern tipies hanteer, soos prosessorbeplanning, multitasking en virtuele geheuebestuur.

### BSD

Die XNU **kern** inkorporeer ook 'n aansienlike hoeveelheid kode wat afgelei is van die **FreeBSD**-projek. Hierdie kode **loop as deel van die kern saam met Mach** in dieselfde adresruimte. Die FreeBSD-kode binne XNU kan egter aansienlik verskil van die oorspronklike FreeBSD-kode omdat wysigings nodig was om die verenigbaarheid met Mach te verseker. FreeBSD dra by tot baie kernoperasies, insluitend:

* Prosesbestuur
* Seinhantering
* Basiese sekuriteitsmeganismes, insluitend gebruiker- en groepbestuur
* Stelseloproep-infrastruktuur
* TCP/IP-stapel en sokkels
* Brandmuur en pakkiefiltering

Die begrip van die interaksie tussen BSD en Mach kan kompleks wees as gevolg van hul verskillende konseptuele raamwerke. Byvoorbeeld, BSD gebruik prosesse as sy fundamentele uitvoerende eenheid, terwyl Mach op drade gebaseer is. Hierdie teenstrydigheid word in XNU verreken deur **elke BSD-proses te koppel aan 'n Mach-taak** wat presies een Mach-draad bevat. Wanneer BSD se fork()-stelseloproep gebruik word, gebruik die BSD-kode binne die kern Mach-funksies om 'n taak- en draadstruktuur te skep.

Verder **handhaaf Mach en BSD elk 'n ander sekuriteitsmodel**: **Mach se** sekuriteitsmodel is gebaseer op **poortregte**, terwyl BSD se sekuriteitsmodel gebaseer is op **proses-eienaarskap**. Verskille tussen hierdie twee modelle het soms gelei tot plaaslike voorreg-escalatiekwesbaarhede. Afgesien van tipiese stelseloproepe, is daar ook **Mach-valstrikke wat gebruikersruimteprogramme in staat stel om met die kern te kommunikeer**. Hierdie verskillende elemente vorm saam die veelsydige, hibriede argitektuur van die macOS-kern.

### I/O Kit - Bestuurders

Die I/O Kit is 'n oopbron, objekgeoriënteerde **toestelbestuurder-raamwerk** in die XNU-kern, wat **dinamies gelaai toestelbestuurders** hanteer. Dit maak dit moontlik om modulêre kode op die vlieg by die kern te voeg, wat diverse hardeware ondersteun.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Interproseskommunikasie

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Die **kernelcache** is 'n **vooraf gekompileerde en vooraf gekoppelde weergawe van die XNU-kern**, tesame met noodsaaklike toestel-**bestuurders** en **kernuitbreidings**. Dit word in 'n **gekomprimeerde** formaat gestoor en word tydens die opstartproses in die geheue gedekomprimeer. Die kernelcache fasiliteer 'n **vinniger opstarttyd** deur 'n gereed-om-uitgevoerde weergawe van die kern en belangrike bestuurders beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins sou word spandeer op die dinamiese laai en koppeling van hierdie komponente tydens die opstartproses.

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kan jy dit vind met **`find / -name kernelcache 2>/dev/null`**

#### IMG4

Die IMG4-lêerformaat is 'n houerformaat wat deur Apple in sy iOS- en macOS-toestelle gebruik word om firmware-komponente (soos **kernelcache**) veilig te **stoor en te verifieer**. Die IMG4-formaat sluit 'n kop en verskeie etikette in wat verskillende stukke data insluit, insluitend die werklike nutslading (soos 'n kern of opstartlader), 'n handtekening en 'n stel manifesteienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel in staat stel om die egtheid en integriteit van die firmware-komponent te bevestig voordat dit uitgevoer word.

Dit bestaan ​​gewoonlik uit die volgende komponente:

* **Nutslading (IM4P)**:
* Dikwels saamgedruk (LZFSE4, LZSS, ...)
* Opsioneel versleutel
* **Manifest (IM4M)**:
* Bevat handtekening
* Addisionele Sleutel/Waarde-woordeboek
* **Herstelinfo (IM4R)**:
* Ook bekend as APNonce
* Voorkom dat sekere opdaterings herhaal word
* OPSIONEEL: Gewoonlik word dit nie gevind nie

Dekomprimeer die Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Kernelcache Simbole

Soms versprei Apple **kernelcache** met **simbole**. Jy kan sommige firmwares met simbole aflaai deur die skakels op [https://theapplewiki.com](https://theapplewiki.com/) te volg.

### IPSW

Dit is Apple **firmwares** wat jy kan aflaai vanaf [**https://ipsw.me/**](https://ipsw.me/). Onder andere lêers bevat dit die **kernelcache**.\
Om die lêers uit te pak, kan jy dit net **onttrek**.

Nadat jy die firmware uitgepak het, sal jy 'n lêer soos hierdie kry: **`kernelcache.release.iphone14`**. Dit is in **IMG4**-formaat, jy kan die interessante inligting uittrek met:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Jy kan die uitgepakte kernelcache vir simbole nagaan met: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Met hierdie kan ons nou **alle uitbreidings onttrek** of die **een waarin jy belangstel:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS Kerneluitbreidings

macOS is **baie beperkend om Kerneluitbreidings** (.kext) te laai as gevolg van die hoë bevoegdhede waarmee kode sal loop. In werklikheid is dit by verstek feitlik onmoontlik (behalwe as 'n omweg gevind word).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS-stelseluitbreidings

In plaas daarvan om Kerneluitbreidings te gebruik, het macOS die Stelseluitbreidings geskep, wat gebruikersvlak-API's bied om met die kernel te kommunikeer. Op hierdie manier kan ontwikkelaars voorkom om kerneluitbreidings te gebruik.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Verwysings

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
