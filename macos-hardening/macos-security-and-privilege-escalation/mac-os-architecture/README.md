# macOS Kernel & Sisteemuitbreidings

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## XNU Kernel

Die **kern van macOS is XNU**, wat staan vir "X is Not Unix". Hierdie kernel bestaan fundamenteel uit die **Mach mikrokernel** (wat later bespreek sal word), **en** elemente van Berkeley Software Distribution (**BSD**). XNU bied ook 'n platform vir **kernbestuurders deur 'n stelsel genaamd die I/O Kit**. Die XNU-kernel is deel van die Darwin oopbronprojek, wat beteken **sy bronkode is vrylik toeganklik**.

Vanuit die oogpunt van 'n sekuriteitsnavorsers of 'n Unix-ontwikkelaar, **kan macOS** redelik **soortgelyk voel** aan 'n **FreeBSD**-sisteem met 'n elegante GUI en 'n verskeidenheid aangepaste toepassings. Die meeste toepassings wat vir BSD ontwikkel is, sal op macOS kompileer en loop sonder dat aanpassings nodig is, aangesien die opdraglynwerktuie wat bekend is aan Unix-gebruikers almal teenwoordig is in macOS. Tog, omdat die XNU-kernel Mach inkorporeer, is daar enkele beduidende verskille tussen 'n tradisionele Unix-soortgelyke stelsel en macOS, en hierdie verskille kan potensiële probleme veroorsaak of unieke voordele bied.

Oopbronweergawe van XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is 'n **mikrokernel** wat ontwerp is om **UNIX-kompatibel** te wees. Een van sy sleutelontwerpbeginsels was om die hoeveelheid **kode** wat in die **kern**-ruimte hardloop, te **minimeer** en eerder baie tipiese kernfunksies, soos lêersisteem, netwerke, en I/O, toe te laat om as gebruikersvlaktake te **hardloop**.

In XNU is Mach **verantwoordelik vir baie van die kritieke laevlak-operasies** wat 'n kernel tipies hanteer, soos prosessorbeplanning, multitasking, en virtuele geheuebestuur.

### BSD

Die XNU **kernel** inkorporeer ook 'n aansienlike hoeveelheid kode wat afgelei is van die **FreeBSD**-projek. Hierdie kode **hardloop as deel van die kernel saam met Mach**, in dieselfde adresruimte. Nietemin, die FreeBSD-kode binne XNU kan aansienlik verskil van die oorspronklike FreeBSD-kode omdat aanpassings nodig was om sy verenigbaarheid met Mach te verseker. FreeBSD dra by tot baie kernoperasies insluitend:

* Prosesbestuur
* Seinhantering
* Basiese sekuriteitsmeganismes, insluitend gebruiker- en groepbestuur
* Stelseloproep-infrastruktuur
* TCP/IP-stapel en sokkels
* Vuurwal en pakkiefiltrasie

Die begrip van die interaksie tussen BSD en Mach kan kompleks wees, as gevolg van hul verskillende konseptuele raamwerke. Byvoorbeeld, BSD gebruik prosesse as sy fundamentele uitvoerende eenheid, terwyl Mach op drade gebaseer is. Hierdie teenstrydigheid word in XNU versoen deur **elke BSD-proses te assosieer met 'n Mach-taak** wat presies een Mach-draad bevat. Wanneer BSD se fork()-stelseloproep gebruik word, gebruik die BSD-kode binne die kernel Mach-funksies om 'n taak- en 'n draadstruktuur te skep.

Verder **handhaaf Mach en BSD elk 'n verskillende sekuriteitsmodel**: **Mach se** sekuriteitsmodel is gebaseer op **poortregte**, terwyl BSD se sekuriteitsmodel opereer op grond van **proses-eienaarskap**. Verskille tussen hierdie twee modelle het soms gelei tot plaaslike voorreg-escalasie-kwesbaarhede. Afgesien van tipiese stelseloproepe, is daar ook **Mach-valle wat gebruikersruimteprogramme toelaat om met die kernel te interaksieer**. Hierdie verskillende elemente vorm saam die veelsydige, hibriede argitektuur van die macOS-kernel.

### I/O Kit - Bestuurders

Die I/O Kit is 'n oopbron, objekgeoriënteerde **toestelbestuurder-raamwerk** in die XNU-kernel, wat **dinamies gelaaide toestelbestuurders** hanteer. Dit maak dit moontlik om modulêre kode op die vlieg by die kernel te voeg, wat 'n verskeidenheid hardeware ondersteun.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Interproseskommunikasie

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Die **kernelcache** is 'n **vooraf saamgestelde en vooraf gekoppelde weergawe van die XNU-kernel**, saam met noodsaaklike toestel **bestuurders** en **kernuitbreidings**. Dit word in 'n **gekomprimeerde** formaat gestoor en word tydens die opstartproses in die geheue gedekomprimeer. Die kernelcache fasiliteer 'n **vinniger opstartsproses** deur 'n gereed-om-te-loop weergawe van die kernel en kritieke bestuurders beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins aan die dinamies laai en koppel van hierdie komponente tydens opstarttyd bestee sou word.

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kan jy dit vind met **`find / -name kernelcache 2>/dev/null`** of **`mdfind kernelcache | grep kernelcache`**

Dit is moontlik om **`kextstat`** uit te voer om die gelaai kernuitbreidings te kontroleer.

#### IMG4

Die IMG4-lêerformaat is 'n houerformaat wat deur Apple in sy iOS- en macOS-toestelle gebruik word vir die veilige **berg en verifieer van firmware**-komponente (soos **kernelcache**). Die IMG4-formaat sluit 'n kopstuk en verskeie etikette in wat verskillende stukke data insluit, insluitend die werklike vrag (soos 'n kernel of beginlaaiers), 'n handtekening, en 'n stel manifesteienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel in staat stel om die egtheid en integriteit van die firmware-komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

* **Pakket (IM4P)**:
* Dikwels saamgedruk (LZFSE4, LZSS, …)
* Opsioneel versleutel
* **Manifest (IM4M)**:
* Bevat Handtekening
* Addisionele Sleutel/Waarde-woordeboek
* **Herstel Inligting (IM4R)**:
* Ook bekend as APNonce
* Voorkom herhaal van sommige opdaterings
* FAKULTATIEF: Gewoonlik word dit nie gevind nie

Dekomprimeer die Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Kernelcache Simbole

Soms publiseer Apple **kernelcache** met **simbole**. Jy kan sommige firmwares met simbole aflaai deur die skakels op [https://theapplewiki.com](https://theapplewiki.com/) te volg.

### IPSW

Dit is Apple **firmwares** wat jy kan aflaai vanaf [**https://ipsw.me/**](https://ipsw.me/). Onder andere lêers bevat dit die **kernelcache**.\
Om die lêers te **onttrek**, kan jy dit net **ontzip**.

Nadat die firmware onttrek is, sal jy 'n lêer soos hierdie kry: **`kernelcache.release.iphone14`**. Dit is in **IMG4**-formaat, jy kan die interessante inligting onttrek met:

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

Met hierdie kan ons nou **alle uitbreidings** of die **een waarin jy belangstel, onttrek:**
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
## macOS Kernel-uitbreidings

macOS is **baie beperkend om Kernel-uitbreidings** (.kext) te laai vanweë die hoë voorregte waarmee kode sal hardloop. Eintlik is dit by verstek feitlik onmoontlik (tensy 'n omweg gevind word).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS-stelseluitbreidings

In plaas daarvan om Kernel-uitbreidings te gebruik, het macOS die Stelseluitbreidings geskep, wat in gebruikersvlak-API's bied om met die kernel te kommunikeer. Op hierdie manier kan ontwikkelaars vermy om kernel-uitbreidings te gebruik.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Verwysings

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
