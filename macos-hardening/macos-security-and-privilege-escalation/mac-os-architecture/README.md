# macOS Kernel & Sisteemuitbreidings

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## XNU Kernel

Die **kern van macOS is XNU**, wat staan vir "X is Not Unix". Hierdie kernel is fundamenteel saamgestel uit die **Mach mikrokernel** (wat later bespreek sal word), **en** elemente van die Berkeley Software Distribution (**BSD**). XNU bied ook 'n platform vir **kernbestuurders deur 'n stelsel genaamd die I/O Kit**. Die XNU-kernel is deel van die Darwin oopbronprojek, wat beteken **sy bronkode is vrylik toeganklik**.

Vanuit die oogpunt van 'n sekuriteitsnavorsers of 'n Unix-ontwikkelaar, **kan macOS** redelik **soortgelyk voel** aan 'n **FreeBSD**-sisteem met 'n elegante GUI en 'n verskeidenheid aangepaste toepassings. Die meeste toepassings wat vir BSD ontwikkel is, sal op macOS kompileer en loop sonder om wysigings nodig te hê, aangesien die opdraglyn-hulpmiddels wat bekend is aan Unix-gebruikers almal teenwoordig is in macOS. Tog, omdat die XNU-kernel Mach inkorporeer, is daar 'n paar beduidende verskille tussen 'n tradisionele Unix-soortgelyke stelsel en macOS, en hierdie verskille kan potensiële probleme veroorsaak of unieke voordele bied.

Oopbronweergawe van XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is 'n **mikrokernel** wat ontwerp is om **UNIX-kompatibel** te wees. Een van sy sleutelontwerpbeginsels was om die hoeveelheid **kode** wat in die **kern**-ruimte hardloop, te **minimeer** en eerder baie tipiese kernfunksies, soos lêersisteem, netwerke, en I/O, toe te laat om **as gebruikersvlaktake te hardloop**.

In XNU is Mach **verantwoordelik vir baie van die kritieke laevlak-operasies** wat 'n kernel tipies hanteer, soos prosessorbeplanning, multitasking, en virtuele geheuebestuur.

### BSD

Die XNU **kernel** inkorporeer ook 'n aansienlike hoeveelheid kode wat afgelei is van die **FreeBSD**-projek. Hierdie kode **hardloop as deel van die kernel saam met Mach**, in dieselfde adresruimte. Nietemin, die FreeBSD-kode binne XNU kan aansienlik verskil van die oorspronklike FreeBSD-kode omdat wysigings nodig was om sy verenigbaarheid met Mach te verseker. FreeBSD dra by tot baie kernoperasies insluitend:

* Prosesbestuur
* Seinhantering
* Basiese sekuriteitsmeganismes, insluitend gebruiker- en groepbestuur
* Stelseloproep-infrastruktuur
* TCP/IP-stapel en sokkels
* Brandmuur en pakkiefiltrasie

Die begrip van die interaksie tussen BSD en Mach kan kompleks wees, as gevolg van hul verskillende konseptuele raamwerke. Byvoorbeeld, BSD gebruik prosesse as sy fundamentele uitvoerenheid, terwyl Mach op drade gebaseer is. Hierdie teenstrydigheid word in XNU versoen deur **elke BSD-proses te assosieer met 'n Mach-taak** wat presies een Mach-draad bevat. Wanneer BSD se fork()-stelseloproep gebruik word, gebruik die BSD-kode binne die kernel Mach-funksies om 'n taak- en 'n draadstruktuur te skep.

Verder **handhaaf Mach en BSD elk 'n verskillende sekuriteitsmodel**: **Mach se** sekuriteitsmodel is gebaseer op **poortregte**, terwyl BSD se sekuriteitsmodel opereer op grond van **proses-eienaarskap**. Verskille tussen hierdie twee modelle het soms gelei tot plaaslike voorreg-escalatie-kwesbaarhede. Afgesien van tipiese stelseloproepe, is daar ook **Mach-valle wat gebruikersruimteprogramme toelaat om met die kernel te interaksieer**. Hierdie verskillende elemente vorm saam die veelsydige, hibriede argitektuur van die macOS-kernel.

### I/O Kit - Bestuurders

Die I/O Kit is 'n oopbron-, objekgeoriënteerde **toestelbestuurder-raamwerk** in die XNU-kernel, hanteer **dinamies gelaaide toestelbestuurders**. Dit maak dit moontlik om modulêre kode by die kernel by te voeg terwyl dit loop, wat 'n verskeidenheid hardeware ondersteun.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Interproseskommunikasie

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Die **kernelcache** is 'n **vooraf saamgestelde en vooraf gekoppelde weergawe van die XNU-kernel**, saam met noodsaaklike toestel **bestuurders** en **kernuitbreidings**. Dit word in 'n **gekomprimeerde** formaat gestoor en word tydens die opstartproses in die geheue gedekomprimeer. Die kernelcache fasiliteer 'n **vinniger opstarttyd** deur 'n gereed-om-te-loop weergawe van die kernel en kritieke bestuurders beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins aan die dinamies laai en koppel van hierdie komponente tydens opstarttyd bestee sou word.

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kan jy dit vind met **`find / -name kernelcache 2>/dev/null`** of **`mdfind kernelcache | grep kernelcache`**

Dit is moontlik om **`kextstat`** uit te voer om die gelaai kernuitbreidings te kontroleer.

#### IMG4

Die IMG4-lêerformaat is 'n houerformaat wat deur Apple in sy iOS- en macOS-toestelle gebruik word om firmware-komponente (soos **kernelcache**) veilig **te stoor en te verifieer**. Die IMG4-formaat sluit 'n kopstuk en verskeie etikette in wat verskillende stukke data insluit, insluitend die werklike vrag (soos 'n kernel of aansitter), 'n handtekening, en 'n stel manifesteienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel in staat stel om die egtheid en integriteit van die firmware-komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

* **Pakket (IM4P)**:
* Dikwels saamgedruk (LZFSE4, LZSS, …)
* Opsioneel versleutel
* **Manifest (IM4M)**:
* Bevat Handtekening
* Addisionele Sleutel/Waarde-woordeboek
* **Herstel-inligting (IM4R)**:
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

Soms publiseer Apple **kernelcache** met **simbole**. Jy kan sommige firmwares met simbole aflaai deur die skakels te volg op [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Dit is Apple **firmwares** wat jy kan aflaai vanaf [**https://ipsw.me/**](https://ipsw.me/). Onder andere lêers bevat dit die **kernelcache**.\
Om die lêers te **onttrek** kan jy dit net **ontzip**.

Na die onttrekking van die firmware sal jy 'n lêer soos hierdie kry: **`kernelcache.release.iphone14`**. Dit is in **IMG4**-formaat, jy kan die interessante inligting onttrek met:

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

Hiermee kan ons nou **alle uitbreidings** uithaal of die **een waarin jy belangstel:**
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
## macOS Kernel Uitbreidings

macOS is **baie beperkend om Kernel Uitbreidings** (.kext) te laai vanweë die hoë voorregte waarmee kode sal hardloop. Eintlik is dit by verstek feitlik onmoontlik (tensy 'n omweg gevind word).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS Stelsel Uitbreidings

In plaas daarvan om Kernel Uitbreidings te gebruik, het macOS die Stelsel Uitbreidings geskep, wat in gebruikersvlak-API's bied om met die kernel te kommunikeer. Op hierdie manier kan ontwikkelaars vermy om kernel-uitbreidings te gebruik.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Verwysings

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslaan.

</details>
{% endhint %}
