# macOS Sisteemuitbreidings

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Sisteemuitbreidings / Eindpuntsekuriteitsraamwerk

In teenstelling met Kerneluitbreidings, **hardloop Sisteemuitbreidings in gebruikerspas** eerder as in die kernelpas, wat die risiko van 'n stelselbotsing as gevolg van uitbreidingsfoute verminder.

<figure><img src="../../../.gitbook/assets/image (603).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Daar is drie tipes sisteemuitbreidings: **DriverKit**-uitbreidings, **Netwerk**-uitbreidings, en **Eindpuntsekuriteit**-uitbreidings.

### **DriverKit-uitbreidings**

DriverKit is 'n vervanging vir kerneluitbreidings wat **hardwaresupport bied**. Dit maak dit moontlik vir toestuurprogramme (soos USB, Seriële, NIC, en HID-toestuurprogramme) om in gebruikerspas te hardloop eerder as in kernelpas. Die DriverKit-raamwerk sluit **gebruikerspasweergawes van sekere I/O Kit-klasse** in, en die kernel stuur normale I/O Kit-gebeure na gebruikerspas deur 'n veiliger omgewing vir hierdie toestuurprogramme te bied.

### **Netwerkuitbreidings**

Netwerkuitbreidings bied die vermoë om netwerkgedrag aan te pas. Daar is verskeie tipes Netwerkuitbreidings:

* **Toepassingsproksi**: Dit word gebruik om 'n VPN-kliënt te skep wat 'n vloeigeoriënteerde, aangepaste VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer op grond van verbindings (of vloeie) eerder as individuele pakkies.
* **Pakketspoorweg**: Dit word gebruik om 'n VPN-kliënt te skep wat 'n pakketgeoriënteerde, aangepaste VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer op grond van individuele pakkies.
* **Filterdata**: Dit word gebruik om netwerk "vloeie" te filter. Dit kan netwerkdata op vloeivlak monitor of wysig.
* **Filterpakkie**: Dit word gebruik om individuele netwerkpakkies te filter. Dit kan netwerkdata op pakkieveld monitor of wysig.
* **DNS-proksi**: Dit word gebruik om 'n aangepaste DNS-leweransier te skep. Dit kan gebruik word om DNS-versoeke en -antwoorde te monitor of wysig.

## Eindpuntsekuriteitsraamwerk

Eindpuntsekuriteit is 'n raamwerk wat deur Apple in macOS voorsien word en 'n stel API's vir stelselsekuriteit bied. Dit is bedoel vir gebruik deur **sekuriteitsvennote en ontwikkelaars om produkte te bou wat stelselaktiwiteit kan monitor en beheer** om skadelike aktiwiteit te identifiseer en teen te beskerm.

Hierdie raamwerk bied 'n **versameling API's om stelselaktiwiteit te monitor en te beheer**, soos prosesuitvoerings, lêersisteemgebeure, netwerk- en kerngebeure.

Die kern van hierdie raamwerk is geïmplementeer in die kernel, as 'n Kerneluitbreiding (KEXT) geleë by **`/System/Library/Extensions/EndpointSecurity.kext`**. Hierdie KEXT bestaan uit verskeie sleutelkomponente:

* **EndpointSecurityDriver**: Dit tree op as die "toegangspunt" vir die kerneluitbreiding. Dit is die hoofpunt van interaksie tussen die OS en die Eindpuntsekuriteitsraamwerk.
* **EndpointSecurityEventManager**: Hierdie komponent is verantwoordelik vir die implementering van kernelhake. Kernelhake maak dit moontlik vir die raamwerk om stelselgebeure te monitor deur stelseloproepe te onderskep.
* **EndpointSecurityClientManager**: Dit bestuur die kommunikasie met gebruikerspas-kliënte, hou by watter kliënte gekoppel is en gebeurteniskennisgewings moet ontvang.
* **EndpointSecurityMessageManager**: Dit stuur boodskappe en gebeurteniskennisgewings na gebruikerspas-kliënte.

Die gebeure wat die Eindpuntsekuriteitsraamwerk kan monitor, word gekategoriseer in:

* Lêergebeure
* Prosessgebeure
* Sokketgebeure
* Kerngebeure (soos die laai/ontlaai van 'n kerneluitbreiding of die oopmaak van 'n I/O Kit-toestel)

### Eindpuntsekuriteitsraamwerkargitektuur

<figure><img src="../../../.gitbook/assets/image (1065).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Gebruikerspas-kommunikasie** met die Eindpuntsekuriteitsraamwerk geskied deur die IOUserClient-klas. Twee verskillende subklasse word gebruik, afhangende van die tipe oproeper:

* **EndpointSecurityDriverClient**: Dit vereis die `com.apple.private.endpoint-security.manager` toestemming, wat slegs deur die stelselproses `endpointsecurityd` besit word.
* **EndpointSecurityExternalClient**: Dit vereis die `com.apple.developer.endpoint-security.client` toestemming. Dit sou tipies deur derdeparty-sekuriteitsagteware gebruik word wat met die Eindpuntsekuriteitsraamwerk moet interaksieer.

Die Eindpuntsekuriteitsuitbreidings:**`libEndpointSecurity.dylib`** is die C-biblioteek wat sisteemuitbreidings gebruik om met die kernel te kommunikeer. Hierdie biblioteek gebruik die I/O Kit (`IOKit`) om met die Eindpuntsekuriteits-KEXT te kommunikeer.

**`endpointsecurityd`** is 'n sleutelstelseldaemon wat betrokke is by die bestuur en aanvang van eindpuntsekuriteitstelseluitbreidings, veral gedurende die vroeë opstartproses. **Slegs sisteemuitbreidings** wat gemerk is met **`NSEndpointSecurityEarlyBoot`** in hul `Info.plist`-lêer ontvang hierdie vroeë opstartbehandeling.

'n Ander stelseldaemon, **`sysextd`**, **valideer sisteemuitbreidings** en skuif hulle na die regte stelsellokasies. Dit vra dan die betrokke daemon om die uitbreiding te laai. Die **`SystemExtensions.framework`** is verantwoordelik vir die aktivering en deaktivering van sisteemuitbreidings.

## ESF-verbygaan

ESF word deur sekuriteitsgereedskap gebruik wat sal probeer om 'n rooi span-lid op te spoor, dus enige inligting oor hoe dit vermy kan word, klink interessant.

### CVE-2021-30965

Die ding is dat die sekuriteitsaansoek **Volledige Skyftoegang-toestemmings** moet hê. As 'n aanvaller dit kon verwyder, kon hy voorkom dat die sagteware hardloop:
```bash
tccutil reset All
```
Vir **meer inligting** oor hierdie omweg en verwante omwegte, kyk na die aanbieding [#OBTS v5.0: "Die Achilleshiel van Eindpuntbeveiliging" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Aan die einde is hierdie probleem opgelos deur die nuwe toestemming **`kTCCServiceEndpointSecurityClient`** te gee aan die beveiligingsprogram wat bestuur word deur **`tccd`** sodat `tccutil` nie sy toestemmings sal skoonmaak nie en dit verhoed om uit te voer.

## Verwysings

* [**OBTS v3.0: "Eindpuntbeveiliging & Onveiligheid" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
