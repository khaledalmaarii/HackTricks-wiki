# macOS Stelseluitbreidings

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Stelseluitbreidings / Eindpuntsekuriteitsraamwerk

In teenstelling met Kernel-uitbreidings, **loop stelseluitbreidings in gebruikersruimte** in plaas van die kernruimte, wat die risiko van 'n stelselcrash as gevolg van uitbreidingsfoute verminder.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Daar is drie tipes stelseluitbreidings: **DriverKit**-uitbreidings, **Netwerk**-uitbreidings en **Eindpuntsekuriteit**-uitbreidings.

### **DriverKit-uitbreidings**

DriverKit is 'n vervanging vir kernuitbreidings wat **hardwaresondersteuning bied**. Dit maak dit moontlik dat toestuurprogramme (soos USB-, Seriële-, NIC- en HID-toestuurprogramme) in gebruikersruimte in plaas van kernruimte loop. Die DriverKit-raamwerk sluit **gebruikersruimte-weergawes van sekere I/O Kit-klasse** in, en die kern stuur normale I/O Kit-gebeure na gebruikersruimte, wat 'n veiliger omgewing bied vir hierdie toestuurprogramme om in te loop.

### **Netwerkuitbreidings**

Netwerkuitbreidings bied die vermoë om netwerkgedrag aan te pas. Daar is verskeie tipes netwerkuitbreidings:

* **App Proxy**: Dit word gebruik om 'n VPN-kliënt te skep wat 'n vloeigeoriënteerde, aangepaste VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer op grond van verbindings (of vloeie) eerder as individuele pakkies.
* **Pakkettunnel**: Dit word gebruik om 'n VPN-kliënt te skep wat 'n pakketgeoriënteerde, aangepaste VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer op grond van individuele pakkies.
* **Filterdata**: Dit word gebruik om netwerk "vloeie" te filter. Dit kan netwerkdata op vloeivlak monitor of wysig.
* **Filterpakkie**: Dit word gebruik om individuele netwerkpakkies te filter. Dit kan netwerkdata op pakkievlak monitor of wysig.
* **DNS Proxy**: Dit word gebruik om 'n aangepaste DNS-verskaffer te skep. Dit kan gebruik word om DNS-versoeke en -antwoorde te monitor of wysig.

## Eindpuntsekuriteitsraamwerk

Eindpuntsekuriteit is 'n raamwerk wat deur Apple in macOS voorsien word en 'n stel API's bied vir stelselsekuriteit. Dit is bedoel vir gebruik deur **sekuriteitsvennote en ontwikkelaars om produkte te bou wat stelselaktiwiteit kan monitor en beheer** om kwaadwillige aktiwiteit te identifiseer en te beskerm daarteen.

Hierdie raamwerk bied 'n **versameling API's om stelselaktiwiteit te monitor en te beheer**, soos prosesuitvoerings, lêersisteemgebeure, netwerk- en kerngebeure.

Die kern van hierdie raamwerk word geïmplementeer in die kern as 'n Kernel-uitbreiding (KEXT) wat geleë is by **`/System/Library/Extensions/EndpointSecurity.kext`**. Hierdie KEXT bestaan uit verskeie sleutelkomponente:

* **EndpointSecurityDriver**: Dit tree op as die "toegangspunt" vir die kernuitbreiding. Dit is die hoofpunt van interaksie tussen die bedryfstelsel en die Eindpuntsekuriteitsraamwerk.
* **EndpointSecurityEventManager**: Hierdie komponent is verantwoordelik vir die implementering van kernhake. Kernhake maak dit moontlik vir die raamwerk om stelselgebeure te monitor deur stelseloproepe te onderskep.
* **EndpointSecurityClientManager**: Dit bestuur die kommunikasie met kliënte in gebruikersruimte, hou by watter kliënte gekoppel is en kennis moet neem van gebeurteniskennisgewings.
* **EndpointSecurityMessageManager**: Dit stuur boodskappe en gebeurteniskennisgewings na kliënte in gebruikersruimte.

Die gebeure wat die Eindpuntsekuriteitsraamwerk kan monitor, word gekategoriseer as:

* Lêergebeure
* Prosessgebeure
* Sokketgebeure
* Kerngebeure (soos die laai/ontlaai van 'n kernuitbreiding of die oopmaak van 'n I/O Kit-toestel)

### Eindpuntsekuriteitsraamwerkargitektuur

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Kommunikasie in gebruikersruimte** met die Eindpuntsekuriteitsraamwerk vind plaas deur die IOUserClient-klas. Twee verskillende subklasse word gebruik, afhangende van die tipe oproeper:

* **EndpointSecurityDriverClient**: Dit vereis die `com.apple.private.endpoint-security.manager`-bevoegdheid, wat slegs deur die stelselproses `endpointsecurityd` besit word.
* **EndpointSecurityExternalClient**: Dit vereis die `com.apple.developer.endpoint-security.client`-bevoegdheid. Dit word tipies deur derdeparty-sekuriteitsagteware gebruik wat met die Eindpuntsekuriteitsraamwerk moet kommunikeer.

Die Eindpuntsekuriteitsuitbreidings:**`libEndpointSecurity.dylib`** is die C-biblioteek wat stelseluitbreidings gebruik om met die kern te kommunikeer. Hierdie biblioteek gebruik die I/O Kit (`IOKit`) om met die Eindpuntsekuriteits-KEXT te kommunikeer.

**`endpointsecurityd`** is 'n belangrike stelseldaemon wat betrokke is by die bestuur en aanstuur van eindpuntsekuriteitstelseluitbreidings, veral gedurende die vroeë opstartproses. Slegs stelseluitbreidings wat in hul `Info.plist`-lêer gemerk is met **`NSEndpointSecurityEarlyBoot`** ontvang hierdie vroeë opstartbehandeling.

'n Ander stelseldaemon, **`sysextd`**, **valideer stelseluitbreidings** en skuif hulle na die korrekte stelselposisies. Dit vra dan die relevante daemon om die uitbreiding te laai. Die **`SystemExtensions.framework`** is verantwoordelik vir die aktivering en deaktivering van stelseluitbreidings.

## Om ESF te omseil

ESF word deur sekuriteitsgereedskap gebruik wat sal probeer om 'n rooi-spanlid op te spoor, dus enige inligting oor hoe dit vermy kan word, klink interessant.

### CVE-2021-30965

Die ding is dat die sekuriteitsprogram **Volle Skyskryftoegang-bevoegdhede** moet hê. As 'n aanvaller dit kan verwyder, kan hy voorkom dat die sagteware loop:
```bash
tccutil reset All
```
Vir **meer inligting** oor hierdie omseiling en verwante omseilings, kyk na die praatjie [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Aan die einde is dit reggestel deur die nuwe toestemming **`kTCCServiceEndpointSecurityClient`** aan die sekuriteitsprogram wat deur **`tccd`** bestuur word te gee, sodat `tccutil` nie sy toestemmings sal skoonmaak en dit sal verhoed om uit te voer nie.

## Verwysings

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
