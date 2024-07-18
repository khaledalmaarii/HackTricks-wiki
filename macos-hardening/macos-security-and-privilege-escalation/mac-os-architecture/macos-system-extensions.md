# macOS Sisteemuitbreidings

{% hint style="success" %}
Leer en oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegramgroep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
{% endhint %}

## Sisteemuitbreidings / Eindpuntbeveiligingsraamwerk

In teenstelling met Kerneluitbreidings, **loop Sisteemuitbreidings in gebruikersruimte** in plaas van kernelruimte, wat die risiko van 'n stelselbotsing as gevolg van uitbreidingsfoute verminder.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Daar is drie tipes sisteemuitbreidings: **DriverKit**-uitbreidings, **Netwerk**-uitbreidings, en **Eindpuntbeveiliging**-uitbreidings.

### **DriverKit-uitbreidings**

DriverKit is 'n vervanging vir kerneluitbreidings wat **hardwaresondersteuning bied**. Dit maak dit moontlik vir toestuurprogramme (soos USB, Seriële, NIC, en HID-toestuurprogramme) om in gebruikersruimte te hardloop eerder as in kernelruimte. Die DriverKit-raamwerk sluit **gebruikersruimte-weergawes van sekere I/O Kit-klasse** in, en die kernel stuur normale I/O Kit-gebeure na gebruikersruimte, wat 'n veiliger omgewing bied vir hierdie toestuurprogramme om te hardloop.

### **Netwerkuitbreidings**

Netwerkuitbreidings bied die vermoë om netwerkgedrag aan te pas. Daar is verskeie tipes Netwerkuitbreidings:

* **Toepassingsproksi**: Dit word gebruik om 'n VPN-kliënt te skep wat 'n vloeigeoriënteerde, aangepaste VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer op grond van verbindings (of vloeie) eerder as individuele pakkette.
* **Pakketspoor**: Dit word gebruik om 'n VPN-kliënt te skep wat 'n pakketgeoriënteerde, aangepaste VPN-protokol implementeer. Dit beteken dit hanteer netwerkverkeer op grond van individuele pakkette.
* **Filterdata**: Dit word gebruik om netwerk "vloeie" te filter. Dit kan netwerkdata op vloeivlak monitor of wysig.
* **Filterpakkette**: Dit word gebruik om individuele netwerkpakkette te filter. Dit kan netwerkdata op pakketvlak monitor of wysig.
* **DNS-proksi**: Dit word gebruik om 'n aangepaste DNS-lewerancier te skep. Dit kan gebruik word om DNS-versoeke en -antwoorde te monitor of wysig.

## Eindpuntbeveiligingsraamwerk

Eindpuntbeveiliging is 'n raamwerk wat deur Apple in macOS voorsien word en 'n stel API's vir stelselsekuriteit bied. Dit is bedoel vir gebruik deur **sekuriteitsvennote en ontwikkelaars om produkte te bou wat stelselaktiwiteit kan monitor en beheer** om skadelike aktiwiteit te identifiseer en teen te beskerm.

Hierdie raamwerk bied 'n **versameling API's om stelselaktiwiteit te monitor en te beheer**, soos prosesuitvoerings, lêersisteemgebeure, netwerk- en kernelgebeure.

Die kern van hierdie raamwerk word geïmplementeer in die kernel, as 'n Kerneluitbreiding (KEXT) geleë by **`/System/Library/Extensions/EndpointSecurity.kext`**. Hierdie KEXT bestaan uit verskeie sleutelkomponente:

* **EndpointSecurityDriver**: Dit tree op as die "ingangspunt" vir die kerneluitbreiding. Dit is die hoofpunt van interaksie tussen die OS en die Eindpuntbeveiligingsraamwerk.
* **EndpointSecurityEventManager**: Hierdie komponent is verantwoordelik vir die implementering van kernelhake. Kernelhake maak dit moontlik vir die raamwerk om stelselgebeure te monitor deur stelseloproepe te onderskep.
* **EndpointSecurityClientManager**: Dit bestuur die kommunikasie met gebruikersruimtekliënte, hou by watter kliënte gekoppel is en kennis moet neem van gebeurteniskennisgewings.
* **EndpointSecurityMessageManager**: Dit stuur boodskappe en gebeurteniskennisgewings na gebruikersruimtekliënte.

Die gebeure wat die Eindpuntbeveiligingsraamwerk kan monitor word gekategoriseer in:

* Lêergebeure
* Prosessgebeure
* Sokketgebeure
* Kernelgebeure (soos die laai/ontlaai van 'n kerneluitbreiding of die oopmaak van 'n I/O Kit-toestel)

### Eindpuntbeveiligingsraamwerkargitektuur

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Gebruikersruimte kommunikasie** met die Eindpuntbeveiligingsraamwerk gebeur deur die IOUserClient-klas. Twee verskillende subklasse word gebruik, afhangende van die tipe oproeper:

* **EndpointSecurityDriverClient**: Dit vereis die `com.apple.private.endpoint-security.manager` toestemming, wat slegs deur die stelselproses `endpointsecurityd` gehou word.
* **EndpointSecurityExternalClient**: Dit vereis die `com.apple.developer.endpoint-security.client` toestemming. Dit sou tipies gebruik word deur derdeparty-sekuriteitsagteware wat met die Eindpuntbeveiligingsraamwerk moet interaksie hê.

Die Eindpuntbeveiligingsuitbreidings:**`libEndpointSecurity.dylib`** is die C-biblioteek wat sisteemuitbreidings gebruik om met die kernel te kommunikeer. Hierdie biblioteek gebruik die I/O Kit (`IOKit`) om met die Eindpuntbeveiligings-KEXT te kommunikeer.

**`endpointsecurityd`** is 'n sleutelstelseldaemon wat betrokke is by die bestuur en aan die gang sit van eindpuntbeveiligingstelseluitbreidings, veral gedurende die vroeë opstartproses. **Slegs sisteemuitbreidings** gemerk met **`NSEndpointSecurityEarlyBoot`** in hul `Info.plist`-lêer ontvang hierdie vroeë opstartbehandeling.

'n Ander stelseldaemon, **`sysextd`**, **valideer sisteemuitbreidings** en skuif hulle na die regte stelsellokasies. Dit vra dan die relevante daemon om die uitbreiding te laai. Die **`SystemExtensions.framework`** is verantwoordelik vir die aktivering en deaktivering van sisteemuitbreidings.

## Omskep ESF

ESF word deur sekuriteitsgereedskap gebruik wat sal probeer om 'n rooi span-lid op te spoor, dus enige inligting oor hoe dit vermy kan word, klink interessant.

### CVE-2021-30965

Die ding is dat die sekuriteitsaansoek **Volle Skyf Toegang-toestemmings** moet hê. Dus as 'n aanvaller dit kon verwyder, kon hy voorkom dat die sagteware hardloop:
```bash
tccutil reset All
```
Vir **meer inligting** oor hierdie omweg en verwante omwegte, kyk na die aanbieding [#OBTS v5.0: "Die Achilleshiel van Eindpuntbeveiliging" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Aan die einde is hierdie probleem opgelos deur die nuwe toestemming **`kTCCServiceEndpointSecurityClient`** te gee aan die beveiligingsprogram wat bestuur word deur **`tccd`** sodat `tccutil` nie sy toestemmings sal skoonmaak nie en dit verhoed om uit te voer.

## Verwysings

* [**OBTS v3.0: "Eindpuntbeveiliging & Onveiligheid" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
