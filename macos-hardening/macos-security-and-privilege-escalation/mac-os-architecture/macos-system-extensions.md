# Vifaa vya Mfumo wa macOS

{% hint style="success" %}
Jifunze & zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Vifaa vya Mfumo / Fremu ya Usalama wa Mwisho

Tofauti na Vifaa vya Kernel, **Vifaa vya Mfumo hufanya kazi katika nafasi ya mtumiaji** badala ya nafasi ya kernel, kupunguza hatari ya kuharibika kwa mfumo kutokana na kushindwa kwa kifaa cha nyongeza.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za vifaa vya mfumo: Vifaa vya **DriverKit**, Vifaa vya **Network**, na Vifaa vya **Usalama wa Mwisho**.

### **Vifaa vya DriverKit**

DriverKit ni mbadala wa vifaa vya kernel ambavyo **hutoa msaada wa vifaa**. Inaruhusu madereva wa vifaa (kama vile USB, Serial, NIC, na madereva ya HID) kufanya kazi katika nafasi ya mtumiaji badala ya nafasi ya kernel. Fremu ya DriverKit inajumuisha **toleo za nafasi ya mtumiaji za darasa fulani za I/O Kit**, na kernel hutoa matukio ya kawaida ya I/O Kit kwa nafasi ya mtumiaji, kutoa mazingira salama kwa madereva haya kufanya kazi.

### **Vifaa vya Network**

Vifaa vya Network hutoa uwezo wa kubinafsisha tabia za mtandao. Kuna aina kadhaa za Vifaa vya Network:

* **App Proxy**: Hii hutumiwa kwa kujenga mteja wa VPN ambao unatekeleza itifaki ya VPN ya desturi inayolenga mwendelezo, hii inamaanisha inashughulikia trafiki ya mtandao kulingana na uhusiano (au mwendelezo) badala ya pakiti binafsi.
* **Packet Tunnel**: Hii hutumiwa kwa kujenga mteja wa VPN ambao unatekeleza itifaki ya VPN ya desturi inayolenga pakiti binafsi, hii inamaanisha inashughulikia trafiki ya mtandao kulingana na pakiti binafsi.
* **Filter Data**: Hii hutumiwa kwa kufilta "mwendelezo" wa mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao kwa kiwango cha mwendelezo.
* **Filter Packet**: Hii hutumiwa kwa kufilta pakiti binafsi za mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao kwa kiwango cha pakiti.
* **DNS Proxy**: Hii hutumiwa kwa kujenga mtoa huduma wa DNS wa desturi. Inaweza kutumika kufuatilia au kurekebisha maombi na majibu ya DNS.

## Fremu ya Usalama wa Mwisho

Usalama wa Mwisho ni fremu iliyotolewa na Apple kwenye macOS ambayo hutoa seti ya APIs kwa usalama wa mfumo. Imelenga kutumiwa na **wauzaji wa usalama na watengenezaji kujenga bidhaa ambazo zinaweza kufuatilia na kudhibiti shughuli za mfumo** ili kutambua na kulinda dhidi ya shughuli za uovu.

Fremu hii hutoa **mkusanyiko wa APIs kufuatilia na kudhibiti shughuli za mfumo**, kama vile utekelezaji wa michakato, matukio ya mfumo wa faili, mtandao na matukio ya kernel.

Muhimu wa fremu hii imetekelezwa katika kernel, kama Kifaa cha Kernel (KEXT) kilichopo katika **`/System/Library/Extensions/EndpointSecurity.kext`**. KEXT hii inajumuisha sehemu muhimu kadhaa:

* **EndpointSecurityDriver**: Hii hufanya kama "mlango wa kuingilia" wa kifaa cha kernel. Ni sehemu kuu ya mwingiliano kati ya OS na fremu ya Usalama wa Mwisho.
* **EndpointSecurityEventManager**: Sehemu hii inahusika na utekelezaji wa kanzu za kernel. Kanzu za kernel huruhusu fremu kufuatilia matukio ya mfumo kwa kuingilia wito wa mfumo.
* **EndpointSecurityClientManager**: Hii inasimamia mawasiliano na wateja wa nafasi ya mtumiaji, ikifuatilia ni wateja gani wameunganishwa na wanahitaji kupokea arifa za matukio.
* **EndpointSecurityMessageManager**: Hii inatuma ujumbe na arifa za matukio kwa wateja wa nafasi ya mtumiaji.

Matukio ambayo fremu ya Usalama wa Mwisho inaweza kufuatilia yamepangwa katika makundi yafuatayo:

* Matukio ya faili
* Matukio ya michakato
* Matukio ya soketi
* Matukio ya kernel (kama vile kupakia/kupakua kifaa cha kernel au kufungua kifaa cha I/O Kit)

### Muundo wa Fremu ya Usalama wa Mwisho

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Mawasiliano ya **nafasi ya mtumiaji** na fremu ya Usalama wa Mwisho hufanyika kupitia darasa la IOUserClient. Darasa mbili tofauti hutumiwa, kulingana na aina ya mpigaji:

* **EndpointSecurityDriverClient**: Hii inahitaji ruhusa ya `com.apple.private.endpoint-security.manager`, ambayo inashikiliwa tu na mchakato wa mfumo `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Hii inahitaji ruhusa ya `com.apple.developer.endpoint-security.client`. Kwa kawaida hutumiwa na programu za usalama za mtu wa tatu ambazo zinahitaji kuingiliana na fremu ya Usalama wa Mwisho.

Vifaa vya Usalama wa Mwisho:**`libEndpointSecurity.dylib`** ni maktaba ya C ambayo vifaa vya mfumo hutumia kuingiliana na kernel. Maktaba hii hutumia I/O Kit (`IOKit`) kuingiliana na KEXT ya Usalama wa Mwisho.

**`endpointsecurityd`** ni daemn muhimu wa mfumo unahusika katika kusimamia na kuzindua vifaa vya mfumo vya usalama, hasa wakati wa mchakato wa kuanza wa awali. **Vifaa vya mfumo** vilivyotambuliwa na **`NSEndpointSecurityEarlyBoot`** katika faili yao ya `Info.plist` ndio hupokea matibabu ya kuanza wa awali huu.

Daemn mwingine wa mfumo, **`sysextd`**, **huthibitisha vifaa vya mfumo** na kuvipeleka katika maeneo sahihi ya mfumo. Kisha inaomba daemn husika kupakia kifaa. **`SystemExtensions.framework`** inahusika na kuamsha na kulemaza vifaa vya mfumo.

## Kupitisha ESF

ESF hutumiwa na zana za usalama ambazo zitajaribu kugundua timu nyekundu, kwa hivyo habari yoyote kuhusu jinsi hii inaweza kuepukwa inasikika ya kuvutia.

### CVE-2021-30965

Jambo ni kwamba programu ya usalama inahitaji **Ruhusa ya Kupata Diski Kamili**. Kwa hivyo, ikiwa mshambuliaji anaweza kuiondoa, anaweza kuzuia programu hiyo isifanye kazi:
```bash
tccutil reset All
```
Kwa **maelezo zaidi** kuhusu kosa hili na mengine yanayohusiana nayo angalia mazungumzo [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Mwishoni hili lilirekebishwa kwa kumpa idhini mpya **`kTCCServiceEndpointSecurityClient`** kwa programu ya usalama inayosimamiwa na **`tccd`** ili `tccutil` isifute idhini zake kuzuia kutokana na kufanya kazi.

## Marejeo

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{% hint style="success" %}
Jifunze & zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
