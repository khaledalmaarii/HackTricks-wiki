# Vifaa vya Mfumo wa macOS

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Vifaa vya Mfumo / Fremu ya Usalama wa Mwisho

Tofauti na Vifaa vya Kernel, **Vifaa vya Mfumo hufanya kazi katika nafasi ya mtumiaji** badala ya nafasi ya kernel, kupunguza hatari ya kuharibika kwa mfumo kutokana na kushindwa kwa kifaa cha nyongeza.

<figure><img src="../../../.gitbook/assets/image (603).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za vifaa vya mfumo: Vifaa vya **DriverKit**, Vifaa vya **Network**, na Vifaa vya **Endpoint Security**.

### **Vifaa vya DriverKit**

DriverKit ni mbadala wa vifaa vya kernel vinavyo **tolea msaada wa vifaa**. Inaruhusu madereva ya vifaa (kama vile USB, Serial, NIC, na madereva ya HID) kufanya kazi katika nafasi ya mtumiaji badala ya nafasi ya kernel. Fremu ya DriverKit inajumuisha **matoleo ya nafasi ya mtumiaji ya darasa fulani za I/O Kit**, na kernel hutoa matukio ya kawaida ya I/O Kit kwa nafasi ya mtumiaji, kutoa mazingira salama kwa madereva haya kufanya kazi.

### **Vifaa vya Network**

Vifaa vya Network hutoa uwezo wa kubinafsisha tabia za mtandao. Kuna aina kadhaa za Vifaa vya Network:

* **App Proxy**: Hii hutumiwa kwa kujenga mteja wa VPN ambao unatekeleza itifaki ya VPN ya desturi inayolenga mwendelezo, hii inamaanisha inashughulikia trafiki ya mtandao kulingana na uhusiano (au mwendelezo) badala ya pakiti binafsi.
* **Packet Tunnel**: Hii hutumiwa kwa kujenga mteja wa VPN ambao unatekeleza itifaki ya VPN ya desturi inayolenga pakiti binafsi, hii inamaanisha inashughulikia trafiki ya mtandao kulingana na pakiti binafsi.
* **Filter Data**: Hii hutumiwa kwa kufilta "mwendelezo" wa mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao kwa kiwango cha mwendelezo.
* **Filter Packet**: Hii hutumiwa kwa kufilta pakiti binafsi za mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao kwa kiwango cha pakiti.
* **DNS Proxy**: Hii hutumiwa kwa kujenga mtoa huduma wa DNS wa desturi. Inaweza kutumika kufuatilia au kurekebisha maombi na majibu ya DNS.

## Fremu ya Usalama wa Mwisho

Endpoint Security ni fremu iliyotolewa na Apple kwenye macOS ambayo hutoa seti ya APIs kwa usalama wa mfumo. Imelenga kutumiwa na **wauzaji wa usalama na watengenezaji kujenga bidhaa ambazo zinaweza kufuatilia na kudhibiti shughuli za mfumo** ili kutambua na kulinda dhidi ya shughuli za uovu.

Fremu hii hutoa **mkusanyo wa APIs kufuatilia na kudhibiti shughuli za mfumo**, kama vile utekelezaji wa michakato, matukio ya mfumo wa faili, mtandao na matukio ya kernel.

Muhimu wa fremu hii imetekelezwa katika kernel, kama Kifaa cha Kernel (KEXT) kilichoko katika **`/System/Library/Extensions/EndpointSecurity.kext`**. KEXT hii inajumuisha sehemu muhimu kadhaa:

* **EndpointSecurityDriver**: Hii hufanya kama "mlango wa kuingilia" wa kifaa cha kernel. Ni sehemu kuu ya mwingiliano kati ya OS na fremu ya Usalama wa Mwisho.
* **EndpointSecurityEventManager**: Sehemu hii inahusika na utekelezaji wa kufunga kwa kernel. Kufunga kwa kernel kuruhusu fremu kufuatilia matukio ya mfumo kwa kuingilia wito wa mfumo.
* **EndpointSecurityClientManager**: Hii inasimamia mawasiliano na wateja wa nafasi ya mtumiaji, ikifuatilia ni wateja gani wameunganishwa na wanahitaji kupokea arifa za matukio.
* **EndpointSecurityMessageManager**: Hii inatuma ujumbe na arifa za matukio kwa wateja wa nafasi ya mtumiaji.

Matukio ambayo fremu ya Usalama wa Mwisho inaweza kufuatilia yamepangwa katika:

* Matukio ya faili
* Matukio ya michakato
* Matukio ya soketi
* Matukio ya kernel (kama vile kupakia/kupakua kifaa cha kernel au kufungua kifaa cha I/O Kit)

### Muundo wa Fremu ya Usalama wa Mwisho

<figure><img src="../../../.gitbook/assets/image (1065).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Mawasiliano ya nafasi ya mtumiaji** na fremu ya Usalama wa Mwisho hufanyika kupitia darasa la IOUserClient. Darasa mbili tofauti hutumiwa, kulingana na aina ya mpigaji:

* **EndpointSecurityDriverClient**: Hii inahitaji ruhusa ya `com.apple.private.endpoint-security.manager`, ambayo inashikiliwa tu na mchakato wa mfumo `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Hii inahitaji ruhusa ya `com.apple.developer.endpoint-security.client`. Kwa kawaida hutumiwa na programu za usalama za mtu wa tatu ambazo zinahitaji kuingiliana na fremu ya Usalama wa Mwisho.

Vifaa vya Usalama wa Mwisho:**`libEndpointSecurity.dylib`** ni maktaba ya C ambayo vifaa vya mfumo hutumia kuingiliana na kernel. Maktaba hii hutumia I/O Kit (`IOKit`) kuingiliana na KEXT ya Usalama wa Mwisho.

**`endpointsecurityd`** ni daemuni muhimu wa mfumo unahusika katika kusimamia na kuzindua vifaa vya mfumo vya usalama, hasa wakati wa mchakato wa kuanza upya mapema. **Vifaa vya mfumo** vilivyochapishwa na **`NSEndpointSecurityEarlyBoot`** katika faili yao ya `Info.plist` ndio hupokea matibabu haya ya kuanza mapema.

Daemuni mwingine wa mfumo, **`sysextd`**, **huthibitisha vifaa vya mfumo** na kuvipeleka kwenye maeneo sahihi ya mfumo. Kisha inaomba daemuni husika kupakia kifaa. **`SystemExtensions.framework`** inahusika na kuamsha na kulemaza vifaa vya mfumo. 

## Kupitisha ESF

ESF hutumiwa na zana za usalama ambazo zitajaribu kugundua timu nyekundu, kwa hivyo habari yoyote kuhusu jinsi hii inaweza kuepukwa inasikika ya kuvutia.

### CVE-2021-30965

Jambo ni kwamba programu ya usalama inahitaji **Ruhusa ya Kupata Diski Kamili**. Kwa hivyo ikiwa mshambuliaji angeweza kuiondoa hiyo, angeweza kuzuia programu hiyo isifanye kazi:
```bash
tccutil reset All
```
Kwa **maelezo zaidi** kuhusu kisitisho hiki na vingine vinavyohusiana, angalia mazungumzo [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Mwishoni, hili lilirekebishwa kwa kutoa idhini mpya **`kTCCServiceEndpointSecurityClient`** kwa programu ya usalama inayosimamiwa na **`tccd`** ili `tccutil` isifute idhini zake kuzuia kutokana na kufanya kazi.

## Marejeo

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
