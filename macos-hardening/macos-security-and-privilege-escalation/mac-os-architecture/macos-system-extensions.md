# Vifaa vya Mfumo wa macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vifaa vya Mfumo / Kitambulisho cha Mwisho cha Usalama

Tofauti na Vifaa vya Kernel, **Vifaa vya Mfumo hufanya kazi katika nafasi ya mtumiaji** badala ya nafasi ya kernel, kupunguza hatari ya kushindwa kwa mfumo kutokana na kosa la kifaa cha nyongeza.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za vifaa vya mfumo: Vifaa vya Kitambulisho cha Dereva, Vifaa vya Mtandao, na Vifaa vya Kitambulisho cha Mwisho.

### **Vifaa vya Kitambulisho cha Dereva**

Kitambulisho cha Dereva ni mbadala wa vifaa vya kernel ambavyo **hutoa msaada wa vifaa**. Inaruhusu madereva ya kifaa (kama vile USB, Serial, NIC, na madereva ya HID) kukimbia katika nafasi ya mtumiaji badala ya nafasi ya kernel. Kitambulisho cha Dereva kinajumuisha **toleo la nafasi ya mtumiaji la darasa fulani za I/O Kit**, na kernel inapeleka matukio ya kawaida ya I/O Kit kwa nafasi ya mtumiaji, kutoa mazingira salama zaidi kwa madereva haya kukimbia.

### **Vifaa vya Mtandao**

Vifaa vya Mtandao hutoa uwezo wa kubinafsisha tabia za mtandao. Kuna aina kadhaa za Vifaa vya Mtandao:

* **App Proxy**: Hii hutumiwa kuunda mteja wa VPN ambao unatekeleza itifaki ya VPN ya desturi inayotegemea mtiririko. Hii inamaanisha inashughulikia trafiki ya mtandao kulingana na uhusiano (au mtiririko) badala ya pakiti binafsi.
* **Packet Tunnel**: Hii hutumiwa kuunda mteja wa VPN ambao unatekeleza itifaki ya VPN ya desturi inayotegemea pakiti binafsi. Hii inamaanisha inashughulikia trafiki ya mtandao kulingana na pakiti binafsi.
* **Filter Data**: Hii hutumiwa kufanya uchujaji wa "mtiririko" wa mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao kwa kiwango cha mtiririko.
* **Filter Packet**: Hii hutumiwa kufanya uchujaji wa pakiti binafsi za mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao kwa kiwango cha pakiti binafsi.
* **DNS Proxy**: Hii hutumiwa kuunda mtoa huduma wa DNS ya desturi. Inaweza kutumika kufuatilia au kurekebisha maombi na majibu ya DNS.

## Kitambulisho cha Mwisho cha Usalama

Kitambulisho cha Mwisho ni mfumo uliotolewa na Apple kwenye macOS ambao hutoa seti ya APIs kwa usalama wa mfumo. Inalenga kutumiwa na **wauzaji wa usalama na watengenezaji** kujenga bidhaa ambazo zinaweza kufuatilia na kudhibiti shughuli za mfumo ili kutambua na kulinda dhidi ya shughuli za uovu.

Mfumo huu hutoa **mkusanyiko wa APIs kufuatilia na kudhibiti shughuli za mfumo**, kama vile utekelezaji wa michakato, matukio ya mfumo wa faili, matukio ya mtandao na kernel.

Muhimu wa mfumo huu umetekelezwa katika kernel, kama Kifaa cha Kernel (KEXT) kilichoko katika **`/System/Library/Extensions/EndpointSecurity.kext`**. KEXT hii inajumuisha sehemu kadhaa muhimu:

* **EndpointSecurityDriver**: Hii hufanya kama "njia ya kuingia" kwa kifaa cha kernel. Ni sehemu kuu ya mwingiliano kati ya OS na mfumo wa Kitambulisho cha Mwisho.
* **EndpointSecurityEventManager**: Sehemu hii inahusika na utekelezaji wa kanzu za kernel. Kanzu za kernel huruhusu mfumo wa kufuatilia matukio ya mfumo kwa kuingilia wito wa mfumo.
* **EndpointSecurityClientManager**: Hii inasimamia mawasiliano na wateja wa nafasi ya mtumiaji, ikifuatilia wateja wapi wameunganishwa na wanahitaji kupokea arifa za matukio.
* **EndpointSecurityMessageManager**: Hii inatuma ujumbe na arifa za matukio kwa wateja wa nafasi ya mtumiaji.

Matukio ambayo mfumo wa Kitambulisho cha Mwisho unaweza kufuatilia yamegawanywa katika makundi yafuatayo:

* Matukio ya faili
* Matukio ya michakato
* Matukio ya soketi
* Matukio ya kernel (kama vile kupakia/kufuta kifaa cha kernel au kufungua kifaa cha I/O Kit)

### Muundo wa Kitambulisho cha Mwisho cha Usalama

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Mawasiliano ya **nafasi ya mtumiaji** na mfumo wa Kitambulisho cha Mwisho hufanyika kupitia darasa la IOUserClient. Darasa mbili tofauti hutumiwa, kulingana na aina ya mtumiaji:

* **EndpointSecurityDriverClient**: Hii inahitaji ruhusa ya `com.apple.private.endpoint-security.manager`, ambayo inashikiliwa tu na mchakato wa mfumo `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Hii inahitaji ruhusa ya `com.apple.developer.endpoint-security.client`. Kawaida hutumiwa na programu ya usalama ya mtu wa tatu ambayo inahitaji kuingiliana na mfumo wa Kitambulisho cha Mwisho.

Vifaa vya Kitambulisho cha Mwisho:**`libEndpointSecurity.dylib`** ni maktaba ya C ambayo vifaa vya mfumo hutumia kuwasiliana na kernel. Maktaba hii hutumia I/O Kit (`IOKit`) kuwasiliana na KEXT ya Kitambulisho cha Mwisho.

**`endpointsecurityd`** ni daemani muhimu wa mfumo unahusika katika kusimamia na kuzindua vifaa vya mfumo vya usalama wa mwisho, haswa wakati wa mchakato wa kuanza kwa mfumo. **Vifaa vya mfumo tu** vilivyotambuliwa na **`NSEndpointSecurityEarlyBoot`** katika faili yao ya `Info.plist` hupokea matibabu haya ya kuanza kwa mfumo.

Daemani mwingine wa mfumo, **`sysextd`**, **huthibitisha vifaa vya mfumo** na kuvipeleka kwenye maeneo sahihi ya mfumo. Kisha inaomba daemani husika kupakia kifaa cha nyongeza. **`SystemExtensions.framework`** inahusika na kuamsha na kuzima vifaa vya mfumo.

## Kuvuka ESF

ESF hutumiwa na zana za usalama ambazo zitajaribu kugundua timu nyekundu, kwa hivyo habari yoyote kuhusu jinsi hii inaweza kuepukwa inaonekana kuwa ya kuvutia.

### CVE-2021-30965

Jambo ni kwamba programu ya usalama inahitaji kuwa na **Ruhusa ya Kupata Diski Kamili**. Kwa hivyo ikiwa mshambuliaji anaweza kuiondoa, anaweza kuzuia programu hiyo isifanye kazi:
```bash
tccutil reset All
```
Kwa **mashauri zaidi** kuhusu kosa hili na mengine yanayohusiana nayo, angalia mazungumzo [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Mwishowe, hili lilirekebishwa kwa kutoa idhini mpya ya **`kTCCServiceEndpointSecurityClient`** kwa programu ya usalama iliyoongozwa na **`tccd`** ili `tccutil` isisafishe idhini zake na kuzuia programu hiyo isifanye kazi.

## Marejeo

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
