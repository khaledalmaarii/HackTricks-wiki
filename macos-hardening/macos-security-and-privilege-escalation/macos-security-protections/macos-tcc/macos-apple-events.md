# macOS Matukio ya Apple

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

**Matukio ya Apple** ni kipengele katika macOS ya Apple kinachoruhusu programu kuwasiliana na nyingine. Wanahusiana na **Meneja wa Matukio ya Apple**, ambayo ni sehemu ya mfumo wa uendeshaji wa macOS inayowajibika kwa kushughulikia mawasiliano kati ya michakato. Mfumo huu huwezesha programu moja kutuma ujumbe kwa programu nyingine kuomba ifanye operesheni fulani, kama kufungua faili, kupata data, au kutekeleza amri.

Mnara wa mina ni `/System/Library/CoreServices/appleeventsd` ambao hujisajili kama huduma `com.apple.coreservices.appleevents`.

Kila programu inayoweza kupokea matukio itaangalia hili na daemon kwa kutoa Bandari yake ya Matukio ya Apple. Na wakati programu inataka kutuma tukio kwake, programu itaomba bandari hii kutoka kwa daemon.

Programu zilizowekwa kwenye sanduku zinahitaji ruhusa kama `ruhusu kutuma matukio ya apple` na `(ruhusu mach-lookup (jina la kawaida "com.apple.coreservices.appleevents))` ili kuweza kutuma matukio. Kumbuka kuwa ruhusa kama `com.apple.security.temporary-exception.apple-events` inaweza kuzuia nani anaye ruhusa ya kutuma matukio ambayo itahitaji ruhusa kama `com.apple.private.appleevents`.

{% hint style="success" %}
Inawezekana kutumia mazingira ya mazingira **`AEDebugSends`** ili kurekodi habari kuhusu ujumbe uliotumwa:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
