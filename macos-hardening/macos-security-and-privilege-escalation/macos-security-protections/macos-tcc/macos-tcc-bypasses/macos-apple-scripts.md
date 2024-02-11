# Skripti za Apple kwenye macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Skripti za Apple

Hii ni lugha ya skripti inayotumiwa kwa **utomatishaji wa kazi** kwa **kuingiliana na michakato ya mbali**. Inafanya iwe rahisi **kuomba michakato mingine kutekeleza baadhi ya hatua**. **Programu hasidi** inaweza kutumia vipengele hivi kudhuru kazi zinazotolewa na michakato mingine.\
Kwa mfano, programu hasidi inaweza **kuingiza msimbo wa JS usiojulikana kwenye kurasa zilizofunguliwa kwenye kivinjari**. Au **bonyeza moja kwa moja** ruhusa zinazoruhusiwa zinazohitajika na mtumiaji.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hapa una mifano kadhaa: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pata habari zaidi kuhusu programu hasidi zinazotumia AppleScripts [**hapa**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Skripti za Apple zinaweza kuwa rahisi "**kukusanywa**". Toleo hizi zinaweza kuwa rahisi "**kukusanywa upya**" na `osadecompile`

Hata hivyo, skripti hizi pia zinaweza **kuwa zimehifadhiwa kama "Soma tu"** (kupitia chaguo la "Hifadhi..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Na katika kesi hii, yaliyomo hayawezi kuchambuliwa hata na `osadecompile`

Hata hivyo, bado kuna zana kadhaa ambazo zinaweza kutumika kuelewa programu hizi, [**soma utafiti huu kwa maelezo zaidi**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Zana [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) pamoja na [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) itakuwa muhimu sana kuelewa jinsi skripti inavyofanya kazi.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
