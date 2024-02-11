# Vikundi vya macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Vikundi katika macOS hutumika kama vyombo vya kuhifadhi aina mbalimbali za rasilimali ikiwa ni pamoja na programu, maktaba, na faili zingine muhimu, ikifanya ionekane kama vitu vya pekee katika Finder, kama vile faili za `*.app` zinazojulikana. Kikundi kinachokutwa mara kwa mara ni kikundi cha `.app`, ingawa aina zingine kama `.framework`, `.systemextension`, na `.kext` pia ni maarufu.

### Sehemu Muhimu za Kikundi

Ndani ya kikundi, haswa ndani ya saraka ya `<application>.app/Contents/`, kuna rasilimali muhimu mbalimbali:

- **_CodeSignature**: Saraka hii inahifadhi maelezo ya kusaini kanuni muhimu kwa kuthibitisha uadilifu wa programu. Unaweza kuangalia maelezo ya kusaini kanuni kwa kutumia amri kama vile:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Ina kifurushi cha kutekelezwa cha programu ambayo inaendesha kwa kuingiliana na mtumiaji.
- **Resources**: Hifadhi ya sehemu za kiolesura cha mtumiaji cha programu ikiwa ni pamoja na picha, hati, na maelezo ya kiolesura (faili za nib/xib).
- **Info.plist**: Inafanya kama faili kuu ya usanidi wa programu, muhimu kwa mfumo kutambua na kuingiliana na programu kwa njia sahihi.

#### Vipengele Muhimu katika Info.plist

Faili ya `Info.plist` ni msingi wa usanidi wa programu, ina vipengele kama:

- **CFBundleExecutable**: Inabainisha jina la faili kuu ya kutekelezwa iliyoko katika saraka ya `Contents/MacOS`.
- **CFBundleIdentifier**: Hutoa kitambulisho cha ulimwengu kwa programu, kinachotumiwa sana na macOS kwa usimamizi wa programu.
- **LSMinimumSystemVersion**: Inaonyesha toleo la chini la macOS linalohitajika ili programu iweze kukimbia.

### Kuchunguza Vikundi

Ili kuchunguza maudhui ya kikundi, kama vile `Safari.app`, unaweza kutumia amri ifuatayo:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Uchunguzi huu unaonyesha saraka kama vile `_CodeSignature`, `MacOS`, `Resources`, na faili kama vile `Info.plist`, kila moja ikitoa kusudi lake maalum kutoka kwa kuhakikisha usalama wa programu hadi kufafanua kiolesura chake cha mtumiaji na vigezo vya uendeshaji.

#### Saraka Zingine za Vikundi

Mbali na saraka za kawaida, vikundi vinaweza pia kuwa na:

- **Frameworks**: Ina maktaba zilizopangwa zinazotumiwa na programu.
- **PlugIns**: Saraka kwa ajili ya programu-jalizi na nyongeza ambazo huongeza uwezo wa programu.
- **XPCServices**: Inashikilia huduma za XPC zinazotumiwa na programu kwa mawasiliano nje ya mchakato.

Muundo huu unahakikisha kuwa vipengele vyote muhimu vimefungwa ndani ya kikundi, kurahisisha mazingira ya programu yenye moduli na salama.

Kwa habari zaidi kuhusu ufafanuzi wa funguo za `Info.plist` na maana yao, nyaraka za maendeleo ya Apple zinatoa rasilimali kubwa: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
