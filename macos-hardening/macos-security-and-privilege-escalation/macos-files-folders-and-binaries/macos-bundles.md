# Vifurushi vya macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Vifurushi katika macOS hutumika kama makontena kwa aina mbalimbali za rasilimali ikiwa ni pamoja na programu, maktaba, na faili zingine muhimu, ikifanya ionekane kama vitu vya pekee katika Finder, kama vile faili za `*.app` zinazojulikana. Vifurushi vinavyokutwa mara kwa mara ni pamoja na vifurushi vya `.app`, ingawa aina zingine kama vile `.framework`, `.systemextension`, na `.kext` pia ni maarufu.

### Vipengele Msingi vya Fungu

Ndani ya kifurushi, hasa ndani ya saraka ya `<application>.app/Contents/`, kuna rasilimali muhimu mbalimbali zilizohifadhiwa:

* **\_CodeSignature**: Saraka hii inahifadhi maelezo ya kusaini kanuni muhimu kwa ajili ya kuthibitisha uadilifu wa programu. Unaweza kukagua maelezo ya kusaini kanuni kwa kutumia amri kama: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Ina kifurushi cha utekelezaji wa programu ambayo hufanya kazi wakati mtumiaji anashirikiana nayo.
* **Resources**: Ghala la vipengele vya interface ya mtumiaji wa programu ikiwa ni pamoja na picha, nyaraka, na maelezo ya interface (faili za nib/xib).
* **Info.plist**: Inafanya kazi kama faili kuu ya usanidi wa programu, muhimu kwa mfumo kutambua na kushirikiana na programu kwa usahihi.

#### Vipengele Muhimu katika Info.plist

Faili ya `Info.plist` ni msingi wa usanidi wa programu, ikijumuisha funguo kama vile:

* **CFBundleExecutable**: Inabainisha jina la faili kuu ya utekelezaji iliyoko katika saraka ya `Contents/MacOS`.
* **CFBundleIdentifier**: Hutoa kitambulisho cha kimataifa kwa programu, kinachotumiwa sana na macOS kwa usimamizi wa programu.
* **LSMinimumSystemVersion**: Inaonyesha toleo la chini la macOS linalohitajika ili programu iweze kufanya kazi.

### Kuchunguza Vifurushi

Kutafiti maudhui ya kifurushi, kama vile `Safari.app`, unaweza kutumia amri ifuatayo: `bash ls -lR /Applications/Safari.app/Contents`

Utafiti huu unaonyesha saraka kama vile `_CodeSignature`, `MacOS`, `Resources`, na faili kama `Info.plist`, kila moja ikihudumia lengo la pekee kutoka kwa kuhakikisha programu hadi kufafanua interface yake ya mtumiaji na vigezo vya uendeshaji.

#### Saraka Zingine za Vifurushi

Zaidi ya saraka za kawaida, vifurushi vinaweza pia kuwa na:

* **Frameworks**: Ina mifumo iliyofungwa inayotumiwa na programu. Mifumo ni kama dylibs na rasilimali ziada.
* **PlugIns**: Saraka kwa ajili ya programu za ziada na nyongeza zinazoboresha uwezo wa programu.
* **XPCServices**: Inashikilia huduma za XPC zinazotumiwa na programu kwa mawasiliano nje ya mchakato.

Muundo huu unahakikisha kuwa vipengele vyote muhimu vimefungwa ndani ya kifurushi, kufanikisha mazingira ya programu yenye modular na salama.

Kwa maelezo zaidi kuhusu funguo za `Info.plist` na maana yao, nyaraka za maendeleo ya Apple zinatoa rasilimali kubwa: [Kumbukumbu ya Funguo ya Info.plist ya Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
