# Vifurushi vya macOS

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Taarifa Msingi

Vifurushi katika macOS hutumika kama makontena ya aina mbalimbali za rasilimali ikiwa ni pamoja na programu, maktaba, na faili zingine muhimu, ikifanya ionekane kama vitu vya pekee katika Finder, kama vile faili za `*.app` zinazojulikana. Vifurushi vinavyokutwa mara kwa mara ni pamoja na vifurushi vya `.app`, ingawa aina zingine kama vile `.framework`, `.systemextension`, na `.kext` pia ni maarufu.

### Vipengele Msingi vya Fungu

Ndani ya kifurushi, hasa ndani ya saraka ya `<application>.app/Contents/`, kuna rasilimali muhimu mbalimbali zilizohifadhiwa:

* **\_CodeSignature**: Saraka hii inahifadhi maelezo ya kusaini kanuni muhimu kwa ajili ya kuthibitisha uadilifu wa programu. Unaweza kukagua maelezo ya kusaini kanuni kwa kutumia amri kama: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Ina kielekezwa cha utekelezaji wa programu ambayo hufanya kazi wakati wa mwingiliano wa mtumiaji.
* **Resources**: Ghala la vipengele vya interface ya mtumiaji wa programu ikiwa ni pamoja na picha, nyaraka, na maelezo ya interface (faili za nib/xib).
* **Info.plist**: Inafanya kazi kama faili kuu ya usanidi wa programu, muhimu kwa mfumo kutambua na kuingiliana na programu kwa usahihi.

#### Vipengele Muhimu katika Info.plist

Faili ya `Info.plist` ni msingi wa usanidi wa programu, ikijumuisha funguo kama vile:

* **CFBundleExecutable**: Inabainisha jina la faili kuu ya utekelezaji iliyoko katika saraka ya `Contents/MacOS`.
* **CFBundleIdentifier**: Hutoa kitambulisho cha ulimwengu kwa programu, kinachotumiwa sana na macOS kwa usimamizi wa programu.
* **LSMinimumSystemVersion**: Inaonyesha toleo la chini la macOS linalohitajika ili programu iweze kufanya kazi.

### Kuchunguza Vifurushi

Kutafiti maudhui ya kifurushi, kama vile `Safari.app`, unaweza kutumia amri ifuatayo: `bash ls -lR /Applications/Safari.app/Contents`

Utafiti huu unaonyesha saraka kama vile `_CodeSignature`, `MacOS`, `Resources`, na faili kama vile `Info.plist`, kila moja ikihudumia lengo la pekee kutoka kwa kuhakikisha programu hadi kufafanua interface yake ya mtumiaji na vigezo vyake vya uendeshaji.

#### Saraka za Ziada za Vifurushi

Zaidi ya saraka za kawaida, vifurushi vinaweza pia kuwa na:

* **Frameworks**: Ina mifumo iliyofungwa inayotumiwa na programu. Mifumo ni kama dylibs na rasilimali ziada.
* **PlugIns**: Saraka kwa ajili ya programu za ziada na nyongeza zinazoboresha uwezo wa programu.
* **XPCServices**: Inashikilia huduma za XPC zinazotumiwa na programu kwa mawasiliano nje ya mchakato.

Muundo huu unahakikisha kuwa vipengele vyote muhimu vimefungwa ndani ya kifurushi, kufanikisha mazingira ya programu yenye moduli na salama.

Kwa maelezo zaidi kuhusu funguo za `Info.plist` na maana yao, nyaraka za maendeleo ya Apple zinatoa rasilimali nyingi: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
