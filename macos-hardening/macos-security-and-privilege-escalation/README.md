# Usalama na Kupandisha Madaraka kwa macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa zawadi za mdudu!

**Machapisho ya Kuhack**\
Shiriki na yaliyomo yanayochimba katika msisimko na changamoto za kuhack

**Taarifa za Kuhack Halisi**\
Kaa up-to-date na ulimwengu wa kuhack wenye kasi kupitia taarifa za wakati halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelekezwa na zawadi mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

## Msingi wa MacOS

Ikiwa haujazoea macOS, unapaswa kuanza kujifunza misingi ya macOS:

* **Faili na ruhusa za macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* **Watumiaji wa kawaida wa macOS**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Mimariria** ya k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Huduma na itifaki za n**etwork za macOS**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS ya **OpenSource**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Ili kupakua `tar.gz` badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM ya MacOS

Katika makampuni **mifumo ya macOS inaweza kuwa imepangiliwa sana na MDM**. Kwa hivyo, kutoka mtazamo wa mshambuliaji ni muhimu kujua **jinsi hiyo inavyofanya kazi**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Ukaguzi, Uchunguzi na Kufanya Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Kinga ya Usalama ya MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Eneo la Mashambulizi

### Ruhusa za Faili

Ikiwa **mchakato unaoendeshwa kama root unahifadhi** faili ambayo inaweza kudhibitiwa na mtumiaji, mtumiaji anaweza kutumia hii kwa **kupandisha madaraka**.\
Hii inaweza kutokea katika hali zifuatazo:

* Faili iliyotumiwa tayari imeundwa na mtumiaji (inayomilikiwa na mtumiaji)
* Faili iliyotumiwa inaweza kuandikwa na mtumiaji kwa sababu ya kikundi
* Faili iliyotumiwa iko ndani ya saraka inayomilikiwa na mtumiaji (mtumiaji anaweza kuunda faili)
* Faili iliyotumiwa iko ndani ya saraka inayomilikiwa na root lakini mtumiaji ana ufikiaji wa kuandika juu yake kwa sababu ya kikundi (mtumiaji anaweza kuunda faili)

Uwezo wa **kuunda faili** ambayo itatumika na **root**, inaruhusu mtumiaji **kutumia maudhui yake** au hata kuunda **symlinks/hardlinks** kuelekeza mahali pengine.

Kwa aina hii ya udhaifu usisahau kuchunguza **wasanidi wa `.pkg`** walio hatarini:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Ugani wa Faili na Wachakataji wa Programu za URL

Programu za ajabu zilizosajiliwa na ugani wa faili zinaweza kutumiwa vibaya na programu tofauti zinaweza kusajiliwa kufungua itifaki maalum

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Kupandisha Madaraka ya TCC / SIP ya macOS

Katika macOS **programu na programu za binary zinaweza kuwa na ruhusa** ya kufikia folda au mipangilio inayowafanya wawe na haki zaidi kuliko wengine.

Kwa hivyo, mshambuliaji anayetaka kudhoofisha kwa mafanikio kompyuta ya macOS atahitaji **kupandisha madaraka yake ya TCC** (au hata **kupuuza SIP**, kulingana na mahitaji yake).

Ruhusa hizi kawaida hupewa kwa mfumo wa **ruhusa** programu imesainiwa nazo, au programu inaweza kuomba ufikiaji fulani na baada ya **mtumiaji kuziidhinisha** zinaweza kupatikana katika **databases za TCC**. Njia nyingine mchakato unaweza kupata ruhusa hizi ni kwa kuwa **mtoto wa mchakato** na ruhusa hizo kwani kawaida **zinarithiwa**.

Fuata viungo hivi kupata njia tofauti za [**kupandisha madaraka katika TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), kwa [**kupuuza TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) na jinsi zamani [**SIP imepita**](macos-security-protections/macos-sip.md#sip-bypasses).

## Kupandisha Madaraka ya Kawaida ya macOS

Bila shaka kutoka mtazamo wa timu nyekundu unapaswa pia kuwa na nia ya kupandisha hadi kufikia mizizi. Angalia chapisho lifuatalo kwa vidokezo:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Marejeo

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za udhaifu!

**Machapisho ya Kudukua**\
Shiriki na maudhui yanayochimba kina kuhusu msisimko na changamoto za kudukua

**Taarifa za Kudukua za Wakati Halisi**\
Kaa sawa na ulimwengu wa kudukua wenye kasi kupitia taarifa za wakati halisi na ufahamu

**Matangazo Mapya**\
Baki mwelekezi na matangazo mapya ya tuzo za udhaifu yanayoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

<details>

<summary><strong>Jifunze kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJISAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
