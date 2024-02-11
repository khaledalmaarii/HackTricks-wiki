# Usalama na Kuongeza Uwezo wa MacOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho Kuhusu Kudukua**\
Shiriki na yaliyomo yanayochunguza msisimko na changamoto za kudukua

**Habari za Kudukua za Wakati Halisi**\
Endelea kuwa na habari za ulimwengu wa kudukua kwa kasi kupitia habari na ufahamu wa wakati halisi

**Matangazo ya Hivi Karibuni**\
Endelea kuwa na habari na matangazo mapya ya tuzo za mdudu yanayoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

## Msingi wa MacOS

Ikiwa haujazoea macOS, unapaswa kuanza kujifunza msingi wa macOS:

* **Faili na ruhusa maalum za macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Watumiaji wa kawaida wa macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Muundo** wa **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Huduma na itifaki za mtandao za kawaida za macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **macOS ya chanzo wazi**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Ili kupakua `tar.gz` badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Katika kampuni, **mifumo ya macOS** inawezekana sana kuwa **inadhibitiwa na MDM**. Kwa hivyo, kutoka kwa mtazamo wa mshambuliaji, ni muhimu kujua **jinsi hilo linavyofanya kazi**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Ukaguzi, Uchunguzi na Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Ulinzi wa Usalama wa MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Eneo la Shambulio

### Ruhusa za Faili

Ikiwa **mchakato unaoendesha kama mzizi unahariri** faili ambayo inaweza kudhibitiwa na mtumiaji, mtumiaji anaweza kuitumia kwa **kuongeza uwezo**.\
Hii inaweza kutokea katika hali zifuatazo:

* Faili iliyotumiwa tayari ilikuwa imeundwa na mtumiaji (inamilikiwa na mtumiaji)
* Faili iliyotumiwa inaweza kuandikwa na mtumiaji kwa sababu ya kikundi
* Faili iliyotumiwa iko ndani ya saraka inayomilikiwa na mtumiaji (mtumiaji anaweza kuunda faili hiyo)
* Faili iliyotumiwa iko ndani ya saraka inayomilikiwa na mzizi lakini mtumiaji ana ufikiaji wa kuandika juu yake kwa sababu ya kikundi (mtumiaji anaweza kuunda faili hiyo)

Uwezo wa **kuunda faili** ambayo itatumika na **mzizi**, inaruhusu mtumiaji kuchukua faida ya yaliyomo au hata kuunda **viungo vya ishara/viungo vigumu** kuielekeza mahali pengine.

Kwa aina hii ya udhaifu, usisahau **kuchunguza wakala wa `.pkg` wenye udhaifu**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Upanuzi wa Faili na Wachanganuzi wa Programu za URL

Programu za ajabu zilizosajiliwa kwa njia ya upanuzi wa faili zinaweza kutumiwa vibaya na programu tofauti zinaweza kusajiliwa kufungua itifaki maalum

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Kuongeza Uwezo wa TCC / SIP wa macOS

Katika macOS, **programu na faili zinaweza kuwa na ruhusa** za kufikia folda au mipangilio ambayo inawafanya kuwa na uwezo zaidi kuliko wengine.

Kwa hivyo, mshambuliaji anayetaka kudukua kwa mafanikio kompyuta ya macOS atahitaji **kuongeza uwezo wake wa TCC** (au hata **kupitisha SIP**, kulingana na mahitaji yake).

Ruhusa hizi kawaida hupewa kwa njia ya **haki** ambazo programu imepokea, au programu inaweza kuomba ufikiaji fulani na baada ya **mtumiaji kuzikubali**, zinaweza kupatikana katika **hifadhidata za TCC**. Njia nyingine ambayo mchakato unaweza kupata ruhusa hizi ni kwa kuwa **mtoto wa mchakato** na ruhusa hizo kwa sababu kawaida **zinaurithiwa**.

Fuata viungo hivi ili kupata njia tofauti za [**kuongeza uwezo katika TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**kupitisha TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) na jinsi hapo zamani [**SIP imepitishwa**](macos-security-protections/macos-sip.md#sip-bypasses).

## Kuongeza Uwezo wa Kawaida wa macOS

Bila shaka, kutoka kwa mtazamo wa timu nyekundu, unapaswa pia kuwa na nia ya kuongeza had
## Marejeo

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na seva ya [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa bug bounty!

**Machapisho ya Udukuzi**\
Shiriki na maudhui yanayochunguza msisimko na changamoto za udukuzi

**Habari za Udukuzi za Wakati Halisi**\
Endelea kuwa na habari za ulimwengu wa udukuzi kwa kasi kupitia habari na ufahamu wa wakati halisi

**Matangazo ya Hivi Karibuni**\
Baki na habari za hivi karibuni kuhusu bug bounty mpya zinazozinduliwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ina tangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
