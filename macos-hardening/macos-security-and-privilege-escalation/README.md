# Usalama na Kupandisha Madaraka kwa macOS

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa zawadi za mdudu!

**Machapisho ya Udukuzi**\
Shiriki na yaliyomo yanayochimba kina katika msisimko na changamoto za udukuzi

**Taarifa za Udukuzi za Wakati Halisi**\
Kaa up-to-date na ulimwengu wa udukuzi wenye kasi kupitia habari za wakati halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelewa na zawadi mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

## Msingi wa MacOS

Ikiwa haujazoea macOS, unapaswa kuanza kujifunza misingi ya macOS:

* **Faili na ruhusa za macOS:**

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

* **Mimaririko** ya **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Huduma na itifaki za mtandao za macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** ya macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Ili kupakua `tar.gz` badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM ya MacOS

Katika makampuni **mifumo ya macOS inaweza kuwa imepangiliwa kwa MDM**. Kwa hivyo, kutoka mtazamo wa mshambuliaji ni muhimu kujua **jinsi hiyo inavyofanya kazi**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Ukaguzi, Udukuzi na Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Kinga ya Usalama ya MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Eneo la Shambulizi

### Ruhusa za Faili

Ikiwa **mchakato unaoendeshwa kama root unahifadhi** faili ambayo inaweza kudhibitiwa na mtumiaji, mtumiaji anaweza kutumia hii kwa **kupandisha madaraka**.\
Hii inaweza kutokea katika hali zifuatazo:

* Faili iliyotumiwa tayari ilikuwa imeundwa na mtumiaji (inayomilikiwa na mtumiaji)
* Faili iliyotumiwa inaweza kuandikwa na mtumiaji kwa sababu ya kikundi
* Faili iliyotumiwa iko ndani ya saraka inayomilikiwa na mtumiaji (mtumiaji anaweza kuunda faili)
* Faili iliyotumiwa iko ndani ya saraka inayomilikiwa na root lakini mtumiaji ana ufikiaji wa kuandika juu yake kwa sababu ya kikundi (mtumiaji anaweza kuunda faili)

Uwezo wa **kuunda faili** ambayo itatumika na **root**, inaruhusu mtumiaji **kutumia maudhui yake** au hata kuunda **viungo vya ishara/viungo ngumu** kuielekeza mahali pengine.

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

Katika macOS **programu na programu za binary zinaweza kuwa na ruhusa** za kufikia folda au mipangilio ambayo inawafanya wawe na haki zaidi kuliko wengine.

Kwa hivyo, mshambuliaji anayetaka kudhoofisha kwa mafanikio kompyuta ya macOS atahitaji **kupandisha madaraka yake ya TCC** (au hata **kupuuza SIP**, kulingana na mahitaji yake).

Ruhusa hizi kawaida hupewa kwa mfumo wa **ruhusa** programu imesainiwa nazo, au programu inaweza kuomba baadhi ya ufikiaji na baada ya **mtumiaji kuidhinisha** wanaweza kupatikana katika **databases za TCC**. Njia nyingine mchakato unaweza kupata ruhusa hizi ni kwa kuwa **mtoto wa mchakato** na ruhusa hizo kwani kawaida **zinarithiwa**.

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

**Machapisho ya Udukuzi**\
Shiriki na maudhui yanayochimba kina katika msisimko na changamoto za udukuzi

**Taarifa za Udukuzi za Muda Halisi**\
Kaa sawa na ulimwengu wa udukuzi wenye kasi kupitia taarifa za muda halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelewa na tuzo za udhaifu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

{% hint style="success" %}
Jifunze & jifanye Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & jifanye Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
