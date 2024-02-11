# Vipengele vya Kernel vya macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya la PEASS au kupakua HackTricks kwa muundo wa PDF**? Tazama [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu maalum wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS na HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord** au [**kikundi cha Telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Shiriki mbinu zako za kudukua kwa kutuma PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Taarifa Msingi

Vipengele vya kernel (Kexts) ni **paki** zenye kipengele cha **`.kext`** ambazo **zinaingizwa moja kwa moja katika nafasi ya kernel ya macOS**, zikitoa utendaji zaidi kwa mfumo wa uendeshaji kuu.

### Mahitaji

Kwa wazi, hii ni nguvu sana hivyo ni **ngumu kuweka kipengele cha kernel**. Haya ndiyo **mahitaji** ambayo kipengele cha kernel lazima kikidhi ili kiweze kuingizwa:

* Wakati wa **kuingia kwenye hali ya kupona**, kernel **inapaswa kuruhusu** kipengele cha kernel kiingizwe:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Kipengele cha kernel lazima kiwe **kimesainiwa na cheti cha usaini wa nambari ya kernel**, ambacho kinaweza tu **kutolewa na Apple**. Ambayo itakagua kwa undani kampuni na sababu za kuhitajika kwake.
* Kipengele cha kernel pia lazima kiwe **kimethibitishwa**, Apple itaweza kukagua ikiwa kina programu hasidi.
* Kisha, mtumiaji wa **root** ndiye anayeweza **kuweka kipengele cha kernel** na faili ndani ya pakiti lazima **ziwe za mmiliki root**.
* Wakati wa mchakato wa kupakia, pakiti lazima iandaliwe katika eneo la **ulinzi lisilokuwa la root**: `/Library/StagedExtensions` (inahitaji idhini ya `com.apple.rootless.storage.KernelExtensionManagement`).
* Hatimaye, wakati wa kujaribu kuipakia, mtumiaji atapokea [**ombi la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) na, ikiwa itakubaliwa, kompyuta lazima **izime na kuipakia**.

### Mchakato wa Kupakia

Katika Catalina ilikuwa hivi: Ni muhimu kufahamu kuwa mchakato wa **uthibitisho** unatokea katika **userland**. Walakini, programu tu zenye idhini ya **`com.apple.private.security.kext-management`** ndizo zinaweza **kuomba kernel kuweka kipengele**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inaanza** mchakato wa **uthibitisho** wa kupakia kipengele
* Itazungumza na **`kextd`** kwa kutuma kwa kutumia **huduma ya Mach**.
2. **`kextd`** itachunguza mambo kadhaa, kama vile **saini**
* Itazungumza na **`syspolicyd`** kuangalia ikiwa kipengele kinaweza **kupakiwa**.
3. **`syspolicyd`** ita**omba** **mtumiaji** ikiwa kipengele hakijapakiwa hapo awali.
* **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. Hatimaye, **`kextd`** itaweza **kuambia kernel kuweka** kipengele

Ikiwa **`kextd`** haipo, **`kextutil`** inaweza kufanya ukaguzi sawa.

## Marejeo

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya la PEASS au kupakua HackTricks kwa muundo wa PDF**? Tazama [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu maalum wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS na HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord** au [**kikundi cha Telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Shiriki mbinu zako za kudukua kwa kutuma PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
