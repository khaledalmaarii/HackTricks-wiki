# Mipangilio Hatari ya macOS & Ruhusa za TCC

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

{% hint style="warning" %}
Tafadhali kumbuka kuwa mipangilio inayoanza na **`com.apple`** haipatikani kwa watu wa tatu, Apple pekee ndiyo wanaweza kutoa.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

Mipangilio ya **`com.apple.rootless.install.heritable`** inaruhusu **kupuuza SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Mipangilio ya **`com.apple.rootless.install`** inaruhusu **kupuuza SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (hapo awali ilikuwa inaitwa `task_for_pid-allow`)**

Mipangilio hii inaruhusu kupata **bandari ya kazi kwa** mchakato wowote, isipokuwa kernel. Angalia [**hii kwa maelezo zaidi**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Mipangilio hii inaruhusu michakato mingine yenye mamlaka ya **`com.apple.security.cs.debugger`** kupata bandari ya kazi ya mchakato unaorushwa na binary yenye mamlaka hii na **kuingiza nambari ndani yake**. Angalia [**hii kwa maelezo zaidi**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Programu zenye Mamlaka ya Zana ya Uchunguzi zinaweza kuita `task_for_pid()` kupata bandari sahihi ya kazi kwa programu zisizo na saini na za watu wa tatu zenye mamlaka ya `Get Task Allow` iliyowekwa kuwa `kweli`. Hata hivyo, hata na mamlaka ya zana ya uchunguzi, mchunguzi **hawezi kupata bandari za kazi** za michakato ambayo **haina mamlaka ya `Get Task Allow`**, na hivyo kulindwa na Ulinzi wa Mfumo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Mipangilio hii inaruhusu **kupakia fremu, programu-jalizi, au maktaba bila kuwa zimesainiwa na Apple au zimesainiwa na Kitambulisho cha Timu sawa** na kutekelezaji kuu, hivyo mshambuliaji anaweza kutumia upakiaji wa maktaba wa kiholela kuingiza nambari. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Mipangilio hii inafanana sana na **`com.apple.security.cs.disable-library-validation`** lakini **badala yake** ya **kulemaza moja kwa moja** uthibitishaji wa maktaba, inaruhusu mchakato huo **kuita wito wa mfumo wa `csops` kulemaza**.\
Angalia [**hii kwa maelezo zaidi**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Mipangilio hii inaruhusu **matumizi ya mazingira ya DYLD** ambayo yanaweza kutumika kuingiza maktaba na nambari. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[Kulingana na blogi hii](https://objective-see.org/blog/blog\_0x4C.html) **na** [blogi hii](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), mipangilio hii inaruhusu **kurekebisha** **database ya TCC**.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Mipangilio hii inaruhusu **kusanikisha programu bila kuomba idhini** ya mtumiaji, ambayo inaweza kuwa na manufaa kwa **kuongeza mamlaka**.

### `com.apple.private.security.kext-management`

Mipangilio inayohitajika kuomba **kernel kupakia kifurushi cha kernel**.

### **`com.apple.private.icloud-account-access`**

Mipangilio ya **`com.apple.private.icloud-account-access`** inawezesha mawasiliano na huduma ya XPC ya **`com.apple.iCloudHelper`** ambayo itatoa **vitambulisho vya iCloud**.

**iMovie** na **Garageband** walikuwa na mamlaka haya.

Kwa maelezo zaidi kuhusu udanganyifu wa **kupata vitambulisho vya iCloud** kutoka kwa mamlaka hiyo, angalia mazungumzo: [**#OBTS v5.0: "Nini Kinatokea kwenye Mac yako, Kinabaki kwenye iCloud ya Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **inasemwa kuwa inaweza kutumika** kuboresha maudhui yaliyolindwa na SSV baada ya kuanza upya. Ikiwa unajua jinsi ya kufanya hivyo, tafadhali wasilisha PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **inasemwa kuwa inaweza kutumika** kuboresha maudhui yaliyolindwa na SSV baada ya kuanza upya. Ikiwa unajua jinsi ya kufanya hivyo, tafadhali wasilisha PR!

### `keychain-access-groups`

Mipangilio hii inaorodhesha vikundi vya **keychain** ambavyo programu ina ufikiaji:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Inatoa ruhusa ya **Upatikanaji Kamili wa Diski**, moja ya ruhusa kubwa zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Inaruhusu programu kutuma matukio kwa programu nyingine ambazo mara nyingi hutumiwa kwa ajili ya **kutautomatisha kazi**. Kwa kudhibiti programu nyingine, inaweza kutumia vibaya ruhusa zilizotolewa kwa programu hizo nyingine.

Kama vile kuwafanya waulize mtumiaji nywila yake:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Au kuwafanya wafanye **vitendo vya kupindukia**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, miongoni mwa idhini zingine, **kuandika katika database ya watumiaji ya TCC**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo inabadilisha njia ya folda yake ya nyumbani na hivyo kuruhusu **kupita TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kuhariri faili ndani ya vifurushi vya programu (ndani ya app.app), ambayo ni **hairuhusiwi kwa chaguo-msingi**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani anaye ruhusa hii katika _Mipangilio ya Mfumo_ > _Faragha & Usalama_ > _Usimamizi wa Programu._

### `kTCCServiceAccessibility`

Mchakato ataweza **kutumia vibaya vipengele vya upatikanaji wa macOS**, Hii inamaanisha kuwa kwa mfano ataweza kubonyeza funguo. HIVYO anaweza kuomba upatikanaji wa kudhibiti programu kama Finder na kuidhinisha dirisha na ruhusa hii.

## Kati

### `com.apple.security.cs.allow-jit`

Ruhusa hii inaruhusu **kuunda kumbukumbu ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha bendera ya `MAP_JIT` kwa kazi ya mfumo ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ruhusa hii inaruhusu **kubadilisha au kufanya marekebisho ya msimbo wa C**, kutumia **`NSCreateObjectFileImageFromMemory`** (ambayo ni hatari kimsingi), au kutumia fremu ya **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Kuingiza ruhusa hii kunafunua programu yako kwa mapungufu ya kawaida katika lugha za msimbo zisizo salama kumbukumbu. Tafakari kwa uangalifu ikiwa programu yako inahitaji kibali hiki.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Ruhusa hii inaruhusu **kubadilisha sehemu za faili zake za kutekelezeka** kwenye diski kwa kufunga kwa lazima. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Ruhusa ya Kulemaza Ulinzi wa Kumbukumbu ya Kutekelezeka ni ruhusa ya kipekee inayondoa ulinzi wa msingi wa usalama kutoka kwa programu yako, ikifanya iwezekane kwa mshambuliaji kubadilisha msimbo wa kutekelezeka wa programu yako bila kugunduliwa. Penda ruhusa nyembamba ikiwezekana.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ruhusa hii inaruhusu kufunga mfumo wa faili wa nullfs (ulioruhusiwa kwa chaguo-msingi). Zana: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blogu, ruhusa hii ya TCC kawaida hupatikana kwa mfumo:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato kuomba **ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
