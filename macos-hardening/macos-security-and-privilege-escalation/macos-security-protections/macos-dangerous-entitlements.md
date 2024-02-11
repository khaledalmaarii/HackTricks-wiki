# macOS Mamlaka Hatari na Ruhusa za TCC

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

{% hint style="warning" %}
Tafadhali kumbuka kuwa ruhusa zinazoanza na **`com.apple`** hazipatikani kwa watu wa tatu, Apple pekee ndiyo inaweza kuzitoa.
{% endhint %}

## Juu

### `com.apple.rootless.install.heritable`

Ruhusa ya **`com.apple.rootless.install.heritable`** inaruhusu **kipuuzi cha SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Ruhusa ya **`com.apple.rootless.install`** inaruhusu **kipuuzi cha SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (iliyokuwa inaitwa `task_for_pid-allow` hapo awali)**

Ruhusa hii inaruhusu kupata **bandari ya kazi kwa** mchakato wowote, isipokuwa kernel. Angalia [**hii kwa maelezo zaidi**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Ruhusa hii inaruhusu michakato mingine yenye ruhusa ya **`com.apple.security.cs.debugger`** kupata bandari ya kazi ya mchakato unaotekelezwa na programu-jalizi na **kuingiza namna ya kificho**. Angalia [**hii kwa maelezo zaidi**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Programu zenye Ruhusa ya Zana ya Kuhakiki zinaweza kuita `task_for_pid()` ili kupata bandari sahihi ya kazi kwa programu zisizo na saini na za watu wa tatu zenye ruhusa ya `Get Task Allow` iliyowekwa kuwa `kweli`. Walakini, hata na ruhusa ya zana ya kuhakiki, kuhakiki **hawezi kupata bandari za kazi** za michakato ambayo **haina ruhusa ya `Get Task Allow`**, na kwa hivyo inalindwa na Usalama wa Mfumo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Ruhusa hii inaruhusu **kupakia fremu, programu-jalizi, au maktaba bila kusainiwa na Apple au kusainiwa na Kitambulisho cha Timu ileile** kama programu kuu, kwa hivyo mshambuliaji anaweza kutumia upakiaji wa maktaba isiyojulikana kuingiza namna ya kificho. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ruhusa hii ni sawa sana na **`com.apple.security.cs.disable-library-validation`** lakini **badala yake** ya **kuzima moja kwa moja** uhakiki wa maktaba, inaruhusu mchakato kuita wito wa mfumo wa `csops` ili kuuzima.\
Angalia [**hii kwa maelezo zaidi**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Ruhusa hii inaruhusu **matumizi ya mazingira ya DYLD** ambayo yanaweza kutumika kuingiza maktaba na namna ya kificho. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blogi hii**](https://objective-see.org/blog/blog\_0x4C.html) **na** [**blogi hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ruhusa hizi zinaruhusu **kurekebisha** **database ya TCC**.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Ruhusa hizi zinaruhusu **kusanikisha programu bila kuomba ruhusa** ya mtumiaji, ambayo inaweza kuwa na manufaa kwa **kuongeza mamlaka**.

### `com.apple.private.security.kext-management`

Ruhusa inayohitajika kuomba **kernel kupakia kifaa cha kernel**.

### **`com.apple.private.icloud-account-access`**

Ruhusa ya **`com.apple.private.icloud-account-access`** inawezesha kuwasiliana na huduma ya XPC ya **`com.apple.iCloudHelper`** ambayo itatoa **vitambulisho vya iCloud**.

**iMovie** na **Garageband** walikuwa na ruhusa hii.

Kwa maelezo zaidi juu ya kudukua **vitambulisho vya icloud** kutoka kwa ruhusa hiyo, angalia mazungumzo: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui inaruhusu nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **inatajwa kuwa inaweza kutumika** kusasisha yaliyomo yaliyolindwa na SSV baada ya kuanza upya. Ikiwa unajua jinsi ya kutuma PR tafadhali tuma!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **inatajwa kuwa inaweza kutumika** kusasisha yaliyomo yaliyolindwa na SSV baada ya kuanza upya. Ikiwa unajua jinsi ya kutuma PR tafadhali tuma!

### `keychain-access-groups`

Ruhusa hii inaorodhesha vikundi vya **keychain** ambavyo programu ina ufikiaji wa:
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

Inatoa ruhusa za **Upatikanaji Kamili wa Diski**, moja ya ruhusa kubwa zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Inaruhusu programu kutuma matukio kwa programu nyingine ambazo mara nyingi hutumiwa kwa **kutumia taratibu za kiotomatiki**. Kwa kudhibiti programu nyingine, inaweza kutumia vibaya ruhusa zilizotolewa kwa programu hizo nyingine.

Kama vile kuwafanya waombe mtumiaji nywila yake:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Au kuwafanya wafanye **vitendo vya kiholela**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, miongoni mwa idhini zingine, **kuandika kwenye hifadhidata ya TCC ya watumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambaye anabadilisha njia ya folda yake ya nyumbani na hivyo kuruhusu **kupita TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kubadilisha faili ndani ya pakiti za programu (ndani ya app.app), ambayo kwa kawaida **imezuiwa kwa chaguo-msingi**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani anaye na ufikiaji huu katika _Mipangilio ya Mfumo_ > _Faragha na Usalama_ > _Usimamizi wa Programu._

### `kTCCServiceAccessibility`

Mchakato ataweza **kutumia vibaya huduma za upatikanaji wa macOS**, Ambayo inamaanisha kuwa kwa mfano ataweza kubonyeza herufi. Kwa hivyo anaweza kuomba ufikiaji wa kudhibiti programu kama Finder na kuidhinisha mazungumzo na idhini hii.

## Kati

### `com.apple.security.cs.allow-jit`

Idhini hii inaruhusu **kuunda kumbukumbu ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha bendera ya `MAP_JIT` kwa kazi ya mfumo ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Idhini hii inaruhusu **kubadilisha au kurekebisha msimbo wa C**, kutumia **`NSCreateObjectFileImageFromMemory`** (ambayo kimsingi ni tishio la usalama), au kutumia mfumo wa **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Kuingiza idhini hii kunafichua programu yako kwa udhaifu wa kawaida katika lugha za msimbo zisizo salama kwenye kumbukumbu. Tafakari kwa uangalifu ikiwa programu yako inahitaji msamaha huu.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Idhini hii inaruhusu **kubadilisha sehemu za faili zake za kutekelezwa** kwenye diski ili kufunga kwa nguvu. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Idhini ya Kuzuia Ulinzi wa Kumbukumbu ya Kutekelezwa ni idhini kali ambayo inaondoa ulinzi wa msingi wa usalama kutoka kwa programu yako, ikifanya iwezekane kwa mshambuliaji kubadilisha msimbo wa kutekelezwa wa programu yako bila kugunduliwa. Chagua idhini nyembamba ikiwa inawezekana.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Idhini hii inaruhusu kufunga mfumo wa faili wa nullfs (kwa kawaida imezuiwa kwa chaguo-msingi). Zana: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blogi, idhini hii ya TCC kawaida hupatikana kwa mfano:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato kuomba **ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
