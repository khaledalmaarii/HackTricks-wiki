# macOS Dangerous Entitlements & TCC perms

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

{% hint style="warning" %}
Tafadhali kumbuka kuwa vibali vinavyoanza na **`com.apple`** havipatikani kwa watu wa tatu, ni Apple pekee inayoweza kuviruhusu.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

Kibali cha **`com.apple.rootless.install.heritable`** kuruhusu **kipuuzie SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Kibali cha **`com.apple.rootless.install`** kuruhusu **kipuuzie SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (hapo awali ilikuwa inaitwa `task_for_pid-allow`)**

Kibali hiki kuruhusu kupata **bandari ya kazi kwa** mchakato wowote, isipokuwa kernel. Angalia [**hii kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Kibali hiki kuruhusu michakato mingine yenye kibali cha **`com.apple.security.cs.debugger`** kupata bandari ya kazi ya mchakato unaorushwa na binary yenye kibali hiki na **kuingiza namna ya kificho**. Angalia [**hii kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Programu zenye Kibali cha Zana ya Udukuzi zinaweza kuita `task_for_pid()` kupata bandari sahihi ya kazi kwa programu zisizo na saini na programu za watu wa tatu zenye kibali cha `Get Task Allow` kilichowekwa kuwa `kweli`. Hata hivyo, hata na kibali cha zana ya udukuzi, mchambuzi **hawezi kupata bandari za kazi** za michakato ambayo **haina kibali cha `Get Task Allow`**, na hivyo kulindwa na Usalama wa Mfumo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Kibali hiki kuruhusu **kupakia fremu, programu-jalizi, au maktaba bila kuwa ime saini na Apple au kusainiwa na Kitambulisho cha Timu ileile** kama faili kuu, hivyo muhusika anaweza kutumia upakiaji wa maktaba wa kiholela kuingiza kificho. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Kibali hiki ni sawa sana na **`com.apple.security.cs.disable-library-validation`** lakini **badala yake** ya **kuzima moja kwa moja** uthibitishaji wa maktaba, inaruhusu mchakato huo **kuita wito wa mfumo wa `csops` kuzima huo**.\
Angalia [**hii kwa maelezo zaidi**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Kibali hiki kuruhusu **matumizi ya mazingira ya DYLD** ambayo yanaweza kutumika kuingiza maktaba na kificho. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[Kulingana na blogi hii](https://objective-see.org/blog/blog\_0x4C.html) **na** [**blogi hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), vibali hivi huruhusu **kurekebisha** **TCC** database.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Vibali hivi huruhusu **kusanikisha programu bila kuomba ruhusa** kwa mtumiaji, ambayo inaweza kuwa na manufaa kwa **kuongeza mamlaka**.

### `com.apple.private.security.kext-management`

Kibali kinachohitajika kuomba **kernel kupakia kifurushi cha kernel**.

### **`com.apple.private.icloud-account-access`**

Kibali cha **`com.apple.private.icloud-account-access`** inawezekana kuwasiliana na huduma ya XPC ya **`com.apple.iCloudHelper`** ambayo itatoa **vibali vya iCloud**.

**iMovie** na **Garageband** walikuwa na kibali hiki.

Kwa maelezo zaidi kuhusu udukuzi wa **kupata vibali vya iCloud** kutoka kwa kibali hicho, angalia mazungumzo: [**#OBTS v5.0: "Nini Kinatokea kwenye Mac yako, Kinabaki kwenye iCloud ya Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **inasemwa kuwa hii inaweza kutumika** kuboresha maudhui yaliyolindwa na SSV baada ya kuanza upya. Ikiwa unajua jinsi ya kufanya hivyo, tafadhali wasilisha PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **inasemwa kuwa hii inaweza kutumika** kuboresha maudhui yaliyolindwa na SSV baada ya kuanza upya. Ikiwa unajua jinsi ya kufanya hivyo, tafadhali wasilisha PR!

### `keychain-access-groups`

Kibali hiki orodha ya **vikundi vya keychain** ambavyo programu ina ufikiaji:

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

Inaruhusu programu kutuma matukio kwa programu nyingine ambazo mara nyingi hutumiwa kwa **kazi za kiotomatiki**. Kwa kudhibiti programu nyingine, inaweza kutumia vibaya ruhusa zilizotolewa kwa programu nyingine hizo.

Kama vile kuwafanya waulize mtumiaji nywila yake:

```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```

Au kuwafanya wafanye **vitendo vya kupindukia**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, miongoni mwa idhini zingine, **kuandika katika database ya TCC ya watumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo inabadilisha njia ya folda yake ya nyumbani na hivyo kuruhusu **kupita TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kuhariri faili ndani ya vifurushi vya programu (ndani ya app.app), ambayo ni **hairuhusiwi kwa chaguo-msingi**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani anaye ruhusa hii katika _Mipangilio ya Mfumo_ > _Faragha & Usalama_ > _Usimamizi wa Programu._

### `kTCCServiceAccessibility`

Mchakato ataweza **kutumia vibaya vipengele vya upatikanaji wa macOS**, Hii inamaanisha kuwa kwa mfano ataweza kubonyeza funguo. HIVYO anaweza kuomba upatikanaji wa kudhibiti programu kama Finder na kuidhinisha dirisha hilo na ruhusa hii.

## Kati

### `com.apple.security.cs.allow-jit`

Ruhusa hii inaruhusu **kuunda kumbukumbu ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha bendera ya `MAP_JIT` kwa kazi ya mfumo ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ruhusa hii inaruhusu **kubadilisha au kufuta msimbo wa C**, kutumia **`NSCreateObjectFileImageFromMemory`** (ambayo ni hatari kimsingi), au kutumia fremu ya **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Kuingiza ruhusa hii kunafunua programu yako kwa mapungufu ya kawaida katika lugha za msimbo zisizo salama kumbukumbu. Tafakari kwa uangalifu ikiwa programu yako inahitaji kibali hiki.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Ruhusa hii inaruhusu **kubadilisha sehemu za faili zake za kutekelezeka** kwenye diski kwa kutoka kwa nguvu. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Ruhusa ya Kulemaza Ulinzi wa Kumbukumbu ya Kutekelezeka ni ruhusa ya kipekee ambayo inaondoa ulinzi wa msingi wa usalama kutoka kwa programu yako, ikifanya iwezekane kwa mshambuliaji kubadilisha msimbo wa kutekelezeka wa programu yako bila kugunduliwa. Penda ruhusa nyembamba ikiwezekana.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ruhusa hii inaruhusu kufunga mfumo wa faili wa nullfs (ulioruhusiwa kwa chaguo-msingi). Zana: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blogi, ruhusa hii ya TCC kawaida hupatikana katika mfumo:

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
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
