# macOS Dangerous Entitlements & TCC perms

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% hint style="warning" %}
Kumbuka kwamba entitlements zinazohusika na **`com.apple`** hazipatikani kwa wahusika wengine, ni Apple pekee inayoweza kuzitoa.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu **kuzidi SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu **kuzidi SIP**. Angalia [hii kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (iliyokuwa inaitwa `task_for_pid-allow`)**

Entitlement hii inaruhusu kupata **task port kwa mchakato wowote**, isipokuwa kernel. Angalia [**hii kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu michakato mingine yenye entitlement **`com.apple.security.cs.debugger`** kupata task port ya mchakato unaotendwa na binary yenye entitlement hii na **kuingiza msimbo ndani yake**. Angalia [**hii kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps zenye Entitlement ya Zana za Ufuatiliaji zinaweza kuita `task_for_pid()` ili kupata task port halali kwa apps zisizosainiwa na wahusika wengine zenye entitlement ya `Get Task Allow` iliyowekwa kuwa `true`. Hata hivyo, hata na entitlement ya zana za ufuatiliaji, mfuatiliaji **hawezi kupata task ports** za michakato ambazo **hazina entitlement ya `Get Task Allow`**, na hivyo kulindwa na Ulinzi wa Uadilifu wa Mfumo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu **kupakia frameworks, plug-ins, au maktaba bila kusainiwa na Apple au kusainiwa na Kitambulisho sawa na executable kuu**, hivyo mshambuliaji anaweza kutumia upakiaji wa maktaba fulani kuingiza msimbo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Entitlement hii ni sawa sana na **`com.apple.security.cs.disable-library-validation`** lakini **badala** ya **kuondoa** uthibitisho wa maktaba moja kwa moja, inaruhusu mchakato **kuita `csops` system call kuondoa**.\
Angalia [**hii kwa maelezo zaidi**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu **kutumia DYLD environment variables** ambazo zinaweza kutumika kuingiza maktaba na msimbo. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blog hii**](https://objective-see.org/blog/blog\_0x4C.html) **na** [**blog hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi zinaruhusu **kubadilisha** database ya **TCC**.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Entitlements hizi zinaruhusu **kufunga programu bila kuomba ruhusa** kwa mtumiaji, ambayo inaweza kuwa na manufaa kwa **kuinua mamlaka**.

### `com.apple.private.security.kext-management`

Entitlement inayohitajika kuomba **kernel kupakia nyongeza ya kernel**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** inaruhusu kuwasiliana na huduma ya XPC **`com.apple.iCloudHelper`** ambayo itatoa **tokens za iCloud**.

**iMovie** na **Garageband** zilikuwa na entitlement hii.

Kwa maelezo zaidi kuhusu exploit ya **kupata tokens za icloud** kutoka kwa entitlement hiyo angalia mazungumzo: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imeelezwa kuwa hii inaweza kutumika** kuboresha yaliyomo yaliyolindwa na SSV baada ya kuanzisha upya. Ikiwa unajua jinsi inavyofanya, tafadhali tuma PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imeelezwa kuwa hii inaweza kutumika** kuboresha yaliyomo yaliyolindwa na SSV baada ya kuanzisha upya. Ikiwa unajua jinsi inavyofanya, tafadhali tuma PR!

### `keychain-access-groups`

Entitlement hii inataja **makundi ya keychain** ambayo programu ina ufikiaji:
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

Inatoa ruhusa za **Upatikanaji Kamili wa Diski**, moja ya ruhusa za juu zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Inaruhusu programu kutuma matukio kwa programu nyingine ambazo mara nyingi hutumiwa kwa **kujiendesha kazi**. Kwa kudhibiti programu nyingine, inaweza kutumia vibaya ruhusa zilizotolewa kwa programu hizi nyingine.

Kama kufanya ziombwe mtumiaji kwa nywila yake: 

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Au kufanya ziweze kutekeleza **vitendo vya kiholela**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, miongoni mwa ruhusa nyingine, **kuandika kwenye hifadhidata ya TCC ya watumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo inabadilisha njia ya folda yake ya nyumbani na hivyo inaruhusu **kuepuka TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kubadilisha faili ndani ya pakiti za programu (ndani ya app.app), ambayo **imezuiliwa kwa chaguo-msingi**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani mwenye ufikiaji huu katika _Mipangilio ya Mfumo_ > _Faragha & Usalama_ > _Usimamizi wa Programu._

### `kTCCServiceAccessibility`

Mchakato utaweza **kutumia vipengele vya upatikanaji wa macOS**, ambayo inamaanisha kwamba kwa mfano ataweza kubonyeza funguo. Hivyo anaweza kuomba ufikiaji wa kudhibiti programu kama Finder na kuidhinisha mazungumzo na ruhusa hii.

## Kati

### `com.apple.security.cs.allow-jit`

Ruhusa hii inaruhusu **kuunda kumbukumbu ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha bendera ya `MAP_JIT` kwa kazi ya mfumo ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ruhusa hii inaruhusu **kufunika au kurekebisha msimbo wa C**, kutumia **`NSCreateObjectFileImageFromMemory`** ambayo imekuwa ikitumiwa kwa muda mrefu (ambayo kimsingi si salama), au kutumia mfumo wa **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Kujumuisha ruhusa hii kunafichua programu yako kwa udhaifu wa kawaida katika lugha za msimbo zisizo salama. Fikiria kwa makini ikiwa programu yako inahitaji ubaguzi huu.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Ruhusa hii inaruhusu **kubadilisha sehemu za faili zake za kutekeleza** kwenye diski ili kutoka kwa nguvu. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Ruhusa ya Kuondoa Ulinzi wa Kumbukumbu ya Kutekeleza ni ruhusa kali ambayo inatoa ulinzi wa msingi wa usalama kutoka kwa programu yako, ikifanya iwezekane kwa mshambuliaji kuandika upya msimbo wa kutekeleza wa programu yako bila kugundulika. Prefer ruhusa nyembamba ikiwa inawezekana.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ruhusa hii inaruhusu kuunganisha mfumo wa faili wa nullfs (uliokatazwa kwa chaguo-msingi). Chombo: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blog, ruhusa hii ya TCC kwa kawaida hupatikana katika mfumo:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato **kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**
{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
</details>
