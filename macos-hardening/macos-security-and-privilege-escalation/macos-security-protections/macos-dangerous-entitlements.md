# macOS Gevaarlike Toestemmings & TCC-permissies

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

{% hint style="warning" %}
Let daarop dat toestemmings wat begin met **`com.apple`** nie beskikbaar is vir derdepartye nie, slegs Apple kan dit toeken.
{% endhint %}

## Hoë

### `com.apple.rootless.install.heritable`

Die toestemming **`com.apple.rootless.install.heritable`** maak dit moontlik om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die toestemming **`com.apple.rootless.install`** maak dit moontlik om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (voorheen genoem `task_for_pid-allow`)**

Hierdie toestemming maak dit moontlik om die **taakpoort vir enige** proses te kry, behalwe die kernel. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Hierdie toestemming maak dit vir ander prosesse met die **`com.apple.security.cs.debugger`** toestemming moontlik om die taakpoort van die proses wat deur die binêre lêer met hierdie toestemming uitgevoer word, te kry en **kode daarop in te spuit**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Toestemming kan `task_for_pid()` aanroep om 'n geldige taakpoort vir ondertekende en derdeparty-apps met die `Get Task Allow` toestemming wat op `waar` is, te kry. Selfs met die debugging tool toestemming kan 'n debugger **nie die taakpoorte kry** van prosesse wat **nie die `Get Task Allow` toestemming het nie**, en wat dus beskerm word deur die Sisteem Integriteitsbeskerming. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Hierdie toestemming maak dit moontlik om **raamwerke, invoegtoepassings, of biblioteke te laai sonder om deur Apple onderteken te wees of met dieselfde Span-ID as die hoofuitvoerbare lêer onderteken te wees**, sodat 'n aanvaller 'n arbitêre biblioteeklas kan misbruik om kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Hierdie toestemming is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`** maar **in plaas daarvan** om biblioteekvalidering direk uit te skakel, maak dit dit vir die proses moontlik om 'n `csops` stelseloproep aan te roep om dit uit te skakel.\
Kyk [**hier vir meer inligting**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie toestemming maak dit moontlik om **DYLD-omgewingsveranderlikes** te gebruik wat gebruik kan word om biblioteke en kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` of `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog\_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), maak hierdie toestemmings dit moontlik om die **TCC** databasis te **verander**.

### **`system.install.apple-software`** en **`system.install.apple-software.standar-user`**

Hierdie toestemmings maak dit moontlik om sagteware te **installeer sonder om toestemming van die gebruiker te vra**, wat nuttig kan wees vir 'n **privilege-escalation**.

### `com.apple.private.security.kext-management`

Toestemming wat nodig is om die **kernel te vra om 'n kernel-uitbreiding te laai**.

### **`com.apple.private.icloud-account-access`**

Die toestemming **`com.apple.private.icloud-account-access`** maak dit moontlik om te kommunikeer met die **`com.apple.iCloudHelper`** XPC-diens wat **iCloud-token** sal voorsien.

**iMovie** en **Garageband** het hierdie toestemming.

Vir meer **inligting** oor die uitbuiting om **iCloud-tokens te kry** van daardie toestemming, kyk na die gesprek: [**#OBTS v5.0: "Wat Gebeur op jou Mac, Bly op Apple se iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud na 'n herlaai op te dateer. As jy weet hoe, stuur asseblief 'n PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud na 'n herlaai op te dateer. As jy weet hoe, stuur asseblief 'n PR!

### `keychain-access-groups`

Hierdie toestemming lys **sleutelhangergroepe** waarop die aansoek toegang het:
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

Gee **Volle Skyftoegang** toestemmings, een van die hoogste TCC-toestemmings wat jy kan hê.

### **`kTCCServiceAppleEvents`**

Laat die app toe om gebeure na ander toepassings te stuur wat gewoonlik gebruik word vir **outomatiese take**. Deur ander programme te beheer, kan dit misbruik maak van die toestemmings wat aan hierdie ander programme verleen is.

Soos om hulle die gebruiker vir sy wagwoord te laat vra:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Of maak hulle **willekeurige aksies** uitvoer.

### **`kTCCServiceEndpointSecurityClient`**

Laat, onder andere toestemmings, toe om die gebruikers TCC-databasis **te skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`** attribuut van 'n gebruiker te **verander** wat sy tuisvouerpad verander en dus toelaat om TCC **te omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne app-bundels te wysig (binne app.app), wat **standaard nie toegelaat is**.

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om te kontroleer wie hierdie toegang het in _Sisteeminstellings_ > _Privaatheid & Sekuriteit_ > _App-bestuur_.

### `kTCCServiceAccessibility`

Die proses sal in staat wees om die macOS-toeganklikheidskenmerke **te misbruik**, wat beteken dat hy byvoorbeeld toetsaanslae kan indruk. Hy kan dus toegang aanvra om 'n app soos Finder te beheer en die dialoog met hierdie toestemming goed te keur.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie toestemming laat toe om **geheue te skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT` vlag na die `mmap()`-sisteemfunksie te stuur. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie toestemming laat toe om C-kode te **oorheers of te lap**, gebruik die lank verouderde **`NSCreateObjectFileImageFromMemory`** (wat fundamenteel onveilig is), of gebruik die **DVDPlayback**-raamwerk. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Die insluiting van hierdie toestemming stel jou app bloot aan algemene kwesbaarhede in geheue-onveilige kodes. Oorweeg sorgvuldig of jou app hierdie uitsondering nodig het.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie toestemming laat toe om **afsnitte van sy eie uitvoerbare lêers** op skyf te wysig om kragtig te verlaat. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Die Uitskakelbare Uitvoerbare Geheuebeskermingstoestemming is 'n ekstreme toestemming wat 'n fundamentele sekuriteitsbeskerming van jou app verwyder, wat dit moontlik maak vir 'n aanvaller om jou app se uitvoerbare kodes sonder opsporing te herskryf. Gee verkieslik nouer toestemmings indien moontlik.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie toestemming laat toe om 'n nullfs-lêersisteem te koppel (standaard verbode). Gereedskap: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpos, hierdie TCC-toestemming word gewoonlik gevind in die vorm:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses toe om **vir al die TCC-toestemmings te vra**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
