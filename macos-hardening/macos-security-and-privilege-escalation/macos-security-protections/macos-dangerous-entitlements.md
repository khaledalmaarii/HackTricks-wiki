# macOS Gevaarlike Toekennings & TCC-permissies

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

{% hint style="warning" %}
Let daarop dat toekennings wat begin met **`com.apple`** nie beskikbaar is vir derde partye nie, slegs Apple kan dit toeken.
{% endhint %}

## Hoog

### `com.apple.rootless.install.heritable`

Die toekenning **`com.apple.rootless.install.heritable`** maak dit moontlik om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die toekenning **`com.apple.rootless.install`** maak dit moontlik om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (voorheen genoem `task_for_pid-allow`)**

Hierdie toekenning maak dit moontlik om die **taakpoort vir enige** proses te kry, behalwe die kernel. Kyk [**hier vir meer inligting**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Hierdie toekenning maak dit moontlik vir ander prosesse met die **`com.apple.security.cs.debugger`** toekenning om die taakpoort van die proses wat deur die binêre lêer met hierdie toekenning uitgevoer word, te kry en **kode daarin in te spuit**. Kyk [**hier vir meer inligting**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Toekenning kan `task_for_pid()` roep om 'n geldige taakpoort vir ongetekende en derde party apps met die `Get Task Allow` toekenning wat op `true` gestel is, te kry. Selfs met die debugging tool toekenning kan 'n debugger **nie die taakpoorte** van prosesse kry wat **nie die `Get Task Allow` toekenning het nie**, en wat dus deur System Integrity Protection beskerm word. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Hierdie toekenning maak dit moontlik om **raamwerke, invoegtoepassings of biblioteke te laai sonder dat dit deur Apple onderteken is of met dieselfde Team ID onderteken is** as die hoofuitvoerbare lêer, sodat 'n aanvaller 'n willekeurige biblioteek kan misbruik om kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Hierdie toekenning is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`**, maar **in plaas daarvan** om biblioteekvalidering **direk uit te skakel**, maak dit dit vir die proses moontlik om 'n `csops`-sisteemaanroep te doen om dit uit te skakel.\
Kyk [**hier vir meer inligting**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie toekenning maak dit moontlik om **DYLD-omgewingsveranderlikes te gebruik** wat gebruik kan word om biblioteke en kode in te spuit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` of `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog\_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), maak hierdie toekenning dit moontlik om die **TCC** databasis te **verander**.

### **`system.install.apple-software`** en **`system.install.apple-software.standar-user`**

Hierdie toekenning maak dit moontlik om sagteware te **installeer sonder om toestemming van die gebruiker te vra**, wat nuttig kan wees vir 'n **privilege-escalation**.

### `com.apple.private.security.kext-management`

Toekenning wat nodig is om die **kernel te vra om 'n kernel-uitbreiding te laai**.

### **`com.apple.private.icloud-account-access`**

Die toekenning **`com.apple.private.icloud-account-access`** maak dit moontlik om te kommunikeer met die **`com.apple.iCloudHelper`** XPC-diens wat **iCloud-token** sal voorsien.

**iMovie** en **Garageband** het hierdie toekenning gehad.

Vir meer **inligting** oor die uitbuiting om **icloud-tokens te kry** van daardie toekenning, kyk na die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die inhoud wat deur SSV beskerm word, na 'n herlaai te werk. As jy weet hoe om dit te doen, stuur asseblief 'n PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die inhoud wat deur SSV beskerm word, na 'n herlaai te werk. As jy weet hoe om dit te doen, stuur asseblief 'n PR!

### `keychain-access-groups`

Hierdie toekenning lys **sleutelbosgroepe** waartoe die aansoek toegang het:
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

Geeft **Volledige Schijftoegang** machtigingen, een van de hoogste machtigingen die je kunt hebben in TCC.

### **`kTCCServiceAppleEvents`**

Staat de app toe om gebeurtenissen naar andere applicaties te sturen die vaak worden gebruikt voor **automatiseringstaken**. Door andere apps te controleren, kan het misbruik maken van de verleende machtigingen aan deze andere apps.

Zoals het vragen van het wachtwoord aan de gebruiker:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Of maak hulle om **willekeurige aksies** uit te voer.

### **`kTCCServiceEndpointSecurityClient`**

Laat onder andere toe om die gebruikers TCC-databasis te **skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`** eienskap van 'n gebruiker te **verander** wat sy tuisgids-pad verander en dus om TCC te **omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne app-bundels (binne app.app) te wysig, wat **standaard verbied** is.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om te kontroleer wie hierdie toegang het in _Sisteeminstellings_ > _Privaatheid & Sekuriteit_ > _App-bestuur_.

### `kTCCServiceAccessibility`

Die proses sal in staat wees om die macOS-toeganklikheidskenmerke te **misbruik**, wat beteken dat hy byvoorbeeld toetsaanslae kan indruk. Hy kan dus toegang aanvra om 'n app soos Finder te beheer en die dialoogvenster met hierdie toestemming goed te keur.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie toekenning maak dit moontlik om geheue te **skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT` vlag aan die `mmap()` stelsel funksie te gee. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie toekenning maak dit moontlik om C-kode te **oorheers of te herstel**, gebruik die lank verouderde **`NSCreateObjectFileImageFromMemory`** (wat fundamenteel onveilig is), of gebruik die **DVDPlayback** raamwerk. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Die insluiting van hierdie toekenning stel jou app bloot aan algemene kwesbaarhede in geheue-onveilige kodelanguages. Oorweeg versigtig of jou app hierdie uitsondering nodig het.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie toekenning maak dit moontlik om **dele van sy eie uitvoerbare lêers** op skyf te wysig om kragtig te beëindig. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Die Uitskakelbare Uitvoerbare Geheuebeskerming Toekenning is 'n ekstreme toekenning wat 'n fundamentele sekuriteitsbeskerming van jou app verwyder, wat dit vir 'n aanvaller moontlik maak om jou app se uitvoerbare kode sonder opsporing te herskryf. Gee verkieslik nouer toekenning as moontlik.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie toekenning maak dit moontlik om 'n nullfs-lêersisteem te monteer (standaard verbode). Hulpmiddel: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpos, word hierdie TCC-toestemming gewoonlik in die vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses toe om **vir alle TCC-toestemmings te vra**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
