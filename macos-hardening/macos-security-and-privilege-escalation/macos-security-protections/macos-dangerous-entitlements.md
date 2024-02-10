# macOS Opasna Ovlašćenja i TCC dozvole

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

{% hint style="warning" %}
Imajte na umu da ovlašćenja koja počinju sa **`com.apple`** nisu dostupna trećim licima, samo Apple može da ih dodeli.
{% endhint %}

## Visok

### `com.apple.rootless.install.heritable`

Ovlašćenje **`com.apple.rootless.install.heritable`** omogućava **zaobilaženje SIP-a**. Proverite [ovde za više informacija](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Ovlašćenje **`com.apple.rootless.install`** omogućava **zaobilaženje SIP-a**. Proverite [ovde za više informacija](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (ranije nazvano `task_for_pid-allow`)**

Ovo ovlašćenje omogućava dobijanje **task porta za bilo koji** proces, osim kernela. Proverite [**ovde za više informacija**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Ovo ovlašćenje omogućava drugim procesima sa ovlašćenjem **`com.apple.security.cs.debugger`** da dobiju task port procesa pokrenutog od strane binarnog fajla sa ovim ovlašćenjem i **ubace kod u njega**. Proverite [**ovde za više informacija**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplikacije sa ovlašćenjem za alat za debagovanje mogu pozvati `task_for_pid()` da dobiju validan task port za nepotpisane i aplikacije trećih lica sa ovlašćenjem `Get Task Allow` postavljenim na `true`. Međutim, čak i sa ovlašćenjem za alat za debagovanje, debager **ne može dobiti task portove** procesa koji **nemaju ovlašćenje `Get Task Allow`**, i koji su stoga zaštićeni Sistemskom Integritetnom Zaštitom. Proverite [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Ovo ovlašćenje omogućava **učitavanje framework-a, plug-inova ili biblioteka bez potpisa od strane Apple-a ili potpisanih istim Team ID-om** kao glavni izvršni fajl, tako da napadač može zloupotrebiti neko proizvoljno učitavanje biblioteke da ubaci kod. Proverite [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ovo ovlašćenje je veoma slično **`com.apple.security.cs.disable-library-validation`** ali umesto **direktnog onemogućavanja** provere biblioteke, omogućava procesu da **pozove `csops` sistemski poziv da je onemogući**.\
Proverite [**ovde za više informacija**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Ovo ovlašćenje omogućava **korišćenje DYLD okruženjskih promenljivih** koje se mogu koristiti za ubacivanje biblioteka i koda. Proverite [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ili `com.apple.rootless.storage`.`TCC`

[**Prema ovom blogu**](https://objective-see.org/blog/blog\_0x4C.html) **i** [**ovom blogu**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ova ovlašćenja omogućavaju **izmenu** TCC baze podataka.

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Ova ovlašćenja omogućavaju **instaliranje softvera bez traženja dozvole** od korisnika, što može biti korisno za eskalaciju privilegija.

### `com.apple.private.security.kext-management`

Ovlašćenje potrebno za traženje od kernela da učita kernel ekstenziju.

### **`com.apple.private.icloud-account-access`**

Ovlašćenje **`com.apple.private.icloud-account-access`** omogućava komunikaciju sa **`com.apple.iCloudHelper`** XPC servisom koji će **pružiti iCloud tokene**.

**iMovie** i **Garageband** imaju ovo ovlašćenje.

Za više **informacija** o eksploataciji za **dobijanje icloud tokena** iz tog ovlašćenja pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ne znam šta ovo omogućava

### `com.apple.private.apfs.revert-to-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se pominje da se ovo može koristiti za** ažuriranje SSV-zaštićenog sadržaja nakon restarta. Ako znate kako, pošaljite PR molim vas!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se pominje da se ovo može koristiti za** ažuriranje SSV-zaštićenog sadržaja nakon restarta. Ako znate kako, pošaljite PR molim vas!

### `keychain-access-groups`

Ova lista ovlašćenja prikazuje grupe **keychain-a** do kojih aplikacija ima pristup:
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

Daje dozvole za **puni pristup disku**, jednu od najviših dozvola TCC-a koje možete imati.

### **`kTCCServiceAppleEvents`**

Omogućava aplikaciji slanje događaja drugim aplikacijama koje se često koriste za **automatizaciju zadataka**. Kontrolisanjem drugih aplikacija, može zloupotrebiti dozvole koje su dodijeljene tim drugim aplikacijama.

Na primjer, može ih natjerati da zatraže korisnikovu lozinku:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ili ih naterati da izvrše **proizvoljne radnje**.

### **`kTCCServiceEndpointSecurityClient`**

Omogućava, između ostalih dozvola, **pisanje korisničke TCC baze podataka**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Omogućava **promenu** atributa **`NFSHomeDirectory`** korisnika koji menja putanju svoje matične fascikle i time omogućava **zaobilaženje TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Omogućava izmenu fajlova unutar aplikacija (unutar app.app), što je **podrazumevano zabranjeno**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Moguće je proveriti ko ima ovaj pristup u _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Proces će moći da **zloupotrebi macOS funkcije pristupačnosti**, što znači da će na primer moći da pritisne tastere. Tako bi mogao da zatraži pristup za kontrolu aplikacije poput Finder-a i odobri dijalog sa ovom dozvolom.

## Srednje

### `com.apple.security.cs.allow-jit`

Ova dozvola omogućava **kreiranje memorije koja je upisiva i izvršna** tako što se `MAP_JIT` zastavica prosleđuje sistemske funkcije `mmap()`. Proverite [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ova dozvola omogućava **zaobilaženje ili izmenu C koda**, korišćenje zastarelog **`NSCreateObjectFileImageFromMemory`** (koji je suštinski nesiguran), ili korišćenje **DVDPlayback** okvira. Proverite [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Uključivanje ove dozvole izlaže vašu aplikaciju uobičajenim ranjivostima u jezicima sa kodom koji nije siguran za memoriju. Pažljivo razmotrite da li vaša aplikacija zahteva ovu izuzetnost.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Ova dozvola omogućava **izmenu sekcija sopstvenih izvršnih fajlova** na disku kako bi se prinudno izašlo. Proverite [**ovde za više informacija**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Dozvola za onemogućavanje zaštite izvršne memorije je ekstremna dozvola koja uklanja osnovnu sigurnosnu zaštitu iz vaše aplikacije, čime se omogućava napadaču da izmeni izvršni kod vaše aplikacije bez otkrivanja. Ako je moguće, radije koristite uže dozvole.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ova dozvola omogućava montiranje nullfs fajl sistema (podrazumevano zabranjeno). Alatka: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Prema ovom blog postu, ova TCC dozvola se obično nalazi u obliku:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Dozvolite procesu da **zatraži sve TCC dozvole**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
