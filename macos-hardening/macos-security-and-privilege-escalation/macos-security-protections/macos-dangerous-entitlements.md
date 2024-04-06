# macOS Dangerous Entitlements & TCC perms

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

{% hint style="warning" %}
Nota che i permessi che iniziano con **`com.apple`** non sono disponibili per terze parti, solo Apple può concederli.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

Il permesso **`com.apple.rootless.install.heritable`** consente di **bypassare SIP**. Controlla [questo per ulteriori informazioni](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Il permesso **`com.apple.rootless.install`** consente di **bypassare SIP**. Controlla [questo per ulteriori informazioni](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (precedentemente chiamato `task_for_pid-allow`)**

Questo permesso consente di ottenere la **porta del task per qualsiasi** processo, tranne il kernel. Controlla [**questo per ulteriori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Questo permesso consente ad altri processi con il permesso **`com.apple.security.cs.debugger`** di ottenere la porta del task del processo eseguito dal binario con questo permesso e **iniettare codice su di esso**. Controlla [**questo per ulteriori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Le app con il Permesso Strumento di Debug possono chiamare `task_for_pid()` per recuperare una porta del task valida per app non firmate e di terze parti con il permesso `Get Task Allow` impostato su `true`. Tuttavia, anche con il permesso dello strumento di debug, un debugger **non può ottenere le porte del task** dei processi che **non hanno il permesso `Get Task Allow`**, e che sono quindi protetti da System Integrity Protection. Controlla [**questo per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Questo permesso consente di **caricare framework, plug-in o librerie senza essere né firmati da Apple né firmati con lo stesso ID del Team** dell'eseguibile principale, quindi un attaccante potrebbe abusare di un caricamento arbitrario di librerie per iniettare codice. Controlla [**questo per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Questo permesso è molto simile a **`com.apple.security.cs.disable-library-validation`** ma **invece** di **disabilitare direttamente** la convalida delle librerie, consente al processo di **chiamare una chiamata di sistema `csops` per disabilitarla**.\
Controlla [**questo per ulteriori informazioni**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Questo permesso consente di **utilizzare le variabili di ambiente DYLD** che potrebbero essere utilizzate per iniettare librerie e codice. Controlla [**questo per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Secondo questo blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**questo blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), questi permessi consentono di **modificare** il **database TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Questi permessi consentono di **installare software senza chiedere autorizzazioni** all'utente, il che può essere utile per una **escalation dei privilegi**.

### `com.apple.private.security.kext-management`

Permesso necessario per chiedere al **kernel di caricare un'estensione del kernel**.

### **`com.apple.private.icloud-account-access`**

Il permesso **`com.apple.private.icloud-account-access`** consente di comunicare con il servizio XPC **`com.apple.iCloudHelper`** che **fornirà token iCloud**.

**iMovie** e **Garageband** avevano questo permesso.

Per ulteriori **informazioni** sull'exploit per **ottenere token iCloud** da quel permesso, controlla il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Non so cosa permetta di fare

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **si menziona che potrebbe essere usato per** aggiornare i contenuti protetti da SSV dopo un riavvio. Se sai come farlo, invia una PR per favore!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **si menziona che potrebbe essere usato per** aggiornare i contenuti protetti da SSV dopo un riavvio. Se sai come farlo, invia una PR per favore!

### `keychain-access-groups`

Questa lista di permessi **gruppi keychain** a cui l'applicazione ha accesso:

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

Concede le autorizzazioni per l'**Accesso completo al disco**, una delle autorizzazioni più elevate di TCC che puoi avere.

### **`kTCCServiceAppleEvents`**

Permette all'applicazione di inviare eventi ad altre applicazioni comunemente utilizzate per **automatizzare compiti**. Controllando altre app, può abusare delle autorizzazioni concesse a queste altre app.

Come ad esempio far sì che chiedano all'utente la sua password:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

O permettendo loro di eseguire **azioni arbitrarie**.

### **`kTCCServiceEndpointSecurityClient`**

Permette, tra le altre autorizzazioni, di **scrivere nel database TCC degli utenti**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permette di **cambiare** l'attributo **`NFSHomeDirectory`** di un utente che cambia il percorso della sua cartella home e quindi consente di **bypassare TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permette di modificare i file all'interno dei bundle delle app (all'interno di app.app), il che è **disabilitato per impostazione predefinita**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

È possibile verificare chi ha questo accesso in _Impostazioni di Sistema_ > _Privacy e Sicurezza_ > _Gestione App._

### `kTCCServiceAccessibility`

Il processo sarà in grado di **abusare delle funzionalità di accessibilità di macOS**, il che significa che ad esempio sarà in grado di premere tasti. Quindi potrebbe richiedere l'accesso per controllare un'app come Finder e approvare il dialogo con questa autorizzazione.

## Medio

### `com.apple.security.cs.allow-jit`

Questo entitlement consente di **creare memoria che è scrivibile ed eseguibile** passando il flag `MAP_JIT` alla funzione di sistema `mmap()`. Controlla [**questo per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Questo entitlement consente di **sovrascrivere o patchare codice C**, utilizzare il long-deprecated **`NSCreateObjectFileImageFromMemory`** (che è fondamentalmente insicuro), o utilizzare il framework **DVDPlayback**. Controlla [**questo per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Includere questo entitlement espone la tua app a vulnerabilità comuni nei linguaggi di codice non sicuri in memoria. Valuta attentamente se la tua app ha bisogno di questa eccezione.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Questo entitlement consente di **modificare sezioni dei propri file eseguibili** su disco per uscire forzatamente. Controlla [**questo per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
L'Entitlement di Disabilitazione della Protezione delle Pagine Eseguibili è un entitlement estremo che rimuove una protezione di sicurezza fondamentale dalla tua app, rendendo possibile per un attaccante riscrivere il codice eseguibile della tua app senza essere rilevato. Preferisci entitlement più specifici se possibile.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Questo entitlement consente di montare un file system nullfs (vietato per impostazione predefinita). Strumento: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Secondo questo post sul blog, questa autorizzazione TCC di solito si trova nella forma:

```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```

Consenti al processo di **richiedere tutti i permessi TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
