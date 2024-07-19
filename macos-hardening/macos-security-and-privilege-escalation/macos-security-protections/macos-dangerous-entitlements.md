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
Nota che le autorizzazioni che iniziano con **`com.apple`** non sono disponibili per terze parti, solo Apple può concederle.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

L'autorizzazione **`com.apple.rootless.install.heritable`** consente di **bypassare SIP**. Controlla [questo per maggiori informazioni](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'autorizzazione **`com.apple.rootless.install`** consente di **bypassare SIP**. Controlla[ questo per maggiori informazioni](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (precedentemente chiamata `task_for_pid-allow`)**

Questa autorizzazione consente di ottenere il **port task per qualsiasi** processo, tranne il kernel. Controlla [**questo per maggiori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Questa autorizzazione consente ad altri processi con l'autorizzazione **`com.apple.security.cs.debugger`** di ottenere il port task del processo eseguito dal binario con questa autorizzazione e **iniettare codice su di esso**. Controlla [**questo per maggiori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Le app con l'autorizzazione Debugging Tool possono chiamare `task_for_pid()` per recuperare un port task valido per app non firmate e di terze parti con l'autorizzazione `Get Task Allow` impostata su `true`. Tuttavia, anche con l'autorizzazione dello strumento di debug, un debugger **non può ottenere i port task** di processi che **non hanno l'autorizzazione `Get Task Allow`**, e che sono quindi protetti dalla Protezione dell'Integrità di Sistema. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Questa autorizzazione consente di **caricare framework, plug-in o librerie senza essere firmati da Apple o firmati con lo stesso Team ID** dell'eseguibile principale, quindi un attaccante potrebbe abusare di un caricamento arbitrario di librerie per iniettare codice. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Questa autorizzazione è molto simile a **`com.apple.security.cs.disable-library-validation`** ma **invece** di **disabilitare direttamente** la validazione delle librerie, consente al processo di **chiamare una chiamata di sistema `csops` per disabilitarla**.\
Controlla [**questo per maggiori informazioni**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Questa autorizzazione consente di **utilizzare variabili di ambiente DYLD** che potrebbero essere utilizzate per iniettare librerie e codice. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Secondo questo blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**questo blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), queste autorizzazioni consentono di **modificare** il database **TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Queste autorizzazioni consentono di **installare software senza chiedere permessi** all'utente, il che può essere utile per un **privilege escalation**.

### `com.apple.private.security.kext-management`

Autorizzazione necessaria per chiedere al **kernel di caricare un'estensione del kernel**.

### **`com.apple.private.icloud-account-access`**

L'autorizzazione **`com.apple.private.icloud-account-access`** consente di comunicare con il servizio XPC **`com.apple.iCloudHelper`** che fornirà **token iCloud**.

**iMovie** e **Garageband** avevano questa autorizzazione.

Per ulteriori **informazioni** sull'exploit per **ottenere token iCloud** da quell'autorizzazione controlla il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Non so cosa consenta di fare

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **si menziona che questo potrebbe essere utilizzato per** aggiornare i contenuti protetti da SSV dopo un riavvio. Se sai come farlo invia un PR per favore!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **si menziona che questo potrebbe essere utilizzato per** aggiornare i contenuti protetti da SSV dopo un riavvio. Se sai come farlo invia un PR per favore!

### `keychain-access-groups`

Questa autorizzazione elenca i gruppi **keychain** a cui l'applicazione ha accesso:
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

Concede i permessi di **Accesso Completo al Disco**, uno dei permessi più elevati di TCC che puoi avere.

### **`kTCCServiceAppleEvents`**

Consente all'app di inviare eventi ad altre applicazioni comunemente utilizzate per **automatizzare compiti**. Controllando altre app, può abusare dei permessi concessi a queste altre app.

Come farle chiedere all'utente la propria password:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

O farli eseguire **azioni arbitrarie**.

### **`kTCCServiceEndpointSecurityClient`**

Consente, tra le altre autorizzazioni, di **scrivere nel database TCC degli utenti**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Consente di **cambiare** l'attributo **`NFSHomeDirectory`** di un utente che modifica il percorso della sua cartella home e quindi consente di **bypassare TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Consente di modificare i file all'interno dei bundle delle app (all'interno di app.app), il che è **vietato per impostazione predefinita**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

È possibile controllare chi ha accesso in _Impostazioni di Sistema_ > _Privacy e Sicurezza_ > _Gestione App._

### `kTCCServiceAccessibility`

Il processo sarà in grado di **abuse delle funzionalità di accessibilità di macOS**, il che significa che, ad esempio, sarà in grado di premere tasti. Quindi potrebbe richiedere l'accesso per controllare un'app come Finder e approvare la finestra di dialogo con questo permesso.

## Medio

### `com.apple.security.cs.allow-jit`

Questa autorizzazione consente di **creare memoria che è scrivibile ed eseguibile** passando il flag `MAP_JIT` alla funzione di sistema `mmap()`. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Questa autorizzazione consente di **sovrascrivere o patchare codice C**, utilizzare il **`NSCreateObjectFileImageFromMemory`** ormai obsoleto (che è fondamentalmente insicuro), o utilizzare il framework **DVDPlayback**. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Includere questa autorizzazione espone la tua app a vulnerabilità comuni nei linguaggi di codice non sicuri in memoria. Considera attentamente se la tua app ha bisogno di questa eccezione.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Questa autorizzazione consente di **modificare sezioni dei propri file eseguibili** su disco per forzare l'uscita. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
L'Autorizzazione per Disabilitare la Protezione della Memoria Eseguibile è un'autorizzazione estrema che rimuove una protezione fondamentale della sicurezza dalla tua app, rendendo possibile per un attaccante riscrivere il codice eseguibile della tua app senza essere rilevato. Preferisci autorizzazioni più ristrette se possibile.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Questa autorizzazione consente di montare un file system nullfs (vietato per impostazione predefinita). Strumento: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Secondo questo post del blog, questo permesso TCC di solito si trova nella forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Consenti al processo di **richiedere tutte le autorizzazioni TCC**.

### **`kTCCServicePostEvent`**
{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
</details>
