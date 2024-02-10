# Sandbox di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub**.

</details>

## Informazioni di base

Il Sandbox di macOS (inizialmente chiamato Seatbelt) **limita le applicazioni** in esecuzione all'interno del sandbox alle **azioni consentite specificate nel profilo del Sandbox** con cui l'app viene eseguita. Ciò aiuta a garantire che **l'applicazione acceda solo alle risorse previste**.

Qualsiasi app con l'**abilitazione** **`com.apple.security.app-sandbox`** verrà eseguita all'interno del sandbox. **I binari di Apple** di solito vengono eseguiti all'interno di un Sandbox e per poterli pubblicare nell'**App Store**, **questa abilitazione è obbligatoria**. Quindi la maggior parte delle applicazioni verrà eseguita all'interno del sandbox.

Per controllare cosa un processo può o non può fare, il **Sandbox ha hook** in tutte le **syscall** del kernel. **A seconda** delle **abilitazioni** dell'app, il Sandbox **permetterà** determinate azioni.

Alcuni componenti importanti del Sandbox sono:

* L'**estensione del kernel** `/System/Library/Extensions/Sandbox.kext`
* Il **framework privato** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** in esecuzione in userland `/usr/libexec/sandboxd`
* I **contenitori** `~/Library/Containers`

All'interno della cartella dei contenitori è possibile trovare **una cartella per ogni app eseguita all'interno del sandbox** con il nome dell'ID del bundle:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
All'interno di ogni cartella dell'ID del bundle è possibile trovare il file **plist** e la directory **Data** dell'app:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Nota che anche se i symlink sono presenti per "uscire" dalla Sandbox e accedere ad altre cartelle, l'App ha comunque bisogno di **avere le autorizzazioni** per accedervi. Queste autorizzazioni sono all'interno del file **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Tutto ciò che viene creato/modificato da un'applicazione Sandbox avrà l'attributo **quarantine**. Questo impedirà uno spazio sandbox attivando Gatekeeper se l'app sandbox prova ad eseguire qualcosa con **`open`**.
{% endhint %}

### Profili Sandbox

I profili Sandbox sono file di configurazione che indicano cosa è **permesso/vietato** in quella **Sandbox**. Utilizzano il **Sandbox Profile Language (SBPL)**, che utilizza il linguaggio di programmazione [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Qui puoi trovare un esempio:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Controlla questa [**ricerca**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **per controllare altre azioni che potrebbero essere consentite o negate.**
{% endhint %}

Importanti **servizi di sistema** vengono eseguiti all'interno del proprio **sandbox personalizzato**, come ad esempio il servizio `mdnsresponder`. Puoi visualizzare questi **profilo sandbox personalizzati** all'interno di:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Altri profili sandbox possono essere controllati su [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Le app **App Store** utilizzano il **profilo** **`/System/Library/Sandbox/Profiles/application.sb`**. Puoi controllare in questo profilo come i privilegi come **`com.apple.security.network.server`** consentono a un processo di utilizzare la rete.

SIP è un profilo Sandbox chiamato platform\_profile in /System/Library/Sandbox/rootless.conf

### Esempi di Profili Sandbox

Per avviare un'applicazione con un **profilo sandbox specifico** puoi utilizzare:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
Il file touch.sb è un file di politica del sandbox di macOS che definisce le restrizioni di accesso per l'applicazione touch. Questo file specifica le autorizzazioni di accesso ai file e alle risorse di sistema che l'applicazione touch può utilizzare all'interno del sandbox.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Si noti che il **software** **sviluppato da Apple** che viene eseguito su **Windows** **non ha ulteriori precauzioni di sicurezza**, come l'applicazione del sandbox.
{% endhint %}

Esempi di bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sono in grado di scrivere file al di fuori del sandbox il cui nome inizia con `~$`).

### Profili di sandbox di MacOS

macOS memorizza i profili di sandbox di sistema in due posizioni: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

E se un'applicazione di terze parti ha l'abilitazione _**com.apple.security.app-sandbox**_, il sistema applica il profilo **/System/Library/Sandbox/Profiles/application.sb** a quel processo.

### **Profilo di sandbox di iOS**

Il profilo predefinito si chiama **container** e non abbiamo la rappresentazione testuale SBPL. In memoria, questa sandbox è rappresentata come un albero binario di autorizzazioni Allow/Deny per ogni permesso della sandbox.

### Debug e bypass del sandbox

Su macOS, a differenza di iOS dove i processi sono sandboxati fin dall'inizio dal kernel, **i processi devono scegliere di aderire al sandbox da soli**. Ciò significa che su macOS, un processo non è limitato dal sandbox fino a quando non decide attivamente di entrarvi.

I processi vengono automaticamente sandboxati da userland quando vengono avviati se hanno l'abilitazione: `com.apple.security.app-sandbox`. Per una spiegazione dettagliata di questo processo, controlla:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Verifica dei privilegi PID**

[**Secondo questo**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), il **`sandbox_check`** (è una `__mac_syscall`), può verificare **se un'operazione è consentita o meno** dal sandbox in un determinato PID.

Lo [**strumento sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) può verificare se un PID può eseguire una determinata azione:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Profili SBPL personalizzati nelle app dell'App Store

Potrebbe essere possibile per le aziende far eseguire le loro app con **profili Sandbox personalizzati** (invece di quelli predefiniti). Devono utilizzare il privilegio **`com.apple.security.temporary-exception.sbpl`** che deve essere autorizzato da Apple.

È possibile verificare la definizione di questo privilegio in **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Questo **valuterà la stringa dopo questo privilegio** come un profilo Sandbox.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
