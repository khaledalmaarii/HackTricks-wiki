# macOS Sandbox

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

## Basic Information

MacOS Sandbox (inizialmente chiamato Seatbelt) **limita le applicazioni** in esecuzione all'interno della sandbox alle **azioni consentite specificate nel profilo Sandbox** con cui l'app è in esecuzione. Questo aiuta a garantire che **l'applicazione accederà solo alle risorse previste**.

Qualsiasi app con l'**entitlement** **`com.apple.security.app-sandbox`** verrà eseguita all'interno della sandbox. **I binari Apple** vengono solitamente eseguiti all'interno di una Sandbox e per pubblicare all'interno dell'**App Store**, **questo entitlement è obbligatorio**. Quindi, la maggior parte delle applicazioni verrà eseguita all'interno della sandbox.

Per controllare cosa un processo può o non può fare, la **Sandbox ha hook** in tutte le **syscall** nel kernel. **A seconda** degli **entitlements** dell'app, la Sandbox **consentirà** determinate azioni.

Al alcuni componenti importanti della Sandbox sono:

* L'**estensione del kernel** `/System/Library/Extensions/Sandbox.kext`
* Il **framework privato** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** in esecuzione in userland `/usr/libexec/sandboxd`
* I **contenitori** `~/Library/Containers`

All'interno della cartella dei contenitori puoi trovare **una cartella per ogni app eseguita in sandbox** con il nome dell'id del bundle:
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
All'interno di ogni cartella dell'ID bundle puoi trovare il **plist** e la **directory Data** dell'App:
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
Nota che anche se i symlink sono presenti per "uscire" dal Sandbox e accedere ad altre cartelle, l'App deve comunque **avere permessi** per accedervi. Questi permessi sono all'interno del **`.plist`**.
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
Tutto ciò che viene creato/modificato da un'applicazione in Sandbox riceverà l'**attributo di quarantena**. Questo impedirà a uno spazio sandbox di attivare Gatekeeper se l'app sandbox tenta di eseguire qualcosa con **`open`**.
{% endhint %}

### Profili Sandbox

I profili Sandbox sono file di configurazione che indicano cosa sarà **consentito/vietato** in quel **Sandbox**. Utilizza il **Sandbox Profile Language (SBPL)**, che utilizza il linguaggio di programmazione [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

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
Controlla questa [**ricerca**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **per verificare ulteriori azioni che potrebbero essere consentite o negate.**
{% endhint %}

I **servizi di sistema** importanti vengono eseguiti anche all'interno del proprio **sandbox** personalizzato, come il servizio `mdnsresponder`. Puoi visualizzare questi **profili sandbox** personalizzati all'interno di:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Altri profili sandbox possono essere controllati su [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Le app dell'**App Store** utilizzano il **profilo** **`/System/Library/Sandbox/Profiles/application.sb`**. Puoi controllare in questo profilo come i diritti, come **`com.apple.security.network.server`**, consentono a un processo di utilizzare la rete.

SIP è un profilo Sandbox chiamato platform\_profile in /System/Library/Sandbox/rootless.conf

### Esempi di profili Sandbox

Per avviare un'applicazione con un **profilo sandbox specifico** puoi usare:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
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
{% endcode %}

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
Nota che il **software** **autorizzato da Apple** che gira su **Windows** **non ha precauzioni di sicurezza aggiuntive**, come il sandboxing delle applicazioni.
{% endhint %}

Esempi di bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sono in grado di scrivere file al di fuori del sandbox il cui nome inizia con `~$`).

### Profili Sandbox di MacOS

macOS memorizza i profili di sandbox di sistema in due posizioni: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

E se un'applicazione di terze parti possiede il diritto _**com.apple.security.app-sandbox**_, il sistema applica il profilo **/System/Library/Sandbox/Profiles/application.sb** a quel processo.

### **Profilo Sandbox di iOS**

Il profilo predefinito si chiama **container** e non abbiamo la rappresentazione testuale SBPL. In memoria, questo sandbox è rappresentato come un albero binario Allow/Deny per ciascuna autorizzazione del sandbox.

### Debug & Bypass Sandbox

Su macOS, a differenza di iOS dove i processi sono sandboxati fin dall'inizio dal kernel, **i processi devono optare per il sandboxing da soli**. Questo significa che su macOS, un processo non è limitato dal sandbox fino a quando non decide attivamente di entrarvi.

I processi vengono automaticamente sandboxati dal userland quando iniziano se hanno il diritto: `com.apple.security.app-sandbox`. Per una spiegazione dettagliata di questo processo controlla:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Controlla i privilegi PID**

[**Secondo questo**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), il **`sandbox_check`** (è un `__mac_syscall`), può controllare **se un'operazione è consentita o meno** dal sandbox in un certo PID.

Il [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) può controllare se un PID può eseguire una certa azione:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL nelle app dell'App Store

Potrebbe essere possibile per le aziende far funzionare le loro app **con profili Sandbox personalizzati** (invece di quello predefinito). Devono utilizzare il diritto **`com.apple.security.temporary-exception.sbpl`** che deve essere autorizzato da Apple.

È possibile controllare la definizione di questo diritto in **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Questo **valuterà la stringa dopo questo diritto** come un profilo Sandbox.

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
