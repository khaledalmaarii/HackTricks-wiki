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

Le Sandbox macOS (appelé initialement Seatbelt) **limite les applications** s'exécutant à l'intérieur du sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application s'exécute. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

Toute application avec l'**entitlement** **`com.apple.security.app-sandbox`** sera exécutée à l'intérieur du sandbox. Les **binaires Apple** sont généralement exécutés à l'intérieur d'un Sandbox et pour être publiés dans l'**App Store**, **cet entitlement est obligatoire**. Ainsi, la plupart des applications seront exécutées à l'intérieur du sandbox.

Pour contrôler ce qu'un processus peut ou ne peut pas faire, le **Sandbox a des hooks** dans tous les **syscalls** à travers le noyau. **Selon** les **entitlements** de l'application, le Sandbox **permettra** certaines actions.

Certains composants importants du Sandbox sont :

* L'**extension du noyau** `/System/Library/Extensions/Sandbox.kext`
* Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** s'exécutant en userland `/usr/libexec/sandboxd`
* Les **conteneurs** `~/Library/Containers`

Dans le dossier des conteneurs, vous pouvez trouver **un dossier pour chaque application exécutée en sandbox** avec le nom de l'identifiant de bundle :
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
À l'intérieur de chaque dossier d'identifiant de bundle, vous pouvez trouver le **plist** et le **répertoire de données** de l'application :
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
Notez que même si les symlinks sont là pour "s'échapper" du Sandbox et accéder à d'autres dossiers, l'App doit toujours **avoir des permissions** pour y accéder. Ces permissions se trouvent dans le **`.plist`**.
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
Tout ce qui est créé/modifié par une application sandboxée obtiendra l'**attribut de quarantaine**. Cela empêchera un espace sandbox en déclenchant Gatekeeper si l'application sandbox essaie d'exécuter quelque chose avec **`open`**.
{% endhint %}

### Profils de Sandbox

Les profils de Sandbox sont des fichiers de configuration qui indiquent ce qui sera **autorisé/interdit** dans ce **Sandbox**. Il utilise le **Sandbox Profile Language (SBPL)**, qui utilise le langage de programmation [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Voici un exemple :
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
Vérifiez cette [**recherche**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **pour voir plus d'actions qui pourraient être autorisées ou refusées.**
{% endhint %}

Des **services système** importants s'exécutent également dans leur propre **sandbox** personnalisée, comme le service `mdnsresponder`. Vous pouvez consulter ces **profils de sandbox** personnalisés dans :

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* D'autres profils de sandbox peuvent être consultés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Les applications de l'**App Store** utilisent le **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profil comment des droits tels que **`com.apple.security.network.server`** permettent à un processus d'utiliser le réseau.

SIP est un profil de sandbox appelé platform\_profile dans /System/Library/Sandbox/rootless.conf

### Exemples de Profils de Sandbox

Pour démarrer une application avec un **profil de sandbox spécifique**, vous pouvez utiliser :
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
Notez que le **logiciel** **écrit par Apple** qui fonctionne sur **Windows** **n'a pas de précautions de sécurité supplémentaires**, telles que le sandboxing des applications.
{% endhint %}

Exemples de contournement :

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils peuvent écrire des fichiers en dehors du sandbox dont le nom commence par `~$`).

### Profils de Sandbox MacOS

macOS stocke les profils de sandbox système à deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce possède le droit _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

### **Profil de Sandbox iOS**

Le profil par défaut s'appelle **container** et nous n'avons pas la représentation textuelle SBPL. En mémoire, ce sandbox est représenté comme un arbre binaire Allow/Deny pour chaque permission du sandbox.

### Déboguer & Contourner le Sandbox

Sur macOS, contrairement à iOS où les processus sont sandboxés dès le départ par le noyau, **les processus doivent s'inscrire eux-mêmes dans le sandbox**. Cela signifie que sur macOS, un processus n'est pas restreint par le sandbox tant qu'il ne décide pas activement d'y entrer.

Les processus sont automatiquement sandboxés depuis l'espace utilisateur lorsqu'ils démarrent s'ils ont le droit : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Vérifier les privilèges PID**

[**Selon ceci**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), le **`sandbox_check`** (c'est un `__mac_syscall`), peut vérifier **si une opération est autorisée ou non** par le sandbox dans un certain PID.

L'**outil sbtool** [**peut vérifier**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) si un PID peut effectuer une certaine action :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL dans les applications de l'App Store

Il pourrait être possible pour les entreprises de faire fonctionner leurs applications **avec des profils de Sandbox personnalisés** (au lieu de celui par défaut). Elles doivent utiliser le droit **`com.apple.security.temporary-exception.sbpl`** qui doit être autorisé par Apple.

Il est possible de vérifier la définition de ce droit dans **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Cela va **évaluer la chaîne après cette attribution** comme un profil Sandbox.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
