# Bac à sable macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Le Bac à sable macOS (initialement appelé Seatbelt) **limite les applications** s'exécutant à l'intérieur du bac à sable aux **actions autorisées spécifiées dans le profil du bac à sable** avec lequel l'application est exécutée. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

Toute application avec le **droit** **`com.apple.security.app-sandbox`** sera exécutée à l'intérieur du bac à sable. **Les binaires Apple** sont généralement exécutés dans un bac à sable et pour publier dans l'**App Store**, **ce droit est obligatoire**. Ainsi, la plupart des applications seront exécutées à l'intérieur du bac à sable.

Pour contrôler ce qu'un processus peut ou ne peut pas faire, le **bac à sable a des crochets** dans tous les **appels système** à travers le noyau. **Selon** les **droits** de l'application, le bac à sable **permettra** certaines actions.

Certains composants importants du bac à sable sont :

* L'**extension du noyau** `/System/Library/Extensions/Sandbox.kext`
* Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **démon** s'exécutant en espace utilisateur `/usr/libexec/sandboxd`
* Les **conteneurs** `~/Library/Containers`

À l'intérieur du dossier des conteneurs, vous pouvez trouver **un dossier pour chaque application exécutée dans un bac à sable** avec le nom de l'identifiant du paquet :
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
Dans chaque dossier d'identifiant de bundle, vous pouvez trouver le **plist** et le **répertoire Data** de l'application :
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
Notez que même si les liens symboliques sont présents pour "s'échapper" du Sandbox et accéder à d'autres dossiers, l'application doit toujours **avoir les permissions** pour y accéder. Ces permissions se trouvent dans le fichier **`.plist`**.
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
Tout ce qui est créé/modifié par une application en mode **Sandbox** recevra l'**attribut de quarantaine**. Cela empêchera un espace sandbox de déclencher Gatekeeper si l'application sandbox essaie d'exécuter quelque chose avec **`open`**.
{% endhint %}

### Profils Sandbox

Les profils Sandbox sont des fichiers de configuration qui indiquent ce qui sera **autorisé/interdit** dans ce **Sandbox**. Il utilise le **Langage de Profil Sandbox (SBPL)**, qui utilise le langage de programmation [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

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
Consultez cette [**recherche**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **pour vérifier plus d'actions qui pourraient être autorisées ou refusées.**
{% endhint %}

Des **services système** importants fonctionnent également dans leur propre **sandbox** personnalisé, comme le service `mdnsresponder`. Vous pouvez consulter ces **profils de sandbox** personnalisés dans :

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* D'autres profils de sandbox peuvent être consultés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Les applications **App Store** utilisent le **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profil comment des droits tels que **`com.apple.security.network.server`** permettent à un processus d'utiliser le réseau.

SIP est un profil de Sandbox appelé platform\_profile dans /System/Library/Sandbox/rootless.conf

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
Since there is no content provided to translate, I cannot proceed with a translation. If you provide the English text from the specified file, I will be able to translate it into French for you. Please provide the relevant English text to continue.
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
Le contenu fourni est un élément de syntaxe Markdown pour un bloc de code avec un titre "touch2.sb". Il n'y a pas de texte anglais à traduire. Veuillez fournir le texte anglais pertinent pour la traduction.
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
Le contenu fourni ne contient pas de texte à traduire. Veuillez fournir le texte anglais pertinent pour que je puisse effectuer la traduction en français.
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
Notez que le **logiciel écrit par Apple** qui fonctionne sur **Windows** **n'a pas de précautions de sécurité supplémentaires**, telles que le confinement des applications (sandboxing).
{% endhint %}

Exemples de contournements :

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils peuvent écrire des fichiers en dehors du sandbox dont le nom commence par `~$`).

### Profils de Sandbox MacOS

macOS stocke les profils de sandbox système dans deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce possède le droit _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

### **Profil Sandbox iOS**

Le profil par défaut s'appelle **container** et nous n'avons pas la représentation textuelle SBPL. En mémoire, ce sandbox est représenté comme un arbre binaire Autoriser/Refuser pour chaque permission du sandbox.

### Déboguer & Contourner le Sandbox

**Les processus ne naissent pas confinés sur macOS : contrairement à iOS**, où le sandbox est appliqué par le noyau avant la première instruction d'un programme, sur macOS **un processus doit choisir de se placer lui-même dans le sandbox.**

Les processus sont automatiquement confinés depuis l'espace utilisateur lorsqu'ils démarrent s'ils possèdent le droit : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Vérifier les Privilèges d'un PID**

[**Selon ceci**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), le **`sandbox_check`** (c'est un `__mac_syscall`), peut vérifier **si une opération est autorisée ou non** par le sandbox pour un certain PID.

L'[**outil sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) peut vérifier si un PID peut effectuer une certaine action :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Profils SBPL personnalisés dans les applications de l'App Store

Il pourrait être possible pour les entreprises de faire fonctionner leurs applications **avec des profils Sandbox personnalisés** (au lieu de celui par défaut). Elles doivent utiliser le droit **`com.apple.security.temporary-exception.sbpl`** qui doit être autorisé par Apple.

Il est possible de vérifier la définition de ce droit dans **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Cela **évaluera la chaîne après ce droit** comme un profil Sandbox.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
