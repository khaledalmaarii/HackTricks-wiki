# Bac à sable macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informations de base

Le bac à sable macOS (initialement appelé Seatbelt) **limite les applications** s'exécutant à l'intérieur du bac à sable aux **actions autorisées spécifiées dans le profil du bac à sable** avec lequel l'application s'exécute. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

Toute application avec l'**autorisation** **`com.apple.security.app-sandbox`** sera exécutée à l'intérieur du bac à sable. Les **binaires Apple** sont généralement exécutés à l'intérieur d'un bac à sable et pour être publiés dans l'**App Store**, **cette autorisation est obligatoire**. Ainsi, la plupart des applications seront exécutées à l'intérieur du bac à sable.

Pour contrôler ce qu'un processus peut ou ne peut pas faire, le **Bac à sable a des hooks** dans tous les **syscalls** à travers le noyau. **En fonction** des **autorisations** de l'application, le Bac à sable **autorise** certaines actions.

Certains composants importants du Bac à sable sont :

* L'**extension de noyau** `/System/Library/Extensions/Sandbox.kext`
* Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **démon** s'exécutant dans l'espace utilisateur `/usr/libexec/sandboxd`
* Les **conteneurs** `~/Library/Containers`

À l'intérieur du dossier des conteneurs, vous pouvez trouver **un dossier pour chaque application exécutée en mode bac à sable** avec le nom de l'ID de bundle :
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
À l'intérieur de chaque dossier d'identifiant de bundle, vous pouvez trouver le **plist** et le **répertoire Data** de l'application :
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
Notez que même si les liens symboliques sont là pour "échapper" au Bac à sable et accéder à d'autres dossiers, l'application doit toujours **avoir les autorisations** pour y accéder. Ces autorisations se trouvent dans le fichier **`.plist`**.
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
Tout ce qui est créé/modifié par une application Sandbox aura l'**attribut de quarantaine**. Cela empêchera un espace sandbox en déclenchant Gatekeeper si l'application sandbox tente d'exécuter quelque chose avec **`open`**.
{% endhint %}

### Profils Sandbox

Les profils Sandbox sont des fichiers de configuration qui indiquent ce qui va être **autorisé/interdit** dans ce **Sandbox**. Il utilise le **Langage de Profil Sandbox (SBPL)**, qui utilise le langage de programmation [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

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

Les **services système** importants s'exécutent également à l'intérieur de leur propre **bac à sable personnalisé** tel que le service `mdnsresponder`. Vous pouvez consulter ces profils de **bac à sable personnalisés** à l'intérieur de :

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* D'autres profils de bac à sable peuvent être consultés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Les applications de l'**App Store** utilisent le **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profil comment les autorisations telles que **`com.apple.security.network.server`** permettent à un processus d'utiliser le réseau.

SIP est un profil de bac à sable appelé platform\_profile dans /System/Library/Sandbox/rootless.conf

### Exemples de Profils de Bac à Sable

Pour démarrer une application avec un **profil de bac à sable spécifique**, vous pouvez utiliser :
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
Notez que les **logiciels** **développés par Apple** qui s'exécutent sur **Windows** **ne bénéficient pas de précautions de sécurité supplémentaires**, telles que l'isolation des applications.
{% endhint %}

Exemples de contournements :

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils peuvent écrire des fichiers en dehors du bac à sable dont le nom commence par `~$`).

### Profils de bac à sable de MacOS

macOS stocke les profils de bac à sable système dans deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce possède l'attribution _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

### **Profil de bac à sable iOS**

Le profil par défaut s'appelle **container** et nous n'avons pas la représentation textuelle SBPL. En mémoire, ce bac à sable est représenté comme un arbre binaire Autoriser/Refuser pour chaque autorisation du bac à sable.

### Débogage & Contournement du Bac à Sable

Sur macOS, contrairement à iOS où les processus sont isolés dès le départ par le noyau, **les processus doivent choisir de s'inscrire dans le bac à sable eux-mêmes**. Cela signifie que sur macOS, un processus n'est pas restreint par le bac à sable tant qu'il ne décide pas activement d'y entrer.

Les processus sont automatiquement placés dans un bac à sable depuis l'espace utilisateur lors de leur démarrage s'ils possèdent l'attribution : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Vérifier les Privilèges PID**

[**Selon ceci**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), le **`sandbox_check`** (c'est un `__mac_syscall`), peut vérifier **si une opération est autorisée ou non** par le bac à sable dans un PID spécifique.

L'**outil sbtool** peut vérifier si un PID peut effectuer une certaine action :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Profils SBPL personnalisés dans les applications de l'App Store

Il pourrait être possible pour les entreprises de faire fonctionner leurs applications avec des **profils Sandbox personnalisés** (au lieu de celui par défaut). Elles doivent utiliser l'attribution **`com.apple.security.temporary-exception.sbpl`** qui doit être autorisée par Apple.

Il est possible de vérifier la définition de cette attribution dans **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Cela **évaluera la chaîne après cette autorisation** en tant que profil Sandbox.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
