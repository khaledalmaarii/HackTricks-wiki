# Bac à sable macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Le bac à sable macOS (initialement appelé Seatbelt) **limite les applications** s'exécutant à l'intérieur du bac à sable aux **actions autorisées spécifiées dans le profil du bac à sable** avec lequel l'application s'exécute. Cela permet de garantir que **l'application n'accédera qu'aux ressources attendues**.

Toute application avec l'**autorisation** **`com.apple.security.app-sandbox`** sera exécutée à l'intérieur du bac à sable. Les binaires **Apple** sont généralement exécutés à l'intérieur d'un bac à sable et pour pouvoir être publiés dans **l'App Store**, **cette autorisation est obligatoire**. Ainsi, la plupart des applications seront exécutées à l'intérieur du bac à sable.

Pour contrôler ce qu'un processus peut ou ne peut pas faire, le **bac à sable dispose de crochets** dans tous les **appels système** du noyau. **Selon** les **autorisations** de l'application, le bac à sable **autorise** certaines actions.

Quelques composants importants du bac à sable sont :

* L'**extension du noyau** `/System/Library/Extensions/Sandbox.kext`
* Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **démon** s'exécutant dans l'espace utilisateur `/usr/libexec/sandboxd`
* Les **conteneurs** `~/Library/Containers`

À l'intérieur du dossier des conteneurs, vous pouvez trouver **un dossier pour chaque application exécutée dans le bac à sable** avec le nom de l'ID de bundle :
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
À l'intérieur de chaque dossier d'identifiant de bundle, vous pouvez trouver le fichier **plist** et le répertoire **Data** de l'application :
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
Notez que même si les liens symboliques sont là pour "échapper" au Sandbox et accéder à d'autres dossiers, l'application doit toujours **avoir les permissions** pour y accéder. Ces permissions se trouvent dans le **`.plist`**.
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
### Profils de sandbox

Les profils de sandbox sont des fichiers de configuration qui indiquent ce qui est autorisé/interdit dans cette sandbox. Ils utilisent le langage de profil de sandbox (SBPL), qui utilise le langage de programmation [Scheme](https://fr.wikipedia.org/wiki/Scheme_(langage)). 

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

Des **services système** importants s'exécutent également dans leur propre **bac à sable personnalisé**, tels que le service `mdnsresponder`. Vous pouvez consulter ces **profils de bac à sable personnalisés** ici :

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* D'autres profils de bac à sable peuvent être consultés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Les applications de l'**App Store** utilisent le **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profil comment les autorisations telles que **`com.apple.security.network.server`** permettent à un processus d'utiliser le réseau.

SIP est un profil de bac à sable appelé platform\_profile dans /System/Library/Sandbox/rootless.conf

### Exemples de profils de bac à sable

Pour démarrer une application avec un **profil de bac à sable spécifique**, vous pouvez utiliser :
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```plaintext
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-data (literal "/tmp/"))
(allow file-write-data (subpath "/Users/"))
(allow file-write-data (subpath "/Applications/"))
(allow file-write-data (subpath "/Library/"))
(allow file-write-data (subpath "/System/"))
(allow file-write-data (subpath "/private/"))
(allow file-write-data (subpath "/var/"))
(allow file-write-data (subpath "/Volumes/"))
(allow file-write-data (subpath "/Network/"))
(allow file-write-data (subpath "/etc/"))
(allow file-write-data (subpath "/bin/"))
(allow file-write-data (subpath "/sbin/"))
(allow file-write-data (subpath "/usr/"))
(allow file-write-data (subpath "/opt/"))
(allow file-write-data (subpath "/Developer/"))
(allow file-write-data (subpath "/Applications/Utilities/"))
(allow file-write-data (subpath "/Library/Application Support/"))
(allow file-write-data (subpath "/Library/Preferences/"))
(allow file-write-data (subpath "/Library/LaunchAgents/"))
(allow file-write-data (subpath "/Library/LaunchDaemons/"))
(allow file-write-data (subpath "/Library/StartupItems/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file-write-data (subpath "/System/Library/Spotlight/"))
(allow file-write-data (subpath "/System/Library/QuickTime/"))
(allow file-write-data (subpath "/System/Library/PreferencePanes/"))
(allow file-write-data (subpath "/System/Library/Extensions/"))
(allow file-write-data (subpath "/System/Library/CoreServices/"))
(allow file-write-data (subpath "/System/Library/Frameworks/"))
(allow file-write-data (subpath "/System/Library/Services/"))
(allow file-write-data (subpath "/System/Library/UserEventPlugins/"))
(allow file-write-data (subpath "/System/Library/Keyboard Layouts/"))
(allow file-write-data (subpath "/System/Library/ColorSync/Profiles/"))
(allow file-write-data (subpath "/System/Library/Fonts/"))
(allow file-write-data (subpath "/System/Library/Screen Savers/"))
(allow file
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
Notez que le **logiciel** **développé par Apple** qui s'exécute sur **Windows** **n'a pas de précautions de sécurité supplémentaires**, telles que l'isolation des applications.
{% endhint %}

Exemples de contournements :

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils peuvent écrire des fichiers en dehors de l'isolation dont le nom commence par `~$`).

### Profils de l'isolation de macOS

macOS stocke les profils d'isolation système dans deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce possède l'attribution _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

### Débogage et contournement de l'isolation

**Les processus ne naissent pas isolés dans macOS : contrairement à iOS**, où l'isolation est appliquée par le noyau avant la première instruction d'un programme, sur macOS **un processus doit choisir de se placer dans l'isolation.**

Les processus sont automatiquement isolés depuis l'espace utilisateur lorsqu'ils démarrent s'ils ont l'attribution : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Vérifier les privilèges PID**

[Selon cela](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), la fonction **`sandbox_check`** (c'est un `__mac_syscall`), peut vérifier **si une opération est autorisée ou non** par l'isolation dans un PID donné.

L'outil [**sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) peut vérifier si un PID peut effectuer une certaine action :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Profils SBPL personnalisés dans les applications de l'App Store

Il est possible pour les entreprises de faire fonctionner leurs applications avec des profils Sandbox personnalisés (au lieu du profil par défaut). Elles doivent utiliser l'attribution `com.apple.security.temporary-exception.sbpl` qui doit être autorisée par Apple.

Il est possible de vérifier la définition de cette attribution dans `/System/Library/Sandbox/Profiles/application.sb:`
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Cela **évaluera la chaîne après cette autorisation** en tant que profil Sandbox.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
