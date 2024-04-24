# macOS File, Cartelle, Binari e Memoria

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Layout della Gerarchia dei File

* **/Applications**: Le app installate dovrebbero essere qui. Tutti gli utenti potranno accedervi.
* **/bin**: Binari della riga di comando
* **/cores**: Se esiste, viene utilizzato per memorizzare i dump core
* **/dev**: Tutto è trattato come un file quindi potresti vedere dispositivi hardware memorizzati qui.
* **/etc**: File di configurazione
* **/Library**: Molte sottodirectory e file relativi a preferenze, cache e log possono essere trovati qui. Una cartella Library esiste nella root e in ogni directory dell'utente.
* **/private**: Non documentato ma molte delle cartelle menzionate sono collegamenti simbolici alla directory private.
* **/sbin**: Binari di sistema essenziali (relativi all'amministrazione)
* **/System**: File per far funzionare OS X. Dovresti trovare principalmente solo file specifici di Apple qui (non di terze parti).
* **/tmp**: I file vengono eliminati dopo 3 giorni (è un collegamento simbolico a /private/tmp)
* **/Users**: Directory home degli utenti.
* **/usr**: Configurazioni e binari di sistema
* **/var**: File di log
* **/Volumes**: Le unità montate appariranno qui.
* **/.vol**: Eseguendo `stat a.txt` otterrai qualcosa come `16777223 7545753 -rw-r--r-- 1 username wheel ...` dove il primo numero è l'id del volume in cui si trova il file e il secondo è il numero di inode. Puoi accedere al contenuto di questo file tramite /.vol/ con queste informazioni eseguendo `cat /.vol/16777223/7545753`

### Cartelle delle Applicazioni

* Le **applicazioni di sistema** si trovano sotto `/System/Applications`
* Le applicazioni **installate** di solito sono installate in `/Applications` o in `~/Applications`
* I **dati dell'applicazione** possono essere trovati in `/Library/Application Support` per le applicazioni in esecuzione come root e `~/Library/Application Support` per le applicazioni in esecuzione come utente.
* I **daemon** delle applicazioni di terze parti che **devono essere eseguiti come root** sono di solito situati in `/Library/PrivilegedHelperTools/`
* Le app **sandboxed** sono mappate nella cartella `~/Library/Containers`. Ogni app ha una cartella con il nome dell'ID del bundle dell'applicazione (`com.apple.Safari`).
* Il **kernel** si trova in `/System/Library/Kernels/kernel`
* Le **estensioni del kernel di Apple** si trovano in `/System/Library/Extensions`
* Le **estensioni del kernel di terze parti** sono memorizzate in `/Library/Extensions`

### File con Informazioni Sensibili

macOS memorizza informazioni come password in diversi luoghi:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Installatori pkg Vulnerabili

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Estensioni Specifiche di OS X

* **`.dmg`**: I file immagine disco di Apple sono molto frequenti per gli installatori.
* **`.kext`**: Deve seguire una struttura specifica ed è la versione OS X di un driver. (è un bundle)
* **`.plist`**: Conosciuto anche come elenco di proprietà, memorizza informazioni in formato XML o binario.
* Può essere XML o binario. Quelli binari possono essere letti con:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Applicazioni Apple che seguono la struttura delle directory (è un bundle).
* **`.dylib`**: Librerie dinamiche (come i file DLL di Windows)
* **`.pkg`**: Sono gli stessi di xar (formato di archivio eXtensible). Il comando installer può essere usato per installare i contenuti di questi file.
* **`.DS_Store`**: Questo file è in ogni directory, salva gli attributi e le personalizzazioni della directory.
* **`.Spotlight-V100`**: Questa cartella appare nella directory radice di ogni volume del sistema.
* **`.metadata_never_index`**: Se questo file è nella radice di un volume, Spotlight non indizzerà quel volume.
* **`.noindex`**: I file e le cartelle con questa estensione non verranno indicizzati da Spotlight.
* **`.sdef`**: File all'interno dei bundle che specificano come è possibile interagire con l'applicazione da uno script Apple.

### Bundle macOS

Un bundle è una **directory** che **sembra un oggetto in Finder** (un esempio di Bundle sono i file `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache Condivisa Dyld

Su macOS (e iOS) tutte le librerie di sistema condivise, come framework e dylib, sono **combinate in un singolo file**, chiamato **cache condivisa dyld**. Questo migliora le prestazioni, poiché il codice può essere caricato più velocemente.

Analogamente alla cache condivisa dyld, il kernel e le estensioni del kernel sono anche compilati in una cache del kernel, che viene caricata all'avvio.

Per estrarre le librerie dal file unico della cache condivisa dylib era possibile utilizzare il binario [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) che potrebbe non funzionare al giorno d'oggi ma puoi anche usare [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

Nelle versioni più vecchie potresti trovare la **cache condivisa** in **`/System/Library/dyld/`**.

In iOS puoi trovarle in **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Nota che anche se lo strumento `dyld_shared_cache_util` non funziona, puoi passare il **binario dyld condiviso a Hopper** e Hopper sarà in grado di identificare tutte le librerie e permetterti di **selezionare quale** vuoi investigare:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1149).png" alt="" width="563"><figcaption></figcaption></figure>

## Permessi Speciali dei File

### Permessi delle Cartelle

In una **cartella**, **read** permette di **elencarla**, **write** permette di **eliminare** e **scrivere** file al suo interno, ed **execute** permette di **attraversare** la directory. Quindi, ad esempio, un utente con **permesso di lettura su un file** all'interno di una directory dove non ha il permesso di **esecuzione non potrà leggere** il file.

### Modificatori di Flag

Ci sono alcuni flag che possono essere impostati nei file e che li faranno comportare in modo diverso. Puoi **controllare i flag** dei file all'interno di una directory con `ls -lO /percorso/directory`

* **`uchg`**: Conosciuto come flag **uchange** impedirà **qualsiasi azione** di modifica o eliminazione del **file**. Per impostarlo fai: `chflags uchg file.txt`
* L'utente root potrebbe **rimuovere il flag** e modificare il file
* **`restricted`**: Questo flag fa sì che il file sia **protetto da SIP** (non puoi aggiungere questo flag a un file).
* **`Sticky bit`**: Se una directory ha il bit sticky, **solo** il **proprietario delle directory o root può rinominare o eliminare** i file. Tipicamente questo è impostato sulla directory /tmp per impedire agli utenti ordinari di eliminare o spostare i file di altri utenti.

Tutti i flag possono essere trovati nel file `sys/stat.h` (trovalo usando `mdfind stat.h | grep stat.h`) e sono:

* `UF_SETTABLE` 0x0000ffff: Maschera dei flag modificabili dal proprietario.
* `UF_NODUMP` 0x00000001: Non eseguire il dump del file.
* `UF_IMMUTABLE` 0x00000002: Il file non può essere modificato.
* `UF_APPEND` 0x00000004: Le scritture nel file possono solo essere aggiunte.
* `UF_OPAQUE` 0x00000008: La directory è opaca rispetto all'unione.
* `UF_COMPRESSED` 0x00000020: Il file è compresso (alcuni file-system).
* `UF_TRACKED` 0x00000040: Nessuna notifica per eliminazioni/ridenominazioni per i file con questo set.
* `UF_DATAVAULT` 0x00000080: Richiesta l'abilitazione per la lettura e la scrittura.
* `UF_HIDDEN` 0x00008000: Suggerimento che questo elemento non dovrebbe essere visualizzato in un'interfaccia grafica.
* `SF_SUPPORTED` 0x009f0000: Maschera dei flag supportati dal superutente.
* `SF_SETTABLE` 0x3fff0000: Maschera dei flag modificabili dal superutente.
* `SF_SYNTHETIC` 0xc0000000: Maschera dei flag sintetici di sola lettura del sistema.
* `SF_ARCHIVED` 0x00010000: Il file è archiviato.
* `SF_IMMUTABLE` 0x00020000: Il file non può essere modificato.
* `SF_APPEND` 0x00040000: Le scritture nel file possono solo essere aggiunte.
* `SF_RESTRICTED` 0x00080000: Richiesta l'abilitazione per la scrittura.
* `SF_NOUNLINK` 0x00100000: L'elemento non può essere rimosso, rinominato o montato.
* `SF_FIRMLINK` 0x00800000: Il file è un firmlink.
* `SF_DATALESS` 0x40000000: Il file è un oggetto senza dati.

### **ACL dei File**

Gli **ACL dei file** contengono **ACE** (voci di controllo dell'accesso) dove possono essere assegnati **permessi più granulari** a diversi utenti.

È possibile concedere a una **directory** questi permessi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a un **file**: `read`, `write`, `append`, `execute`.

Quando il file contiene ACL troverai un "+" quando elenchi i permessi come in:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Puoi **leggere gli ACL** del file con:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Puoi trovare **tutti i file con ACL** con (questo è moooolto lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributi Estesi

Gli attributi estesi hanno un nome e un valore desiderato, e possono essere visualizzati utilizzando `ls -@` e manipolati utilizzando il comando `xattr`. Alcuni attributi estesi comuni sono:

- `com.apple.resourceFork`: Compatibilità con la biforcazione delle risorse. Visibile anche come `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: meccanismo di quarantena di Gatekeeper (III/6)
- `metadata:*`: MacOS: vari metadati, come `_backup_excludeItem`, o `kMD*`
- `com.apple.lastuseddate` (#PS): Data dell'ultimo utilizzo del file
- `com.apple.FinderInfo`: MacOS: informazioni del Finder (ad es., etichette di colore)
- `com.apple.TextEncoding`: Specifica la codifica del testo dei file di testo ASCII
- `com.apple.logd.metadata`: Utilizzato da logd su file in `/var/db/diagnostics`
- `com.apple.genstore.*`: Archiviazione generazionale (`/.DocumentRevisions-V100` nella radice del filesystem)
- `com.apple.rootless`: MacOS: Utilizzato da System Integrity Protection per etichettare il file (III/10)
- `com.apple.uuidb.boot-uuid`: Marcature di logd degli epoche di avvio con UUID univoci
- `com.apple.decmpfs`: MacOS: Compressione trasparente dei file (II/7)
- `com.apple.cprotect`: \*OS: Dati di crittografia per file (III/11)
- `com.apple.installd.*`: \*OS: Metadati utilizzati da installd, ad es., `installType`, `uniqueInstallID`

### Biforcazioni delle Risorse | ADS di macOS

Questo è un modo per ottenere **Stream di Dati Alternativi in macOS**. È possibile salvare contenuti all'interno di un attributo esteso chiamato **com.apple.ResourceFork** all'interno di un file salvandolo in **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puoi **trovare tutti i file che contengono questo attributo esteso** con:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

### decmpfs

L'attributo esteso `com.apple.decmpfs` indica che il file è memorizzato criptato, `ls -l` riporterà una **dimensione di 0** e i dati compressi sono all'interno di questo attributo. Ogni volta che il file viene accesso, verrà decriptato in memoria.

Questo attributo può essere visto con `ls -lO` indicato come compresso perché i file compressi sono contrassegnati anche con il flag `UF_COMPRESSED`. Se un file compresso viene rimosso, questo flag con `chflags nocompressed </percorso/al/file>`, il sistema non saprà che il file era compresso e quindi non sarà in grado di decomprimere e accedere ai dati (penserà che sia effettivamente vuoto).

Lo strumento afscexpand può essere utilizzato per forzare la decompressione di un file.

## **Universal binaries &** Formato Mach-o

Di solito i binari di Mac OS sono compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumping della memoria di macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## File di categoria di rischio di Mac OS

La directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` è dove sono memorizzate le informazioni sul **rischio associato a diverse estensioni di file**. Questa directory categorizza i file in vari livelli di rischio, influenzando come Safari gestisce questi file al momento del download. Le categorie sono le seguenti:

* **LSRiskCategorySafe**: I file in questa categoria sono considerati **completamente sicuri**. Safari aprirà automaticamente questi file dopo il download.
* **LSRiskCategoryNeutral**: Questi file non presentano avvertimenti e non vengono **aperti automaticamente** da Safari.
* **LSRiskCategoryUnsafeExecutable**: I file in questa categoria **attivano un avviso** che indica che il file è un'applicazione. Questo serve come misura di sicurezza per avvisare l'utente.
* **LSRiskCategoryMayContainUnsafeExecutable**: Questa categoria è per i file, come gli archivi, che potrebbero contenere un eseguibile. Safari **attiverà un avviso** a meno che non possa verificare che tutti i contenuti siano sicuri o neutrali.

## File di log

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene informazioni sui file scaricati, come l'URL da cui sono stati scaricati.
* **`/var/log/system.log`**: Log principale dei sistemi OSX. com.apple.syslogd.plist è responsabile dell'esecuzione del logging di sistema (puoi verificare se è disabilitato cercando "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Questi sono i Log di Sistema Apple che potrebbero contenere informazioni interessanti.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Memorizza i file e le applicazioni recentemente accessi tramite "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Memorizza gli elementi da avviare all'avvio del sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: File di log per l'app DiskUtility (informazioni su unità, inclusi USB)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dati sugli access point wireless.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Elenco dei demoni disattivati.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
