# File, Cartelle, Binari e Memoria di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Layout della gerarchia dei file

* **/Applications**: Le app installate dovrebbero essere qui. Tutti gli utenti saranno in grado di accedervi.
* **/bin**: Binari della riga di comando
* **/cores**: Se esiste, viene utilizzato per archiviare i core dump
* **/dev**: Tutto viene trattato come un file, quindi è possibile trovare qui dispositivi hardware.
* **/etc**: File di configurazione
* **/Library**: Molte sottodirectory e file relativi a preferenze, cache e registri possono essere trovati qui. Esiste una cartella Library nella root e in ogni directory dell'utente.
* **/private**: Non documentato, ma molte delle cartelle menzionate sono collegamenti simbolici alla directory privata.
* **/sbin**: Binari di sistema essenziali (relativi all'amministrazione)
* **/System**: File per far funzionare OS X. Qui dovresti trovare principalmente file specifici di Apple (non di terze parti).
* **/tmp**: I file vengono eliminati dopo 3 giorni (è un collegamento simbolico a /private/tmp)
* **/Users**: Directory home degli utenti.
* **/usr**: Configurazione e binari di sistema
* **/var**: File di registro
* **/Volumes**: Le unità montate appariranno qui.
* **/.vol**: Eseguendo `stat a.txt` otterrai qualcosa del genere `16777223 7545753 -rw-r--r-- 1 username wheel ...`, dove il primo numero è l'id del volume in cui si trova il file e il secondo è il numero di inode. Puoi accedere al contenuto di questo file tramite /.vol/ con queste informazioni eseguendo `cat /.vol/16777223/7545753`

### Cartelle delle applicazioni

* Le **applicazioni di sistema** si trovano in `/System/Applications`
* Le applicazioni **installate** di solito vengono installate in `/Applications` o in `~/Applications`
* I **dati dell'applicazione** possono essere trovati in `/Library/Application Support` per le applicazioni in esecuzione come root e `~/Library/Application Support` per le applicazioni in esecuzione come utente.
* I **daemon** delle applicazioni di terze parti che **devono essere eseguiti come root** di solito si trovano in `/Library/PrivilegedHelperTools/`
* Le app **sandboxed** sono mappate nella cartella `~/Library/Containers`. Ogni app ha una cartella con il nome dell'ID del bundle dell'applicazione (`com.apple.Safari`).
* Il **kernel** si trova in `/System/Library/Kernels/kernel`
* Le **estensioni del kernel di Apple** si trovano in `/System/Library/Extensions`
* Le **estensioni del kernel di terze parti** sono memorizzate in `/Library/Extensions`

### File con informazioni sensibili

macOS memorizza informazioni come password in diversi luoghi:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Installatori pkg vulnerabili

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Estensioni specifiche di OS X

* **`.dmg`**: I file di immagine disco di Apple sono molto frequenti per gli installatori.
* **`.kext`**: Deve seguire una struttura specifica ed è la versione di OS X di un driver. (è un bundle)
* **`.plist`**: Conosciuto anche come property list, memorizza informazioni in formato XML o binario.
* Può essere XML o binario. Quelli binari possono essere letti con:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Applicazioni Apple che seguono la struttura delle directory (è un bundle).
* **`.dylib`**: Librerie dinamiche (come i file DLL di Windows)
* **`.pkg`**: Sono gli stessi di xar (formato di archivio estensibile). Il comando installer può essere utilizzato per installare i contenuti di questi file.
* **`.DS_Store`**: Questo file è presente in ogni directory, salva gli attributi e le personalizzazioni della directory.
* **`.Spotlight-V100`**: Questa cartella appare nella directory radice di ogni volume del sistema.
* **`.metadata_never_index`**: Se questo file si trova alla radice di un volume, Spotlight non indizzerà quel volume.
* **`.noindex`**: I file e le cartelle con questa estensione non verranno indicizzati da Spotlight.

### Bundle di macOS

Un bundle è una **directory** che **sembra un oggetto in Finder** (un esempio di bundle sono i file `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

Su macOS (e iOS) tutte le librerie condivise di sistema, come framework e dylib, vengono **combinate in un singolo file**, chiamato **dyld shared cache**. Questo migliora le prestazioni, poiché il codice può essere caricato più velocemente.

Analogamente alla dyld shared cache, il kernel e le estensioni del kernel vengono anche compilati in una cache del kernel, che viene caricata all'avvio.

Per estrarre le librerie dal file singolo dylib shared cache era possibile utilizzare il binario [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) che potrebbe non funzionare al giorno d'oggi, ma è possibile utilizzare anche [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

Nelle versioni più vecchie potresti essere in grado di trovare la **cache condivisa** in **`/System/Library/dyld/`**.

In iOS puoi trovarli in **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Nota che anche se lo strumento `dyld_shared_cache_util` non funziona, puoi passare il **binario dyld condiviso a Hopper** e Hopper sarà in grado di identificare tutte le librerie e permetterti di **selezionare quella** che desideri investigare:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Permessi speciali dei file

### Permessi delle cartelle

In una **cartella**, **read** permette di **elencarla**, **write** permette di **eliminare** e **scrivere** file al suo interno, e **execute** permette di **attraversare** la directory. Quindi, ad esempio, un utente con **permesso di lettura su un file** all'interno di una directory in cui non ha il permesso di **esecuzione non sarà in grado di leggere** il file.

### Flag modificatori

Ci sono alcuni flag che possono essere impostati sui file e che ne modificano il comportamento. Puoi **controllare i flag** dei file all'interno di una directory con `ls -lO /percorso/directory`

* **`uchg`**: Conosciuto come flag **uchange** impedirà qualsiasi azione di modifica o eliminazione del **file**. Per impostarlo: `chflags uchg file.txt`
* L'utente root può **rimuovere il flag** e modificare il file
* **`restricted`**: Questo flag rende il file **protetto da SIP** (non puoi aggiungere questo flag a un file).
* **`Sticky bit`**: Se una directory ha il bit sticky, **solo** il **proprietario della directory o root può rinominare o eliminare** i file. Tipicamente questo viene impostato sulla directory /tmp per impedire agli utenti ordinari di eliminare o spostare i file di altri utenti.

### **File ACL**

Le ACL dei file contengono **ACE** (Access Control Entries) in cui possono essere assegnati permessi più **granulari** a diversi utenti.

È possibile concedere a una **directory** questi permessi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a un **file**: `read`, `write`, `append`, `execute`.

Quando il file contiene ACL, troverai un "+" quando elenchi i permessi come in:
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
### Forchette di risorse | ADS di macOS

Questa è un modo per ottenere **Alternate Data Streams in MacOS**. Puoi salvare il contenuto all'interno di un attributo esteso chiamato **com.apple.ResourceFork** all'interno di un file salvandolo in **file/..namedfork/rsrc**.
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

## **Universal binaries &** Mach-o Format

I binari di Mac OS di solito vengono compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumping della memoria di macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## File di categoria di rischio di Mac OS

La directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` è dove vengono memorizzate le informazioni sul **rischio associato a diverse estensioni di file**. Questa directory categorizza i file in vari livelli di rischio, influenzando il modo in cui Safari gestisce questi file al momento del download. Le categorie sono le seguenti:

- **LSRiskCategorySafe**: I file in questa categoria sono considerati **completamente sicuri**. Safari aprirà automaticamente questi file dopo il download.
- **LSRiskCategoryNeutral**: Questi file non presentano avvertimenti e non vengono aperti automaticamente da Safari.
- **LSRiskCategoryUnsafeExecutable**: I file in questa categoria **generano un avviso** che indica che il file è un'applicazione. Questo serve come misura di sicurezza per avvisare l'utente.
- **LSRiskCategoryMayContainUnsafeExecutable**: Questa categoria è per i file, come gli archivi, che potrebbero contenere un eseguibile. Safari **genererà un avviso** a meno che non possa verificare che tutti i contenuti siano sicuri o neutrali.

## File di registro

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene informazioni sui file scaricati, come l'URL da cui sono stati scaricati.
* **`/var/log/system.log`**: Registro principale dei sistemi OSX. com.apple.syslogd.plist è responsabile dell'esecuzione del syslog (puoi verificare se è disabilitato cercando "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Questi sono i log di sistema di Apple che possono contenere informazioni interessanti.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Memorizza i file e le applicazioni recentemente accessi tramite "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Memorizza gli elementi da avviare all'avvio del sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: File di registro per l'app DiskUtility (informazioni su unità, inclusi USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dati sugli access point wireless.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Elenco dei daemon disattivati.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
