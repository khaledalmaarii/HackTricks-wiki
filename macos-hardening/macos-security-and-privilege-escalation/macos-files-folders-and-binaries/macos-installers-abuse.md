# Abuso degli installer di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

## Informazioni di base sui pacchetti Pkg

Un **installer package** di macOS (noto anche come file `.pkg`) è un formato di file utilizzato da macOS per **distribuire software**. Questi file sono come una **scatola che contiene tutto ciò di cui un software** ha bisogno per installarsi ed eseguirsi correttamente.

Il file del pacchetto stesso è un archivio che contiene una **gerarchia di file e directory che verranno installati nel computer di destinazione**. Può anche includere **script** per eseguire operazioni prima e dopo l'installazione, come la configurazione dei file di configurazione o la pulizia delle vecchie versioni del software.

### Gerarchia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Personalizzazioni (titolo, testo di benvenuto...) e controlli di script/installazione
* **PackageInfo (xml)**: Informazioni, requisiti di installazione, posizione di installazione, percorsi degli script da eseguire
* **Bill of materials (bom)**: Elenco dei file da installare, aggiornare o rimuovere con le autorizzazioni dei file
* **Payload (archivio CPIO compresso con gzip)**: File da installare nella `install-location` da PackageInfo
* **Scripts (archivio CPIO compresso con gzip)**: Script di installazione precedenti e successivi e altre risorse estratte in una directory temporanea per l'esecuzione.

### Decomprimere
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Informazioni di base sui file DMG

I file DMG, o Apple Disk Images, sono un formato di file utilizzato da macOS di Apple per le immagini dei dischi. Un file DMG è essenzialmente un'immagine di disco montabile (contiene il proprio filesystem) che contiene dati di blocco grezzi compressi e talvolta crittografati. Quando apri un file DMG, macOS lo monta come se fosse un disco fisico, consentendoti di accedere ai suoi contenuti.

### Gerarchia

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

La gerarchia di un file DMG può essere diversa in base al contenuto. Tuttavia, per i file DMG delle applicazioni, di solito segue questa struttura:

* Livello superiore: questo è la radice dell'immagine del disco. Spesso contiene l'applicazione e eventualmente un collegamento alla cartella Applicazioni.
* Applicazione (.app): questa è l'applicazione effettiva. In macOS, un'applicazione è tipicamente un pacchetto che contiene molti file e cartelle individuali che compongono l'applicazione.
* Collegamento alle applicazioni: questo è un collegamento rapido alla cartella Applicazioni in macOS. Lo scopo di questo collegamento è semplificare l'installazione dell'applicazione. Puoi trascinare il file .app su questo collegamento per installare l'app.

## Privesc tramite abuso di pkg

### Esecuzione da directory pubbliche

Se uno script di installazione pre o post viene ad esempio eseguito da **`/var/tmp/Installerutil`**, un attaccante potrebbe controllare tale script per ottenere privilegi elevati ogni volta che viene eseguito. Oppure un altro esempio simile:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Questa è una [funzione pubblica](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) che diversi programmi di installazione e aggiornamento chiameranno per eseguire qualcosa come root. Questa funzione accetta il **percorso** del **file** da **eseguire** come parametro, tuttavia, se un attaccante potesse **modificare** questo file, sarebbe in grado di **abusarne** l'esecuzione con privilegi di root per **elevare i privilegi**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Per ulteriori informazioni, guarda questa presentazione: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Esecuzione tramite montaggio

Se un installer scrive su `/tmp/fixedname/bla/bla`, è possibile **creare un mount** su `/tmp/fixedname` senza proprietari, in modo da poter **modificare qualsiasi file durante l'installazione** per abusare del processo di installazione.

Un esempio di ciò è **CVE-2021-26089**, che è riuscito a **sovrascrivere uno script periodico** per ottenere l'esecuzione come root. Per ulteriori informazioni, guarda la presentazione: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg come malware

### Payload vuoto

È possibile generare semplicemente un file **`.pkg`** con script di **pre e post-installazione** senza alcun payload.

### JS in Distribution xml

È possibile aggiungere tag **`<script>`** nel file **distribution xml** del pacchetto e quel codice verrà eseguito e può **eseguire comandi** utilizzando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Riferimenti

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
