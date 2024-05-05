# Abuso degli Installatori macOS

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Informazioni di Base su Pkg

Un **pacchetto di installazione macOS** (noto anche come file `.pkg`) è un formato di file utilizzato da macOS per **distribuire software**. Questi file sono come una **scatola che contiene tutto ciò di cui un software** ha bisogno per installarsi ed eseguirsi correttamente.

Il file del pacchetto stesso è un archivio che contiene una **gerarchia di file e directory che verranno installati sul computer di destinazione**. Può anche includere **script** per eseguire attività prima e dopo l'installazione, come configurare file di configurazione o pulire vecchie versioni del software.

### Gerarchia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribuzione (xml)**: Personalizzazioni (titolo, testo di benvenuto...) e controlli di script/installazione
* **PackageInfo (xml)**: Informazioni, requisiti di installazione, posizione di installazione, percorsi agli script da eseguire
* **Elenco dei materiali (bom)**: Elenco dei file da installare, aggiornare o rimuovere con permessi di file
* **Payload (archivio CPIO compresso gzip)**: File da installare nella `posizione-di-installazione` da PackageInfo
* **Script (archivio CPIO compresso gzip)**: Script di installazione precedenti e successivi e altre risorse estratte in una directory temporanea per l'esecuzione.

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
Per visualizzare i contenuti dell'installer senza decomprimerlo manualmente, è possibile utilizzare il tool gratuito [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Informazioni di Base sui DMG

I file DMG, o Apple Disk Images, sono un formato di file utilizzato da macOS di Apple per le immagini disco. Un file DMG è essenzialmente un **immagine disco montabile** (contiene il proprio filesystem) che contiene dati di blocco grezzi tipicamente compressi e talvolta criptati. Quando apri un file DMG, macOS lo **monta come se fosse un disco fisico**, consentendoti di accedere ai suoi contenuti.

{% hint style="danger" %}
Nota che gli installer **`.dmg`** supportano **così tanti formati** che in passato alcuni di essi contenenti vulnerabilità sono stati abusati per ottenere **esecuzione di codice kernel**.
{% endhint %}

### Gerarchia

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

La gerarchia di un file DMG può essere diversa in base al contenuto. Tuttavia, per i DMG delle applicazioni, di solito segue questa struttura:

- Livello Superiore: Questo è la radice dell'immagine disco. Contiene spesso l'applicazione e eventualmente un collegamento alla cartella Applicazioni.
- Applicazione (.app): Questa è l'applicazione effettiva. In macOS, un'applicazione è tipicamente un pacchetto che contiene molti file e cartelle individuali che compongono l'applicazione.
- Collegamento alle Applicazioni: Questo è un collegamento rapido alla cartella Applicazioni in macOS. Lo scopo di questo è rendere facile l'installazione dell'applicazione. Puoi trascinare il file .app su questo collegamento per installare l'app.

## Privesc tramite abuso di pkg

### Esecuzione da directory pubbliche

Se uno script di pre o post installazione ad esempio viene eseguito da **`/var/tmp/Installerutil`**, e un attaccante potrebbe controllare tale script per ottenere privilegi ogni volta che viene eseguito. Oppure un altro esempio simile:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Questa è una [funzione pubblica](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) che diversi installer e aggiornatori chiameranno per **eseguire qualcosa come root**. Questa funzione accetta il **percorso** del **file** da **eseguire** come parametro, tuttavia, se un attaccante potesse **modificare** questo file, sarà in grado di **abusare** della sua esecuzione con privilegi di root per **escalare i privilegi**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Esecuzione tramite mountaggio

Se un programma di installazione scrive in `/tmp/fixedname/bla/bla`, è possibile **creare un mount** su `/tmp/fixedname` senza proprietari in modo da poter **modificare qualsiasi file durante l'installazione** per abusare del processo di installazione.

Un esempio di ciò è **CVE-2021-26089** che è riuscito a **sovrascrivere uno script periodico** per ottenere l'esecuzione come root. Per ulteriori informazioni, guarda il talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg come malware

### Payload vuoto

È possibile generare un file **`.pkg`** con **script pre e post-installazione** senza alcun payload.

### JS in Distribution xml

È possibile aggiungere tag **`<script>`** nel file **xml di distribuzione** del pacchetto e quel codice verrà eseguito e può **eseguire comandi** utilizzando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Riferimenti

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
