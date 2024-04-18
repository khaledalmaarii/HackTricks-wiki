# macOS SIP

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è contrastare i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

## **Informazioni di Base**

**System Integrity Protection (SIP)** in macOS è un meccanismo progettato per impedire persino agli utenti più privilegiati di apportare modifiche non autorizzate alle cartelle di sistema chiave. Questa funzionalità svolge un ruolo cruciale nel mantenere l'integrità del sistema limitando azioni come aggiungere, modificare o eliminare file in aree protette. Le cartelle principali protette da SIP includono:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Le regole che governano il comportamento di SIP sono definite nel file di configurazione situato in **`/System/Library/Sandbox/rootless.conf`**. All'interno di questo file, i percorsi che sono prefissati con un asterisco (\*) sono indicati come eccezioni alle restrizioni rigorose di SIP.

Considera l'esempio seguente:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Questo frammento implica che mentre SIP generalmente protegge la directory **`/usr`**, ci sono specifiche sottodirectory (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`) dove le modifiche sono permesse, come indicato dall'asterisco (\*) che precede i loro percorsi.

Per verificare se una directory o un file è protetto da SIP, è possibile utilizzare il comando **`ls -lOd`** per controllare la presenza del flag **`restricted`** o **`sunlnk`**. Per esempio:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In questo caso, il flag **`sunlnk`** indica che la directory `/usr/libexec/cups` stessa **non può essere eliminata**, anche se i file al suo interno possono essere creati, modificati o eliminati.

D'altra parte:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Qui, il flag **`restricted`** indica che la directory `/usr/libexec` è protetta da SIP. In una directory protetta da SIP, i file non possono essere creati, modificati o eliminati.

Inoltre, se un file contiene l'attributo esteso **`com.apple.rootless`**, quel file sarà anche **protetto da SIP**.

**SIP limita anche altre azioni di root** come:

* Caricamento di estensioni kernel non attendibili
* Ottenere porte di attività per processi firmati da Apple
* Modificare le variabili NVRAM
* Consentire il debug del kernel

Le opzioni sono mantenute nella variabile nvram come un bitflag (`csr-active-config` su Intel e `lp-sip0` è letto dall'albero dei dispositivi avviato per ARM). Puoi trovare i flag nel codice sorgente XNU in `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

### Stato di SIP

Puoi verificare se SIP è abilitato sul tuo sistema con il seguente comando:
```bash
csrutil status
```
Se hai bisogno di disabilitare SIP, devi riavviare il tuo computer in modalità di ripristino (premendo Command+R durante l'avvio), quindi eseguire il seguente comando:
```bash
csrutil disable
```
Se desideri mantenere SIP abilitato ma rimuovere le protezioni del debug, puoi farlo con:
```bash
csrutil enable --without debug
```
### Altre restrizioni

* **Vieta il caricamento di estensioni kernel non firmate** (kext), garantendo che solo le estensioni verificate interagiscano con il kernel di sistema.
* **Impedisce il debug** dei processi di sistema di macOS, proteggendo i componenti principali del sistema da accessi e modifiche non autorizzati.
* **Inibisce strumenti** come dtrace dall'ispezionare i processi di sistema, proteggendo ulteriormente l'integrità dell'operatività del sistema.

[**Per saperne di più sulle informazioni di SIP in questa presentazione**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## Bypass di SIP

Bypassare SIP consente a un attaccante di:

* **Accedere ai dati dell'utente**: Leggere dati sensibili dell'utente come posta, messaggi e cronologia di Safari di tutti gli account utente.
* **Bypass di TCC**: Manipolare direttamente il database TCC (Trasparenza, Consenso e Controllo) per concedere accesso non autorizzato alla webcam, al microfono e ad altre risorse.
* **Stabilire la persistenza**: Posizionare malware in posizioni protette da SIP, rendendolo resistente alla rimozione, anche con privilegi di root. Questo include anche la possibilità di manomettere lo Strumento di Rimozione Malware (MRT).
* **Caricare estensioni kernel**: Anche se ci sono ulteriori protezioni, bypassare SIP semplifica il processo di caricamento di estensioni kernel non firmate.

### Pacchetti di installazione

**I pacchetti di installazione firmati con il certificato di Apple** possono eludere le sue protezioni. Ciò significa che anche i pacchetti firmati da sviluppatori standard verranno bloccati se tentano di modificare directory protette da SIP.

### File SIP inesistente

Un potenziale vuoto è che se un file è specificato in **`rootless.conf` ma attualmente non esiste**, può essere creato. Il malware potrebbe sfruttare questo per **stabilire la persistenza** nel sistema. Ad esempio, un programma dannoso potrebbe creare un file .plist in `/System/Library/LaunchDaemons` se è elencato in `rootless.conf` ma non presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
L'abilitazione **`com.apple.rootless.install.heritable`** consente di eludere SIP
{% endhint %}

#### Shrootless

[**Ricercatori da questo post sul blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) hanno scoperto una vulnerabilità nel meccanismo di Protezione dell'Integrità di Sistema (SIP) di macOS, chiamata vulnerabilità 'Shrootless'. Questa vulnerabilità ruota attorno al demone **`system_installd`**, che ha un'abilitazione, **`com.apple.rootless.install.heritable`**, che consente a uno qualsiasi dei suoi processi figlio di eludere le restrizioni del sistema di file di SIP.

Il demone **`system_installd`** installerà pacchetti firmati da **Apple**.

I ricercatori hanno scoperto che durante l'installazione di un pacchetto firmato da Apple (.pkg), **`system_installd`** **esegue** eventuali **script post-installazione** inclusi nel pacchetto. Questi script vengono eseguiti dal terminale predefinito, **`zsh`**, che esegue automaticamente i comandi dal file **`/etc/zshenv`**, se esiste, anche in modalità non interattiva. Questo comportamento potrebbe essere sfruttato dagli attaccanti: creando un file `/etc/zshenv` dannoso e aspettando che **`system_installd` invochi `zsh`**, potrebbero eseguire operazioni arbitrarie sul dispositivo.

Inoltre, è stato scoperto che **`/etc/zshenv` potrebbe essere utilizzato come tecnica di attacco generale**, non solo per un bypass di SIP. Ogni profilo utente ha un file `~/.zshenv`, che si comporta allo stesso modo di `/etc/zshenv` ma non richiede permessi di root. Questo file potrebbe essere utilizzato come meccanismo di persistenza, attivandosi ogni volta che `zsh` si avvia, o come meccanismo di elevazione dei privilegi. Se un utente amministratore si eleva a root usando `sudo -s` o `sudo <comando>`, il file `~/.zshenv` verrebbe attivato, elevando efficacemente a root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) è stato scoperto che lo stesso processo **`system_installd`** poteva comunque essere abusato perché metteva lo **script post-installazione dentro una cartella con nome casuale protetta da SIP dentro `/tmp`**. Il punto è che **`/tmp` di per sé non è protetto da SIP**, quindi era possibile **montare** un'**immagine virtuale su di esso**, quindi l'**installatore** avrebbe messo lì lo **script post-installazione**, **smontato** l'immagine virtuale, **ricreato** tutte le **cartelle** e **aggiunto** lo **script di post-installazione** con il **payload** da eseguire.

#### [utility fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

È stata identificata una vulnerabilità in cui **`fsck_cs`** è stato ingannato nel corrompere un file cruciale, a causa della sua capacità di seguire i **link simbolici**. In particolare, gli attaccanti hanno creato un link da _`/dev/diskX`_ al file `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Eseguire **`fsck_cs`** su _`/dev/diskX`_ ha portato alla corruzione di `Info.plist`. L'integrità di questo file è vitale per la Protezione dell'Integrità di Sistema (SIP) del sistema operativo, che controlla il caricamento delle estensioni kernel. Una volta corrotto, la capacità di SIP di gestire le esclusioni del kernel è compromessa.

I comandi per sfruttare questa vulnerabilità sono:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
L'exploit di questa vulnerabilità ha gravi implicazioni. Il file `Info.plist`, normalmente responsabile della gestione delle autorizzazioni per le estensioni del kernel, diventa inefficace. Ciò include l'incapacità di mettere in blacklist alcune estensioni, come `AppleHWAccess.kext`. Di conseguenza, con il meccanismo di controllo di SIP fuori uso, questa estensione può essere caricata, concedendo accesso non autorizzato in lettura e scrittura alla RAM del sistema.

#### [Montare sopra le cartelle protette da SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Era possibile montare un nuovo sistema di file sopra le **cartelle protette da SIP per eludere la protezione**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass dell'aggiornamento (2016)](https://objective-see.org/blog/blog\_0x14.html)

Il sistema è impostato per avviarsi da un'immagine disco dell'installatore incorporata all'interno di `Install macOS Sierra.app` per aggiornare il sistema operativo, utilizzando l'utilità `bless`. Il comando utilizzato è il seguente:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La sicurezza di questo processo può essere compromessa se un attaccante altera l'immagine di aggiornamento (`InstallESD.dmg`) prima del boot. La strategia prevede la sostituzione di un caricatore dinamico (dyld) con una versione dannosa (`libBaseIA.dylib`). Questa sostituzione porta all'esecuzione del codice dell'attaccante quando l'installazione viene avviata.

Il codice dell'attaccante prende il controllo durante il processo di aggiornamento, sfruttando la fiducia del sistema nell'installatore. L'attacco procede alterando l'immagine `InstallESD.dmg` tramite method swizzling, prendendo di mira in particolare il method `extractBootBits`. Questo consente l'iniezione di codice dannoso prima che l'immagine del disco venga impiegata.

Inoltre, all'interno di `InstallESD.dmg`, c'è un `BaseSystem.dmg`, che funge da sistema di file radice del codice di aggiornamento. L'iniezione di una libreria dinamica in questo permette al codice dannoso di operare all'interno di un processo in grado di alterare file di livello OS, aumentando significativamente il potenziale di compromissione del sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In questa presentazione da [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), viene mostrato come **`systemmigrationd`** (che può eludere SIP) esegue uno script **bash** e **perl**, che possono essere abusati tramite le variabili d'ambiente **`BASH_ENV`** e **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
L'entitlement **`com.apple.rootless.install`** consente di eludere SIP
{% endhint %}

L'entitlement `com.apple.rootless.install` è noto per eludere la Protezione dell'Integrità del Sistema (SIP) su macOS. Questo è stato menzionato in modo significativo in relazione a [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In questo caso specifico, il servizio XPC di sistema situato in `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possiede questo entitlement. Ciò consente al processo correlato di aggirare i vincoli di SIP. Inoltre, questo servizio presenta in modo significativo un metodo che permette lo spostamento di file senza applicare misure di sicurezza.

## Snapshot di Sistema Sigillati

I Snapshot di Sistema Sigillati sono una funzionalità introdotta da Apple in **macOS Big Sur (macOS 11)** come parte del meccanismo di **Protezione dell'Integrità del Sistema (SIP)** per fornire un ulteriore livello di sicurezza e stabilità del sistema. Sono essenzialmente versioni in sola lettura del volume di sistema.

Ecco uno sguardo più dettagliato:

1. **Sistema Immutabile**: I Snapshot di Sistema Sigillati rendono il volume di sistema macOS "immutabile", il che significa che non può essere modificato. Ciò impedisce qualsiasi modifica non autorizzata o accidentale al sistema che potrebbe compromettere la sicurezza o la stabilità del sistema.
2. **Aggiornamenti del Software di Sistema**: Quando si installano aggiornamenti o upgrade di macOS, macOS crea un nuovo snapshot di sistema. Il volume di avvio di macOS utilizza quindi **APFS (Apple File System)** per passare a questo nuovo snapshot. L'intero processo di applicazione degli aggiornamenti diventa più sicuro e affidabile poiché il sistema può sempre tornare al snapshot precedente se qualcosa va storto durante l'aggiornamento.
3. **Separazione dei Dati**: In congiunzione con il concetto di separazione dei volumi Dati e Sistema introdotto in macOS Catalina, la funzionalità Snapshot di Sistema Sigillati garantisce che tutti i dati e le impostazioni siano memorizzati su un volume "**Dati**" separato. Questa separazione rende i dati indipendenti dal sistema, semplificando il processo di aggiornamento del sistema e migliorando la sicurezza del sistema.

Ricorda che questi snapshot sono gestiti automaticamente da macOS e non occupano spazio aggiuntivo sul disco, grazie alle capacità di condivisione dello spazio di APFS. È importante notare che questi snapshot sono diversi dai **snapshot di Time Machine**, che sono backup accessibili dall'utente dell'intero sistema.

### Verifica Snapshot

Il comando **`diskutil apfs list`** elenca i **dettagli dei volumi APFS** e la loro disposizione:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Riferimento Contenitore APFS:     disk3
|   Dimensione (Capacità Massima):    494384795648 B (494.4 GB)
|   Capacità Utilizzata Dai Volumi:   219214536704 B (219.2 GB) (44.3% utilizzata)
|   Capacità Non Allocata:            275170258944 B (275.2 GB) (55.7% libera)
|   |
|   +-&#x3C; Archivio Fisico disco0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Disco Archivio Fisico APFS:   disco0s2
|   |   Dimensione:                   494384795648 B (494.4 GB)
|   |
|   +-> Volume disco3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Volume Disco APFS (Ruolo):   disco3s1 (Sistema)
</strong>|   |   Nome:                      Macintosh HD (Case-insensitive)
<strong>|   |   Punto di Montaggio:         /System/Volumes/Update/mnt1
</strong>|   |   Capacità Consumata:         12819210240 B (12.8 GB)
|   |   Sigillato:                    Rotto
|   |   FileVault:                   Sì (Sbloccato)
|   |   Crittografato:               No
|   |   |
|   |   Snapshot:                    FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disco Snapshot:               disco3s1s1
<strong>|   |   Punto di Montaggio Snapshot:  /
</strong><strong>|   |   Sigillato Snapshot:           Sì
</strong>[...]
+-> Volume disco3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Volume Disco APFS (Ruolo):   disco3s5 (Dati)
|   Nome:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Punto di Montaggio:         /System/Volumes/Data
</strong><strong>    |   Capacità Consumata:         412071784448 B (412.1 GB)
</strong>    |   Sigillato:                    No
|   FileVault:                   Sì (Sbloccato)
</code></pre>

Nell'output precedente è possibile vedere che le **posizioni accessibili dall'utente** sono montate sotto `/System/Volumes/Data`.

Inoltre, lo **snapshot del volume di sistema macOS** è montato in `/` ed è **sigillato** (firmato crittograficamente dal sistema operativo). Quindi, se SIP viene eluso e modificato, il **sistema operativo non si avvierà più**.

È anche possibile **verificare che il sigillo sia abilitato** eseguendo:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Inoltre, il disco snapshot è montato anche come **sola lettura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
