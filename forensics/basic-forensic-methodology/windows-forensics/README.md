# Artefatti di Windows

## Artefatti di Windows

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Artefatti Generici di Windows

### Notifiche di Windows 10

Nel percorso `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` è possibile trovare il database `appdb.dat` (prima dell'anniversario di Windows) o `wpndatabase.db` (dopo l'anniversario di Windows).

All'interno di questo database SQLite, è possibile trovare la tabella `Notification` con tutte le notifiche (in formato XML) che possono contenere dati interessanti.

### Timeline

La Timeline è una caratteristica di Windows che fornisce una **cronologia cronologica** delle pagine web visitate, dei documenti modificati e delle applicazioni eseguite.

Il database risiede nel percorso `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Questo database può essere aperto con uno strumento SQLite o con lo strumento [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **che genera 2 file che possono essere aperti con lo strumento** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Flussi di Dati Alternativi)

I file scaricati possono contenere la **ADS Zone.Identifier** che indica **come** è stato **scaricato** dall'intranet, internet, ecc. Alcuni software (come i browser) di solito inseriscono ancora **più** **informazioni** come l'**URL** da cui è stato scaricato il file.

## **Backup dei File**

### Cestino

In Vista/Win7/Win8/Win10 il **Cestino** si trova nella cartella **`$Recycle.bin`** nella radice del drive (`C:\$Recycle.bin`).\
Quando un file viene eliminato in questa cartella vengono creati 2 file specifici:

* `$I{id}`: Informazioni sul file (data in cui è stato eliminato)
* `$R{id}`: Contenuto del file

![](<../../../.gitbook/assets/image (486).png>)

Avendo questi file è possibile utilizzare lo strumento [**Rifiuti**](https://github.com/abelcheung/rifiuti2) per ottenere l'indirizzo originale dei file eliminati e la data in cui sono stati eliminati (usare `rifiuti-vista.exe` per Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Copie delle ombre del volume

Shadow Copy è una tecnologia inclusa in Microsoft Windows che può creare **copie di backup** o snapshot dei file o volumi del computer, anche quando sono in uso.

Questi backup sono di solito situati in `\System Volume Information` dalla radice del sistema di file e il nome è composto da **UID** mostrati nell'immagine seguente:

![](<../../../.gitbook/assets/image (520).png>)

Montando l'immagine forense con **ArsenalImageMounter**, lo strumento [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) può essere utilizzato per ispezionare una copia delle ombre e anche **estrarre i file** dai backup delle copie delle ombre.

![](<../../../.gitbook/assets/image (521).png>)

L'entry del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene i file e le chiavi **da non eseguire il backup**:

![](<../../../.gitbook/assets/image (522).png>)

Il registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contiene anche informazioni di configurazione sulle `Volume Shadow Copies`.

### File di salvataggio automatico di Office

È possibile trovare i file di salvataggio automatico di Office in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementi della shell

Un elemento della shell è un elemento che contiene informazioni su come accedere a un altro file.

### Documenti recenti (LNK)

Windows **crea automaticamente** queste **scorciatoie** quando l'utente **apre, utilizza o crea un file** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando viene creata una cartella, viene creata anche una scorciatoia alla cartella, alla cartella genitore e alla cartella nonna.

Questi file di collegamento creati automaticamente **contengono informazioni sull'origine** come se si tratti di un **file** **o** di una **cartella**, **orari MAC** di quel file, **informazioni sul volume** di dove è memorizzato il file e **cartella del file di destinazione**. Queste informazioni possono essere utili per recuperare quei file nel caso in cui siano stati rimossi.

Inoltre, la **data di creazione del file di collegamento** è la prima **volta** in cui il file originale è stato **utilizzato** e la **data** **modificata** del file di collegamento è l'**ultima** **volta** in cui il file di origine è stato utilizzato.

Per ispezionare questi file è possibile utilizzare [**LinkParser**](http://4discovery.com/our-tools/).

In questo strumento troverai **2 set** di timestamp:

* **Primo set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Secondo set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Il primo set di timestamp fa riferimento ai **timestamp del file stesso**. Il secondo set fa riferimento ai **timestamp del file collegato**.

È possibile ottenere le stesse informazioni eseguendo lo strumento della riga di comando di Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### Jumplists

Questi sono i file recenti indicati per applicazione. È l'elenco dei **file recenti utilizzati da un'applicazione** a cui è possibile accedere su ciascuna applicazione. Possono essere creati **automaticamente o personalizzati**.

I **jumplists** creati automaticamente sono memorizzati in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. I jumplists sono nominati seguendo il formato `{id}.autmaticDestinations-ms` dove l'ID iniziale è l'ID dell'applicazione.

I jumplists personalizzati sono memorizzati in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e sono creati dall'applicazione di solito perché è successo qualcosa di **importante** con il file (forse contrassegnato come preferito).

Il **tempo di creazione** di qualsiasi jumplist indica **la prima volta in cui il file è stato accesso** e il **tempo di modifica l'ultima volta**.

È possibile ispezionare i jumplists utilizzando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(Si noti che i timestamp forniti da JumplistExplorer sono relativi al file jumplist stesso)

### Shellbags

[**Segui questo link per saperne di più su cosa sono le shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilizzo delle chiavette USB di Windows

È possibile identificare l'uso di un dispositivo USB grazie alla creazione di:

* Cartella Recent di Windows
* Cartella Recent di Microsoft Office
* Jumplists

Si noti che alcuni file LNK invece di puntare al percorso originale, puntano alla cartella WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

I file nella cartella WPDNSE sono una copia di quelli originali, quindi non sopravviveranno a un riavvio del PC e il GUID è preso da una shellbag.

### Informazioni del Registro di Sistema

[Controlla questa pagina per sapere](interesting-windows-registry-keys.md#usb-information) quali chiavi di registro contengono informazioni interessanti sui dispositivi USB collegati.

### setupapi

Controlla il file `C:\Windows\inf\setupapi.dev.log` per ottenere i timestamp su quando è stata prodotta la connessione USB (cerca `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati collegati a un'immagine.

![](<../../../.gitbook/assets/image (483).png>)

### Pulizia Plug and Play

Il task pianificato noto come 'Pulizia Plug and Play' è principalmente progettato per la rimozione delle versioni obsolete dei driver. Contrariamente al suo scopo specificato di mantenere la versione più recente del pacchetto driver, fonti online suggeriscono che miri anche ai driver inattivi da 30 giorni. Di conseguenza, i driver per dispositivi rimovibili non collegati negli ultimi 30 giorni potrebbero essere soggetti a cancellazione.

Il task si trova nel seguente percorso:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Viene fornita una schermata che mostra il contenuto del task:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componenti chiave e impostazioni del task:**
- **pnpclean.dll**: Questa DLL è responsabile del processo effettivo di pulizia.
- **UseUnifiedSchedulingEngine**: Impostato su `TRUE`, indicando l'uso del motore di pianificazione dei task generico.
- **MaintenanceSettings**:
- **Period ('P1M')**: Indirizza il Task Scheduler ad avviare il task di pulizia mensilmente durante la manutenzione automatica regolare.
- **Deadline ('P2M')**: Istruisce il Task Scheduler, se il task fallisce per due mesi consecutivi, ad eseguire il task durante la manutenzione automatica di emergenza.

Questa configurazione garantisce una manutenzione regolare e la pulizia dei driver, con disposizioni per ripetere il task in caso di fallimenti consecutivi.

**Per ulteriori informazioni controlla:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Email

Le email contengono **2 parti interessanti: gli header e il contenuto** dell'email. Negli **header** è possibile trovare informazioni come:

* **Chi** ha inviato le email (indirizzo email, IP, server di posta che ha reindirizzato l'email)
* **Quando** è stata inviata l'email

Inoltre, all'interno degli header `References` e `In-Reply-To` è possibile trovare l'ID dei messaggi:

![](<../../../.gitbook/assets/image (484).png>)

### App Mail di Windows

Questa applicazione salva le email in HTML o testo. È possibile trovare le email all'interno delle sottocartelle all'interno di `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Le email sono salvate con l'estensione `.dat`.

I **metadati** delle email e i **contatti** possono essere trovati all'interno del **database EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia l'estensione** del file da `.vol` a `.edb` e puoi utilizzare lo strumento [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) per aprirlo. All'interno della tabella `Message` è possibile vedere le email.

### Microsoft Outlook

Quando vengono utilizzati server Exchange o client Outlook ci saranno alcuni header MAPI:

* `Mapi-Client-Submit-Time`: Ora del sistema in cui è stata inviata l'email
* `Mapi-Conversation-Index`: Numero di messaggi figli del thread e timestamp di ciascun messaggio del thread
* `Mapi-Entry-ID`: Identificatore del messaggio.
* `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: Informazioni sul client MAPI (messaggio letto? non letto? risposto? reindirizzato? fuori sede?)

Nel client Microsoft Outlook, tutti i messaggi inviati/ricevuti, i dati dei contatti e i dati del calendario sono memorizzati in un file PST in:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Il percorso nel registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica il file che viene utilizzato.

È possibile aprire il file PST utilizzando lo strumento [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)
### File OST di Microsoft Outlook

Un file **OST** è generato da Microsoft Outlook quando è configurato con un server **IMAP** o **Exchange**, memorizzando informazioni simili a un file PST. Questo file è sincronizzato con il server, conservando i dati degli **ultimi 12 mesi** fino a una **dimensione massima di 50GB**, ed è situato nella stessa directory del file PST. Per visualizzare un file OST, può essere utilizzato il [**visualizzatore OST Kernel**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recupero degli Allegati

Gli allegati persi potrebbero essere recuperabili da:

- Per **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Per **IE11 e versioni successive**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### File MBOX di Thunderbird

**Thunderbird** utilizza file **MBOX** per memorizzare i dati, situati in `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Anteprime delle Immagini

- **Windows XP e 8-8.1**: Accedendo a una cartella con anteprime si genera un file `thumbs.db` che memorizza anteprime delle immagini, anche dopo l'eliminazione.
- **Windows 7/10**: `thumbs.db` viene creato quando si accede tramite un percorso UNC su una rete.
- **Windows Vista e versioni successive**: Le anteprime delle miniature sono centralizzate in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` con file denominati **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) e [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sono strumenti per visualizzare questi file.

### Informazioni nel Registro di Windows

Il Registro di Windows, che memorizza dati estesi sul sistema e sull'attività dell'utente, è contenuto in file in:

- `%windir%\System32\Config` per varie sottochiavi di `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` per `HKEY_CURRENT_USER`.
- Windows Vista e versioni successive effettuano il backup dei file del registro di `HKEY_LOCAL_MACHINE` in `%Windir%\System32\Config\RegBack\`.
- Inoltre, le informazioni sull'esecuzione dei programmi sono memorizzate in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` da Windows Vista e Windows 2008 Server in poi.

### Strumenti

Alcuni strumenti sono utili per analizzare i file di registro:

* **Editor del Registro di Sistema**: È installato in Windows. È un'interfaccia grafica per navigare nel registro di Windows della sessione corrente.
* [**Esploratore del Registro**](https://ericzimmerman.github.io/#!index.md): Consente di caricare il file di registro e navigarvi con un'interfaccia grafica. Contiene anche segnalibri che evidenziano chiavi con informazioni interessanti.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ha nuovamente un'interfaccia grafica che consente di navigare nel registro caricato e contiene anche plugin che evidenziano informazioni interessanti all'interno del registro caricato.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Un'altra applicazione GUI in grado di estrarre le informazioni importanti dal registro caricato.

### Recupero di Elementi Eliminati

Quando una chiave viene eliminata, viene contrassegnata come tale, ma finché lo spazio che occupa non è necessario, non verrà rimossa. Pertanto, utilizzando strumenti come **Registry Explorer** è possibile recuperare queste chiavi eliminate.

### Ultima Data di Modifica

Ogni Chiave-Valore contiene un **timestamp** che indica l'ultima volta in cui è stata modificata.

### SAM

Il file/hive **SAM** contiene gli **hash delle password degli utenti, gruppi e utenti** del sistema.

In `SAM\Domains\Account\Users` è possibile ottenere il nome utente, il RID, l'ultimo accesso, l'ultimo accesso fallito, il contatore di accesso, la politica delle password e la data di creazione dell'account. Per ottenere gli **hash** è necessario anche il file/hive **SYSTEM**.

### Voci Interessanti nel Registro di Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programmi Eseguiti

### Processi di Base di Windows

In [questo post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) è possibile apprendere sui processi comuni di Windows per rilevare comportamenti sospetti.

### Applicazioni Recenti di Windows

All'interno del registro `NTUSER.DAT` nel percorso `Software\Microsoft\Current Version\Search\RecentApps` è possibile trovare sottochiavi con informazioni sull'**applicazione eseguita**, l'**ultima volta** in cui è stata eseguita e il **numero di volte** in cui è stata avviata.

### BAM (Moderatore Attività di Background)

È possibile aprire il file `SYSTEM` con un editor del registro e all'interno del percorso `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` è possibile trovare le informazioni sulle **applicazioni eseguite da ciascun utente** (nota il `{SID}` nel percorso) e a **che ora** sono state eseguite (l'ora è all'interno del valore dei dati del registro).

### Prefetch di Windows

Il prefetching è una tecnica che consente a un computer di **recuperare silenziosamente le risorse necessarie per visualizzare contenuti** a cui un utente **potrebbe accedere in futuro** in modo che le risorse possano essere accessibili più rapidamente.

Il prefetch di Windows consiste nel creare **cache dei programmi eseguiti** per poterli caricare più velocemente. Queste cache vengono create come file `.pf` nel percorso: `C:\Windows\Prefetch`. Vi è un limite di 128 file in XP/VISTA/WIN7 e 1024 file in Win8/Win10.

Il nome del file è creato come `{nome_programma}-{hash}.pf` (l'hash si basa sul percorso e sugli argomenti dell'eseguibile). In W10 questi file sono compressi. Si noti che la sola presenza del file indica che **il programma è stato eseguito** in qualche momento.

Il file `C:\Windows\Prefetch\Layout.ini` contiene i **nomi delle cartelle dei file prefetched**. Questo file contiene **informazioni sul numero delle esecuzioni**, **date** dell'esecuzione e **file** **aperti** dal programma.

Per ispezionare questi file è possibile utilizzare lo strumento [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** ha lo stesso obiettivo del prefetch, **caricare i programmi più velocemente** prevedendo cosa verrà caricato successivamente. Tuttavia, non sostituisce il servizio prefetch.\
Questo servizio genererà file di database in `C:\Windows\Prefetch\Ag*.db`.

In questi database è possibile trovare il **nome** del **programma**, il **numero** di **esecuzioni**, i **file** **aperti**, il **volume** **accessato**, il **percorso completo**, i **frame temporali** e i **timestamp**.

È possibile accedere a queste informazioni utilizzando lo strumento [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitora** le **risorse** **consumate** **da un processo**. È apparso in W8 e memorizza i dati in un database ESE situato in `C:\Windows\System32\sru\SRUDB.dat`.

Fornisce le seguenti informazioni:

* AppID e Percorso
* Utente che ha eseguito il processo
* Byte inviati
* Byte ricevuti
* Interfaccia di rete
* Durata della connessione
* Durata del processo

Queste informazioni vengono aggiornate ogni 60 minuti.

È possibile ottenere i dati da questo file utilizzando lo strumento [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Il **AppCompatCache**, noto anche come **ShimCache**, fa parte del **Database di compatibilità delle applicazioni** sviluppato da **Microsoft** per affrontare problemi di compatibilità delle applicazioni. Questo componente di sistema registra vari metadati dei file, tra cui:

- Percorso completo del file
- Dimensione del file
- Ultima ora di modifica sotto **$Standard\_Information** (SI)
- Ultima ora di aggiornamento del ShimCache
- Flag di esecuzione del processo

Tali dati sono memorizzati nel registro in posizioni specifiche in base alla versione del sistema operativo:

- Per XP, i dati sono memorizzati in `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` con una capacità di 96 voci.
- Per Server 2003, così come per le versioni di Windows 2008, 2012, 2016, 7, 8 e 10, il percorso di archiviazione è `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, con una capacità rispettivamente di 512 e 1024 voci.

Per analizzare le informazioni memorizzate, si consiglia di utilizzare lo strumento [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Il file **Amcache.hve** è essenzialmente un hive del registro che registra dettagli sulle applicazioni eseguite su un sistema. Di solito si trova in `C:\Windows\AppCompat\Programas\Amcache.hve`.

Questo file è noto per memorizzare i record dei processi eseguiti di recente, inclusi i percorsi ai file eseguibili e i loro hash SHA1. Queste informazioni sono preziose per tracciare l'attività delle applicazioni su un sistema.

Per estrarre e analizzare i dati da **Amcache.hve**, si può utilizzare lo strumento [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Il seguente comando è un esempio di come utilizzare AmcacheParser per analizzare i contenuti del file **Amcache.hve** e produrre i risultati in formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Tra i file CSV generati, il file `Voci file non associate di Amcache` è particolarmente degno di nota per le ricche informazioni che fornisce sulle voci dei file non associate.

Il file CSV più interessante generato è il `Voci file non associate di Amcache`.

### RecentFileCache

Questo artefatto può essere trovato solo in W7 in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` e contiene informazioni sull'esecuzione recente di alcuni binari.

Puoi utilizzare lo strumento [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) per analizzare il file.

### Attività pianificate

Puoi estrarle da `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` e leggerle come XML.

### Servizi

Puoi trovarli nel registro sotto `SYSTEM\ControlSet001\Services`. Puoi vedere cosa verrà eseguito e quando.

### **Windows Store**

Le applicazioni installate possono essere trovate in `\ProgramData\Microsoft\Windows\AppRepository\`\
Questo repository ha un **log** con **ogni applicazione installata** nel sistema all'interno del database **`StateRepository-Machine.srd`**.

All'interno della tabella delle Applicazioni di questo database, è possibile trovare le colonne: "ID Applicazione", "Numero Pacchetto" e "Nome Visualizzato". Queste colonne contengono informazioni sulle applicazioni preinstallate e installate e è possibile verificare se alcune applicazioni sono state disinstallate poiché gli ID delle applicazioni installate dovrebbero essere sequenziali.

È inoltre possibile **trovare le applicazioni installate** nel percorso del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
E le **applicazioni disinstallate** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventi di Windows

Le informazioni che compaiono negli eventi di Windows sono:

* Cosa è successo
* Timestamp (UTC + 0)
* Utenti coinvolti
* Host coinvolti (nome host, IP)
* Risorse accessate (file, cartelle, stampanti, servizi)

I log sono situati in `C:\Windows\System32\config` prima di Windows Vista e in `C:\Windows\System32\winevt\Logs` dopo Windows Vista. Prima di Windows Vista, i log degli eventi erano in formato binario e dopo sono in formato **XML** e utilizzano l'estensione **.evtx**.

La posizione dei file degli eventi può essere trovata nel registro di sistema in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Possono essere visualizzati dall'Event Viewer di Windows (**`eventvwr.msc`**) o con altri strumenti come [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprensione della Registrazione Eventi di Sicurezza di Windows

Gli eventi di accesso vengono registrati nel file di configurazione di sicurezza situato in `C:\Windows\System32\winevt\Security.evtx`. La dimensione di questo file è regolabile e, quando raggiunge la capacità massima, gli eventi più vecchi vengono sovrascritti. Gli eventi registrati includono accessi e disconessioni degli utenti, azioni degli utenti e modifiche alle impostazioni di sicurezza, nonché accessi a file, cartelle e risorse condivise.

### Principali ID Evento per l'Autenticazione Utente:

- **EventID 4624**: Indica un'utente autenticato con successo.
- **EventID 4625**: Segnala un fallimento dell'autenticazione.
- **EventIDs 4634/4647**: Rappresentano eventi di disconnessione dell'utente.
- **EventID 4672**: Indica l'accesso con privilegi amministrativi.

#### Sottotipi all'interno di EventID 4634/4647:

- **Interattivo (2)**: Accesso diretto dell'utente.
- **Rete (3)**: Accesso alle cartelle condivise.
- **Batch (4)**: Esecuzione di processi batch.
- **Servizio (5)**: Avvio di servizi.
- **Proxy (6)**: Autenticazione proxy.
- **Sblocco (7)**: Schermo sbloccato con una password.
- **Testo in chiaro di rete (8)**: Trasmissione di password in chiaro, spesso da IIS.
- **Nuove credenziali (9)**: Utilizzo di credenziali diverse per l'accesso.
- **Interattivo remoto (10)**: Accesso remoto tramite desktop remoto o servizi terminal.
- **Interattivo nella cache (11)**: Accesso con credenziali memorizzate senza contatto con il controller di dominio.
- **Interattivo remoto nella cache (12)**: Accesso remoto con credenziali memorizzate.
- **Sblocco nella cache (13)**: Sblocco con credenziali memorizzate.

#### Codici di stato e sottostati per EventID 4625:

- **0xC0000064**: Il nome utente non esiste - Potrebbe indicare un attacco di enumerazione dei nomi utente.
- **0xC000006A**: Nome utente corretto ma password errata - Possibile tentativo di indovinare la password o attacco di forza bruta.
- **0xC0000234**: Account utente bloccato - Potrebbe seguire un attacco di forza bruta con molteplici tentativi di accesso falliti.
- **0xC0000072**: Account disabilitato - Tentativi non autorizzati di accedere a account disabilitati.
- **0xC000006F**: Accesso al di fuori dell'orario consentito - Indica tentativi di accesso al di fuori degli orari di accesso impostati, possibile segno di accesso non autorizzato.
- **0xC0000070**: Violazione delle restrizioni della postazione di lavoro - Potrebbe essere un tentativo di accesso da una posizione non autorizzata.
- **0xC0000193**: Scadenza dell'account - Tentativi di accesso con account utente scaduti.
- **0xC0000071**: Password scaduta - Tentativi di accesso con password obsolete.
- **0xC0000133**: Problemi di sincronizzazione dell'orario - Grandi discrepanze di tempo tra client e server potrebbero indicare attacchi più sofisticati come pass-the-ticket.
- **0xC0000224**: Cambio obbligatorio della password - Cambi frequenti obbligatori potrebbero suggerire un tentativo di destabilizzare la sicurezza dell'account.
- **0xC0000225**: Indica un bug di sistema piuttosto che un problema di sicurezza.
- **0xC000015b**: Tipo di accesso al login negato - Tentativo di accesso con tipo di login non autorizzato, come un utente che cerca di eseguire un login di servizio.

#### EventID 4616:
- **Modifica dell'orario**: Modifica dell'orario di sistema, potrebbe oscurare la sequenza temporale degli eventi.

#### EventID 6005 e 6006:
- **Avvio e spegnimento del sistema**: L'EventID 6005 indica l'avvio del sistema, mentre l'EventID 6006 indica lo spegnimento.

#### EventID 1102:
- **Cancellazione del log**: I log di sicurezza vengono cancellati, spesso segno di attività illecite da nascondere.

#### EventID per il Tracciamento dei Dispositivi USB:
- **20001 / 20003 / 10000**: Primo collegamento del dispositivo USB.
- **10100**: Aggiornamento del driver USB.
- **EventID 112**: Orario di inserimento del dispositivo USB.

Per esempi pratici sulla simulazione di questi tipi di accesso e opportunità di recupero delle credenziali, consulta la [guida dettagliata di Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

I dettagli degli eventi, inclusi i codici di stato e sottostato, forniscono ulteriori informazioni sulle cause degli eventi, particolarmente rilevanti nell'Evento ID 4625.

### Recupero degli Eventi di Windows

Per aumentare le possibilità di recuperare gli eventi di Windows eliminati, è consigliabile spegnere il computer sospetto staccandolo direttamente. **Bulk_extractor**, uno strumento di recupero che specifica l'estensione `.evtx`, è consigliato per tentare di recuperare tali eventi.

### Identificazione degli Attacchi Comuni tramite gli Eventi di Windows

Per una guida completa sull'utilizzo degli ID degli eventi di Windows per identificare attacchi informatici comuni, visita [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Attacchi di Forza Bruta

Identificabili da molteplici registrazioni di EventID 4625, seguite da un EventID 4624 se l'attacco ha successo.

#### Cambio dell'Orario

Registrato dall'EventID 4616, i cambiamenti all'orario di sistema possono complicare l'analisi forense.

#### Tracciamento dei Dispositivi USB

Gli utili EventID di Sistema per il tracciamento dei dispositivi USB includono 20001/20003/10000 per l'uso iniziale, 10100 per gli aggiornamenti dei driver e l'EventID 112 da DeviceSetupManager per i timestamp di inserimento.
#### Eventi di accensione del sistema

L'EventID 6005 indica l'avvio del sistema, mentre l'EventID 6006 segna lo spegnimento.

#### Cancellazione dei log

L'EventID 1102 della sicurezza segnala la cancellazione dei log, un evento critico per l'analisi forense.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>
