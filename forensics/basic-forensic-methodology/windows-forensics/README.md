# Artefatti di Windows

## Artefatti di Windows

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Artefatti generici di Windows

### Notifiche di Windows 10

Nel percorso `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` puoi trovare il database `appdb.dat` (prima di Windows Anniversary) o `wpndatabase.db` (dopo Windows Anniversary).

All'interno di questo database SQLite, puoi trovare la tabella `Notification` con tutte le notifiche (in formato XML) che possono contenere dati interessanti.

### Timeline

La Timeline è una caratteristica di Windows che fornisce una **cronologia cronologica** delle pagine web visitate, dei documenti modificati e delle applicazioni eseguite.

Il database risiede nel percorso `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Questo database può essere aperto con uno strumento SQLite o con lo strumento [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **che genera 2 file che possono essere aperti con lo strumento** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

I file scaricati possono contenere la **ADS Zone.Identifier** che indica **come** è stato **scaricato** dall'intranet, internet, ecc. Alcuni software (come i browser) di solito inseriscono anche **ulteriori** **informazioni** come l'**URL** da cui è stato scaricato il file.

## **Backup dei file**

### Cestino

In Vista/Win7/Win8/Win10 il **Cestino** può essere trovato nella cartella **`$Recycle.bin`** nella radice del disco (`C:\$Recycle.bin`).\
Quando un file viene eliminato in questa cartella vengono creati 2 file specifici:

* `$I{id}`: Informazioni sul file (data in cui è stato eliminato)
* `$R{id}`: Contenuto del file

![](<../../../.gitbook/assets/image (486).png>)

Avendo questi file puoi utilizzare lo strumento [**Rifiuti**](https://github.com/abelcheung/rifiuti2) per ottenere l'indirizzo originale dei file eliminati e la data in cui è stato eliminato (usa `rifiuti-vista.exe` per Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Copie Shadow del Volume

Shadow Copy è una tecnologia inclusa in Microsoft Windows che può creare **copia di backup** o snapshot di file o volumi del computer, anche quando sono in uso.

Questi backup sono di solito situati in `\System Volume Information` dalla radice del file system e il nome è composto da **UID** mostrati nell'immagine seguente:

![](<../../../.gitbook/assets/image (520).png>)

Montando l'immagine forense con **ArsenalImageMounter**, lo strumento [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) può essere utilizzato per ispezionare una copia shadow e persino **estrarre i file** dai backup delle copie shadow.

![](<../../../.gitbook/assets/image (521).png>)

L'entry del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene i file e le chiavi **da non eseguire il backup**:

![](<../../../.gitbook/assets/image (522).png>)

Il registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contiene anche informazioni di configurazione sulle `Copie Shadow del Volume`.

### File AutoSalvati di Office

È possibile trovare i file auto-salvati di Office in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementi della Shell

Un elemento della shell è un elemento che contiene informazioni su come accedere a un altro file.

### Documenti Recenti (LNK)

Windows **crea automaticamente** questi **collegamenti** quando l'utente **apre, utilizza o crea un file** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando viene creata una cartella, viene creato anche un collegamento alla cartella, alla cartella genitore e alla cartella del nonno.

Questi file di collegamento creati automaticamente **contengono informazioni sull'origine** come se fosse un **file** **o** una **cartella**, **tempi MAC** di quel file, **informazioni sul volume** in cui è memorizzato il file e **cartella del file di destinazione**. Queste informazioni possono essere utili per recuperare quei file nel caso in cui siano stati rimossi.

Inoltre, la **data di creazione del collegamento** è il primo **momento** in cui il file originale è stato **utilizzato per la prima volta** e la **data di modifica** del collegamento è l'**ultimo momento** in cui il file di origine è stato utilizzato.

Per ispezionare questi file è possibile utilizzare [**LinkParser**](http://4discovery.com/our-tools/).

In questo strumento troverai **2 set** di timestamp:

* **Primo Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Secondo Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Il primo set di timestamp fa riferimento ai **timestamp del file stesso**. Il secondo set fa riferimento ai **timestamp del file collegato**.

È possibile ottenere le stesse informazioni eseguendo lo strumento della riga di comando di Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In questo caso, le informazioni verranno salvate all'interno di un file CSV.

### Jumplists

Questi sono i file recenti indicati per applicazione. È l'elenco dei **file recenti utilizzati da un'applicazione** a cui è possibile accedere su ogni applicazione. Possono essere creati **automaticamente o personalizzati**.

Le **jumplists** create automaticamente vengono memorizzate in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Le jumplists sono denominate seguendo il formato `{id}.autmaticDestinations-ms` dove l'ID iniziale è l'ID dell'applicazione.

Le jumplists personalizzate vengono memorizzate in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e vengono create dall'applicazione di solito perché è successo qualcosa di **importante** con il file (forse contrassegnato come preferito).

Il **tempo di creazione** di qualsiasi jumplist indica **la prima volta in cui il file è stato accesso** e il **tempo di modifica l'ultima volta**.

È possibile ispezionare le jumplists utilizzando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Nota che i timestamp forniti da JumplistExplorer sono relativi al file jumplist stesso_)

### Shellbags

[**Segui questo link per saperne di più su cosa sono le shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilizzo delle chiavette USB di Windows

È possibile identificare l'utilizzo di un dispositivo USB grazie alla creazione di:

* Cartella Recent di Windows
* Cartella Recent di Microsoft Office
* Jumplists

Nota che alcuni file LNK invece di puntare al percorso originale, puntano alla cartella WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

I file nella cartella WPDNSE sono una copia di quelli originali, quindi non sopravviveranno a un riavvio del PC e l'ID viene preso da una shellbag.

### Informazioni del Registro di sistema

[Controlla questa pagina per saperne di più](interesting-windows-registry-keys.md#usb-information) su quali chiavi di registro contengono informazioni interessanti sui dispositivi USB collegati.

### setupapi

Controlla il file `C:\Windows\inf\setupapi.dev.log` per ottenere i timestamp su quando è stata effettuata la connessione USB (cerca `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati collegati a un'immagine.

![](<../../../.gitbook/assets/image (483).png>)

### Pulizia Plug and Play

Il task pianificato noto come 'Pulizia Plug and Play' è principalmente progettato per la rimozione delle versioni obsolete dei driver. Contrariamente al suo scopo specificato di mantenere la versione più recente del pacchetto di driver, fonti online suggeriscono che miri anche ai driver inattivi da 30 giorni. Di conseguenza, i driver per dispositivi rimovibili non collegati negli ultimi 30 giorni potrebbero essere soggetti a cancellazione.

Il task si trova nel seguente percorso:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Viene fornita un'immagine che mostra il contenuto del task:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componenti chiave e impostazioni del task:**
- **pnpclean.dll**: Questa DLL è responsabile del processo effettivo di pulizia.
- **UseUnifiedSchedulingEngine**: Impostato su `TRUE`, indica l'utilizzo del motore di pianificazione dei task generico.
- **MaintenanceSettings**:
- **Period ('P1M')**: Indica al Task Scheduler di avviare il task di pulizia mensilmente durante la manutenzione automatica regolare.
- **Deadline ('P2M')**: Istruisce il Task Scheduler, se il task fallisce per due mesi consecutivi, di eseguire il task durante la manutenzione automatica di emergenza.

Questa configurazione garantisce la manutenzione e la pulizia regolare dei driver, con disposizioni per riprovare il task in caso di fallimenti consecutivi.

**Per ulteriori informazioni, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Email

Le email contengono **2 parti interessanti: gli header e il contenuto** dell'email. Negli **header** è possibile trovare informazioni come:

* **Chi** ha inviato le email (indirizzo email, IP, server di posta che hanno reindirizzato l'email)
* **Quando** è stata inviata l'email

Inoltre, all'interno degli header `References` e `In-Reply-To` è possibile trovare l'ID dei messaggi:

![](<../../../.gitbook/assets/image (484).png>)

### App Mail di Windows

Questa applicazione salva le email in formato HTML o testo. È possibile trovare le email all'interno delle sottocartelle all'interno di `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Le email vengono salvate con l'estensione `.dat`.

I **metadati** delle email e i **contatti** possono essere trovati all'interno del database **EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia l'estensione** del file da `.vol` a `.edb` e puoi utilizzare lo strumento [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) per aprirlo. All'interno della tabella `Message` è possibile visualizzare le email.

### Microsoft Outlook

Quando vengono utilizzati server Exchange o client Outlook, ci saranno alcuni header MAPI:

* `Mapi-Client-Submit-Time`: Ora del sistema in cui è stata inviata l'email
* `Mapi-Conversation-Index`: Numero di messaggi figli del thread e timestamp di ogni messaggio del thread
* `Mapi-Entry-ID`: Identificatore del messaggio.
* `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: Informazioni sul client MAPI (messaggio letto? non letto? risposto? reindirizzato? fuori sede?)

Nel client Microsoft Outlook, tutti i messaggi inviati/ricevuti, i dati dei contatti e i dati del calendario vengono memorizzati in un file PST in:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Il percorso del registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica il file che viene utilizzato.

È possibile aprire il file PST utilizzando lo strumento [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)
### File OST di Microsoft Outlook

Un file **OST** viene generato da Microsoft Outlook quando è configurato con un server **IMAP** o **Exchange**, memorizzando informazioni simili a un file PST. Questo file viene sincronizzato con il server, conservando i dati degli **ultimi 12 mesi** fino a una **dimensione massima di 50 GB**, ed è situato nella stessa directory del file PST. Per visualizzare un file OST, può essere utilizzato il [**visualizzatore OST Kernel**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recupero degli allegati

Gli allegati persi potrebbero essere recuperabili da:

- Per **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Per **IE11 e versioni successive**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### File MBOX di Thunderbird

**Thunderbird** utilizza file **MBOX** per memorizzare i dati, situati in `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Anteprime delle immagini

- **Windows XP e 8-8.1**: L'accesso a una cartella con anteprime genera un file `thumbs.db` che memorizza anteprime delle immagini, anche dopo l'eliminazione.
- **Windows 7/10**: `thumbs.db` viene creato quando viene acceduto tramite un percorso UNC tramite una rete.
- **Windows Vista e versioni successive**: Le anteprime delle miniature sono centralizzate in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` con file denominati **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) e [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sono strumenti per visualizzare questi file.

### Informazioni del Registro di sistema di Windows

Il Registro di sistema di Windows, che memorizza dati estesi sull'attività di sistema e degli utenti, è contenuto in file in:

- `%windir%\System32\Config` per diverse sottochiavi di `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` per `HKEY_CURRENT_USER`.
- Le versioni di Windows Vista e successive eseguono il backup dei file del Registro di sistema di `HKEY_LOCAL_MACHINE` in `%Windir%\System32\Config\RegBack\`.
- Inoltre, le informazioni sull'esecuzione dei programmi vengono memorizzate in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` a partire da Windows Vista e Windows 2008 Server.

### Strumenti

Alcuni strumenti sono utili per analizzare i file del Registro di sistema:

* **Editor del Registro di sistema**: È installato in Windows. È un'interfaccia grafica per navigare nel Registro di sistema di Windows della sessione corrente.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Consente di caricare il file del Registro di sistema e navigare attraverso di esso con un'interfaccia grafica. Contiene anche segnalibri che evidenziano chiavi con informazioni interessanti.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Anche questo ha un'interfaccia grafica che consente di navigare nel Registro di sistema caricato e contiene plugin che evidenziano informazioni interessanti all'interno del Registro di sistema caricato.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Un'altra applicazione grafica in grado di estrarre le informazioni importanti dal Registro di sistema caricato.

### Recupero di elementi eliminati

Quando una chiave viene eliminata, viene contrassegnata come tale, ma finché lo spazio che occupa non è necessario, non verrà rimossa. Pertanto, utilizzando strumenti come **Registry Explorer**, è possibile recuperare queste chiavi eliminate.

### Ora dell'ultima modifica

Ogni chiave-valore contiene un **timestamp** che indica l'ultima volta in cui è stata modificata.

### SAM

Il file/hive **SAM** contiene gli hash delle **password degli utenti, gruppi e utenti** del sistema.

In `SAM\Domains\Account\Users` è possibile ottenere il nome utente, l'RID, l'ultimo accesso, l'ultimo accesso non riuscito, il contatore di accessi, la politica delle password e la data di creazione dell'account. Per ottenere gli **hash**, è necessario anche il file/hive **SYSTEM**.

### Voci interessanti nel Registro di sistema di Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programmi eseguiti

### Processi di base di Windows

In [questo post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puoi apprendere informazioni sui processi comuni di Windows per rilevare comportamenti sospetti.

### App recenti di Windows

All'interno del registro `NTUSER.DAT` nel percorso `Software\Microsoft\Current Version\Search\RecentApps` puoi trovare sottochiavi con informazioni sull'**applicazione eseguita**, l'**ultima volta** in cui è stata eseguita e il **numero di volte** in cui è stata avviata.

### BAM (Background Activity Moderator)

Puoi aprire il file `SYSTEM` con un editor del registro e all'interno del percorso `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` puoi trovare le informazioni sulle **applicazioni eseguite da ciascun utente** (nota l'{SID} nel percorso) e l'**ora** in cui sono state eseguite (l'ora è all'interno del valore Data del registro).

### Prefetch di Windows

Il prefetching è una tecnica che consente a un computer di **recuperare silenziosamente le risorse necessarie per visualizzare contenuti** che un utente **potrebbe accedere in futuro** in modo da poter accedere alle risorse più rapidamente.

Il prefetch di Windows consiste nella creazione di **cache dei programmi eseguiti** per poterli caricare più velocemente. Queste cache vengono create come file `.pf` nel percorso: `C:\Windows\Prefetch`. C'è un limite di 128 file in XP/VISTA/WIN7 e 1024 file in Win8/Win10.

Il nome del file viene creato come `{nome_programma}-{hash}.pf` (l'hash è basato sul percorso e sugli argomenti dell'eseguibile). In W10 questi file sono compressi. Tieni presente che la sola presenza del file indica che **il programma è stato eseguito** in qualche momento.

Il file `C:\Windows\Prefetch\Layout.ini` contiene i **nomi delle cartelle dei file che vengono prefetchati**. Questo file contiene **informazioni sul numero delle esecuzioni**, **date** dell'esecuzione e **file** **aperti** dal programma.

Per ispezionare questi file puoi utilizzare lo strumento [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** ha lo stesso obiettivo del prefetch, **caricare i programmi più velocemente** prevedendo cosa verrà caricato successivamente. Tuttavia, non sostituisce il servizio di prefetch.\
Questo servizio genererà file di database in `C:\Windows\Prefetch\Ag*.db`.

In questi database è possibile trovare il **nome** del **programma**, il **numero** di **esecuzioni**, i **file** **aperti**, il **volume** **accessato**, il **percorso** **completo**, gli **intervalli di tempo** e i **timestamp**.

È possibile accedere a queste informazioni utilizzando lo strumento [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitora** le **risorse** **consumate** **da un processo**. È apparso in W8 e memorizza i dati in un database ESE situato in `C:\Windows\System32\sru\SRUDB.dat`.

Fornisce le seguenti informazioni:

* AppID e percorso
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

L'**AppCompatCache**, noto anche come **ShimCache**, fa parte del **Database di compatibilità delle applicazioni** sviluppato da **Microsoft** per affrontare i problemi di compatibilità delle applicazioni. Questo componente di sistema registra diverse informazioni sui file, tra cui:

- Percorso completo del file
- Dimensione del file
- Ultima modifica sotto **$Standard\_Information** (SI)
- Ultimo aggiornamento di ShimCache
- Flag di esecuzione del processo

Questi dati vengono memorizzati nel registro di sistema in posizioni specifiche in base alla versione del sistema operativo:

- Per XP, i dati vengono memorizzati in `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` con una capacità di 96 voci.
- Per Server 2003, così come per le versioni di Windows 2008, 2012, 2016, 7, 8 e 10, il percorso di archiviazione è `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, con una capacità rispettivamente di 512 e 1024 voci.

Per analizzare le informazioni memorizzate, si consiglia di utilizzare lo strumento [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Il file **Amcache.hve** è essenzialmente un hive del registro che registra i dettagli sulle applicazioni eseguite su un sistema. Di solito si trova in `C:\Windows\AppCompat\Programas\Amcache.hve`.

Questo file è noto per memorizzare i record dei processi recentemente eseguiti, inclusi i percorsi dei file eseguibili e i loro hash SHA1. Queste informazioni sono preziose per tracciare l'attività delle applicazioni su un sistema.

Per estrarre e analizzare i dati da **Amcache.hve**, è possibile utilizzare lo strumento [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Il seguente comando è un esempio di come utilizzare AmcacheParser per analizzare il contenuto del file **Amcache.hve** e produrre i risultati in formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Tra i file CSV generati, il file `Amcache_Unassociated file entries` è particolarmente interessante per le informazioni dettagliate che fornisce sulle voci di file non associate.

Il file CSV più interessante generato è `Amcache_Unassociated file entries`.

### RecentFileCache

Questo artefatto può essere trovato solo in W7 in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` e contiene informazioni sull'esecuzione recente di alcuni binari.

È possibile utilizzare lo strumento [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) per analizzare il file.

### Attività pianificate

È possibile estrarle da `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` e leggerle come XML.

### Servizi

È possibile trovarli nel registro di sistema in `SYSTEM\ControlSet001\Services`. È possibile vedere cosa verrà eseguito e quando.

### **Windows Store**

Le applicazioni installate possono essere trovate in `\ProgramData\Microsoft\Windows\AppRepository\`\
Questo repository ha un **log** con **ogni applicazione installata** nel sistema all'interno del database **`StateRepository-Machine.srd`**.

All'interno della tabella Application di questo database, è possibile trovare le colonne: "Application ID", "PackageNumber" e "Display Name". Queste colonne contengono informazioni sulle applicazioni preinstallate e installate e possono essere utilizzate per verificare se alcune applicazioni sono state disinstallate poiché gli ID delle applicazioni installate dovrebbero essere sequenziali.

È anche possibile **trovare le applicazioni installate** nel percorso del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
E le **applicazioni disinstallate** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventi di Windows

Le informazioni che compaiono negli eventi di Windows sono:

* Cosa è successo
* Timestamp (UTC + 0)
* Utenti coinvolti
* Host coinvolti (nome host, IP)
* Risorse accessate (file, cartelle, stampanti, servizi)

I log si trovano in `C:\Windows\System32\config` prima di Windows Vista e in `C:\Windows\System32\winevt\Logs` dopo Windows Vista. Prima di Windows Vista, i log degli eventi erano in formato binario e dopo sono in formato **XML** e utilizzano l'estensione **.evtx**.

La posizione dei file di evento può essere trovata nel registro di sistema in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Possono essere visualizzati dall'Event Viewer di Windows (**`eventvwr.msc`**) o con altri strumenti come [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprensione della registrazione degli eventi di sicurezza di Windows

Gli eventi di accesso vengono registrati nel file di configurazione di sicurezza situato in `C:\Windows\System32\winevt\Security.evtx`. La dimensione di questo file è regolabile e, quando raggiunge la capacità massima, gli eventi più vecchi vengono sovrascritti. Gli eventi registrati includono l'accesso e il logout degli utenti, le azioni degli utenti e le modifiche alle impostazioni di sicurezza, nonché l'accesso a file, cartelle e risorse condivise.

### ID evento chiave per l'autenticazione dell'utente:

- **EventID 4624**: Indica un'autenticazione dell'utente riuscita.
- **EventID 4625**: Segnala un fallimento dell'autenticazione.
- **EventIDs 4634/4647**: Rappresentano eventi di logout dell'utente.
- **EventID 4672**: Indica l'accesso con privilegi amministrativi.

#### Sottotipi all'interno di EventID 4634/4647:

- **Interattivo (2)**: Accesso diretto dell'utente.
- **Rete (3)**: Accesso a cartelle condivise.
- **Batch (4)**: Esecuzione di processi batch.
- **Servizio (5)**: Avvio di servizi.
- **Proxy (6)**: Autenticazione del proxy.
- **Sblocco (7)**: Sblocco dello schermo con una password.
- **Testo in chiaro di rete (8)**: Trasmissione della password in chiaro, spesso da IIS.
- **Nuove credenziali (9)**: Utilizzo di credenziali diverse per l'accesso.
- **Interattivo remoto (10)**: Accesso desktop remoto o servizi terminal.
- **Interattivo nella cache (11)**: Accesso con credenziali memorizzate nella cache senza contatto con il controller di dominio.
- **Interattivo remoto nella cache (12)**: Accesso remoto con credenziali memorizzate nella cache.
- **Sblocco nella cache (13)**: Sblocco con credenziali memorizzate nella cache.

#### Codici di stato e sottostati per EventID 4625:

- **0xC0000064**: Il nome utente non esiste - Potrebbe indicare un attacco di enumerazione dei nomi utente.
- **0xC000006A**: Nome utente corretto ma password errata - Possibile tentativo di indovinare la password o attacco di forza bruta.
- **0xC0000234**: Account utente bloccato - Può seguire un attacco di forza bruta che ha causato numerosi tentativi di accesso non riusciti.
- **0xC0000072**: Account disabilitato - Tentativi non autorizzati di accedere a account disabilitati.
- **0xC000006F**: Accesso al di fuori dell'orario consentito - Indica tentativi di accesso al di fuori dell'orario di accesso stabilito, possibile segno di accesso non autorizzato.
- **0xC0000070**: Violazione delle restrizioni del computer - Potrebbe essere un tentativo di accesso da una posizione non autorizzata.
- **0xC0000193**: Scadenza dell'account - Tentativi di accesso con account utente scaduti.
- **0xC0000071**: Password scaduta - Tentativi di accesso con password obsolete.
- **0xC0000133**: Problemi di sincronizzazione dell'orario - Grandi discrepanze di tempo tra client e server possono indicare attacchi più sofisticati come pass-the-ticket.
- **0xC0000224**: Cambio di password obbligatorio - Cambi obbligatori frequenti potrebbero suggerire un tentativo di destabilizzare la sicurezza dell'account.
- **0xC0000225**: Indica un bug di sistema piuttosto che un problema di sicurezza.
- **0xC000015b**: Tipo di accesso al login negato - Tentativo di accesso con tipo di accesso non autorizzato, ad esempio un utente che cerca di eseguire un accesso di servizio.

#### EventID 4616:
- **Modifica dell'ora**: Modifica dell'ora di sistema, potrebbe oscurare la sequenza temporale degli eventi.

#### EventID 6005 e 6006:
- **Avvio e spegnimento del sistema**: L'EventID 6005 indica l'avvio del sistema, mentre l'EventID 6006 indica lo spegnimento.

#### EventID 1102:
- **Cancellazione del log**: Cancellazione dei log di sicurezza, spesso un segnale di attività illecite.

#### EventID per il tracciamento dei dispositivi USB:
- **20001 / 20003 / 10000**: Primo collegamento del dispositivo USB.
- **10100**: Aggiornamento del driver USB.
- **EventID 112**: Ora di inserimento del dispositivo USB.

Per esempi pratici sulla simulazione di questi tipi di accesso e opportunità di recupero delle credenziali, fare riferimento alla guida dettagliata di [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

I dettagli degli eventi, inclusi i codici di stato e sottostato, forniscono ulteriori informazioni sulle cause degli eventi, particolarmente rilevanti nell'Event ID 4625.

### Recupero degli eventi di Windows

Per aumentare le possibilità di recuperare gli eventi di Windows eliminati, è consigliabile spegnere direttamente il computer sospetto scollegandolo. Si consiglia di utilizzare **Bulk_extractor**, uno strumento di recupero specificando l'estensione `.evtx`, per tentare di recuperare tali eventi.

### Identificazione degli attacchi comuni tramite eventi di Windows

Per una guida completa sull'utilizzo degli ID evento di Windows per identificare attacchi informatici comuni, visitare [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Attacchi di forza bruta

Identificabili da registrazioni multiple di EventID 4625, seguite da un EventID 4624 se l'attacco ha successo.

#### Modifica dell'ora

Registrata dall'EventID 4616, le modifiche all'ora di sistema possono complicare l'analisi forense.

#### Tracciamento dei dispositivi USB

Gli EventID di sistema utili per il tracciamento dei dispositivi USB includono 20001/20003/10000 per l'uso iniziale, 10100 per gli aggiornamenti dei driver e l'EventID 112 da DeviceSetupManager per i timestamp
#### Eventi di alimentazione del sistema

L'EventID 6005 indica l'avvio del sistema, mentre l'EventID 6006 segna lo spegnimento.

#### Cancellazione dei log

L'EventID 1102 della sicurezza segnala la cancellazione dei log, un evento critico per l'analisi forense.


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
