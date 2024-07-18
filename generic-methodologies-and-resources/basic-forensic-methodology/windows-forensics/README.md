# Windows Artifacts

## Windows Artifacts

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Generic Windows Artifacts

### Windows 10 Notifications

Nel percorso `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` puoi trovare il database `appdb.dat` (prima dell'anniversario di Windows) o `wpndatabase.db` (dopo l'anniversario di Windows).

All'interno di questo database SQLite, puoi trovare la tabella `Notification` con tutte le notifiche (in formato XML) che possono contenere dati interessanti.

### Timeline

La Timeline è una caratteristica di Windows che fornisce **una cronologia cronologica** delle pagine web visitate, dei documenti modificati e delle applicazioni eseguite.

Il database si trova nel percorso `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Questo database può essere aperto con uno strumento SQLite o con lo strumento [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **che genera 2 file che possono essere aperti con lo strumento** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

I file scaricati possono contenere l'**ADS Zone.Identifier** che indica **come** è stato **scaricato** dall'intranet, internet, ecc. Alcuni software (come i browser) di solito aggiungono anche **ulteriori** **informazioni** come l'**URL** da cui è stato scaricato il file.

## **File Backups**

### Recycle Bin

In Vista/Win7/Win8/Win10 il **Cestino** può essere trovato nella cartella **`$Recycle.bin`** nella radice dell'unità (`C:\$Recycle.bin`).\
Quando un file viene eliminato in questa cartella vengono creati 2 file specifici:

* `$I{id}`: Informazioni sul file (data di quando è stato eliminato)
* `$R{id}`: Contenuto del file

![](<../../../.gitbook/assets/image (1029).png>)

Avendo questi file puoi utilizzare lo strumento [**Rifiuti**](https://github.com/abelcheung/rifiuti2) per ottenere l'indirizzo originale dei file eliminati e la data in cui è stato eliminato (usa `rifiuti-vista.exe` per Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy è una tecnologia inclusa in Microsoft Windows che può creare **copia di backup** o snapshot di file o volumi del computer, anche quando sono in uso.

Questi backup si trovano solitamente in `\System Volume Information` dalla radice del file system e il nome è composto da **UID** mostrati nell'immagine seguente:

![](<../../../.gitbook/assets/image (94).png>)

Montando l'immagine forense con **ArsenalImageMounter**, lo strumento [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) può essere utilizzato per ispezionare una copia shadow e persino **estrarre i file** dai backup delle copie shadow.

![](<../../../.gitbook/assets/image (576).png>)

L'entry del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene i file e le chiavi **da non eseguire il backup**:

![](<../../../.gitbook/assets/image (254).png>)

Il registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contiene anche informazioni di configurazione riguardo le `Volume Shadow Copies`.

### Office AutoSaved Files

Puoi trovare i file autosalvati di Office in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Un elemento shell è un elemento che contiene informazioni su come accedere a un altro file.

### Recent Documents (LNK)

Windows **crea automaticamente** questi **collegamenti** quando l'utente **apre, utilizza o crea un file** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando viene creata una cartella, viene creato anche un collegamento alla cartella, alla cartella padre e alla cartella nonna.

Questi file di collegamento creati automaticamente **contengono informazioni sull'origine** come se è un **file** **o** una **cartella**, **tempi MAC** di quel file, **informazioni sul volume** di dove è memorizzato il file e **cartella del file di destinazione**. Queste informazioni possono essere utili per recuperare quei file nel caso siano stati rimossi.

Inoltre, la **data di creazione del collegamento** è il primo **tempo** in cui il file originale è stato **utilizzato per la prima volta** e la **data** **modificata** del file di collegamento è l'**ultima** **volta** in cui il file di origine è stato utilizzato.

Per ispezionare questi file puoi utilizzare [**LinkParser**](http://4discovery.com/our-tools/).

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

Puoi ottenere le stesse informazioni eseguendo lo strumento CLI di Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In questo caso, le informazioni verranno salvate all'interno di un file CSV.

### Jumplists

Questi sono i file recenti indicati per applicazione. È l'elenco dei **file recenti utilizzati da un'applicazione** a cui puoi accedere su ciascuna applicazione. Possono essere creati **automaticamente o essere personalizzati**.

I **jumplists** creati automaticamente sono memorizzati in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. I jumplists sono nominati seguendo il formato `{id}.autmaticDestinations-ms` dove l'ID iniziale è l'ID dell'applicazione.

I jumplists personalizzati sono memorizzati in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e vengono creati dall'applicazione solitamente perché è successo qualcosa di **importante** con il file (forse contrassegnato come preferito).

Il **tempo di creazione** di qualsiasi jumplist indica **la prima volta che il file è stato accesso** e il **tempo modificato l'ultima volta**.

Puoi ispezionare i jumplists utilizzando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Nota che i timestamp forniti da JumplistExplorer sono relativi al file jumplist stesso_)

### Shellbags

[**Segui questo link per scoprire cosa sono i shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso delle USB di Windows

È possibile identificare che un dispositivo USB è stato utilizzato grazie alla creazione di:

* Cartella Recenti di Windows
* Cartella Recenti di Microsoft Office
* Jumplists

Nota che alcuni file LNK invece di puntare al percorso originale, puntano alla cartella WPDNSE:

![](<../../../.gitbook/assets/image (218).png>)

I file nella cartella WPDNSE sono una copia di quelli originali, quindi non sopravvivranno a un riavvio del PC e il GUID è preso da un shellbag.

### Informazioni sul Registro

[Controlla questa pagina per scoprire](interesting-windows-registry-keys.md#usb-information) quali chiavi di registro contengono informazioni interessanti sui dispositivi USB connessi.

### setupapi

Controlla il file `C:\Windows\inf\setupapi.dev.log` per ottenere i timestamp su quando è stata effettuata la connessione USB (cerca `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati connessi a un'immagine.

![](<../../../.gitbook/assets/image (452).png>)

### Pulizia Plug and Play

Il compito pianificato noto come 'Pulizia Plug and Play' è principalmente progettato per la rimozione di versioni di driver obsolete. Contrariamente al suo scopo specificato di mantenere l'ultima versione del pacchetto driver, fonti online suggeriscono che miri anche a driver che sono stati inattivi per 30 giorni. Di conseguenza, i driver per dispositivi rimovibili non connessi negli ultimi 30 giorni potrebbero essere soggetti a eliminazione.

Il compito si trova al seguente percorso: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Uno screenshot che mostra il contenuto del compito è fornito: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componenti chiave e impostazioni del compito:**

* **pnpclean.dll**: Questo DLL è responsabile del processo di pulizia effettivo.
* **UseUnifiedSchedulingEngine**: Impostato su `TRUE`, indica l'uso del motore di pianificazione dei compiti generico.
* **MaintenanceSettings**:
* **Period ('P1M')**: Indica al Task Scheduler di avviare il compito di pulizia mensilmente durante la manutenzione automatica regolare.
* **Deadline ('P2M')**: Istruisce il Task Scheduler, se il compito fallisce per due mesi consecutivi, ad eseguire il compito durante la manutenzione automatica di emergenza.

Questa configurazione garantisce una manutenzione regolare e la pulizia dei driver, con disposizioni per riprovare il compito in caso di fallimenti consecutivi.

**Per ulteriori informazioni controlla:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Email

Le email contengono **2 parti interessanti: Le intestazioni e il contenuto** dell'email. Nelle **intestazioni** puoi trovare informazioni come:

* **Chi** ha inviato le email (indirizzo email, IP, server di posta che hanno reindirizzato l'email)
* **Quando** è stata inviata l'email

Inoltre, all'interno delle intestazioni `References` e `In-Reply-To` puoi trovare l'ID dei messaggi:

![](<../../../.gitbook/assets/image (593).png>)

### App di posta di Windows

Questa applicazione salva le email in HTML o testo. Puoi trovare le email all'interno delle sottocartelle in `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Le email sono salvate con l'estensione `.dat`.

I **metadati** delle email e i **contatti** possono essere trovati all'interno del **database EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Cambia l'estensione** del file da `.vol` a `.edb` e puoi utilizzare lo strumento [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) per aprirlo. All'interno della tabella `Message` puoi vedere le email.

### Microsoft Outlook

Quando vengono utilizzati server Exchange o client Outlook, ci saranno alcune intestazioni MAPI:

* `Mapi-Client-Submit-Time`: Ora del sistema quando l'email è stata inviata
* `Mapi-Conversation-Index`: Numero di messaggi figli del thread e timestamp di ciascun messaggio del thread
* `Mapi-Entry-ID`: Identificatore del messaggio.
* `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: Informazioni sul client MAPI (messaggio letto? non letto? risposto? reindirizzato? fuori ufficio?)

Nel client Microsoft Outlook, tutti i messaggi inviati/ricevuti, i dati dei contatti e i dati del calendario sono memorizzati in un file PST in:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Il percorso del registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica il file che viene utilizzato.

Puoi aprire il file PST utilizzando lo strumento [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)

### File OST di Microsoft Outlook

Un **file OST** viene generato da Microsoft Outlook quando è configurato con **IMAP** o un server **Exchange**, memorizzando informazioni simili a un file PST. Questo file è sincronizzato con il server, mantenendo i dati per **gli ultimi 12 mesi** fino a un **massimo di 50GB**, ed è situato nella stessa directory del file PST. Per visualizzare un file OST, può essere utilizzato il [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recupero degli Allegati

Allegati persi potrebbero essere recuperabili da:

* Per **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Per **IE11 e versioni superiori**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### File MBOX di Thunderbird

**Thunderbird** utilizza **file MBOX** per memorizzare i dati, situati in `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniature delle Immagini

* **Windows XP e 8-8.1**: Accedere a una cartella con miniature genera un file `thumbs.db` che memorizza le anteprime delle immagini, anche dopo l'eliminazione.
* **Windows 7/10**: `thumbs.db` viene creato quando viene accesso tramite una rete tramite percorso UNC.
* **Windows Vista e versioni successive**: Le anteprime delle miniature sono centralizzate in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` con file denominati **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) e [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sono strumenti per visualizzare questi file.

### Informazioni sul Registro di Windows

Il Registro di Windows, che memorizza un'ampia gamma di dati sulle attività di sistema e utente, è contenuto all'interno di file in:

* `%windir%\System32\Config` per vari sottochiavi `HKEY_LOCAL_MACHINE`.
* `%UserProfile%{User}\NTUSER.DAT` per `HKEY_CURRENT_USER`.
* Windows Vista e versioni successive eseguono il backup dei file di registro `HKEY_LOCAL_MACHINE` in `%Windir%\System32\Config\RegBack\`.
* Inoltre, le informazioni sull'esecuzione dei programmi sono memorizzate in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` a partire da Windows Vista e Windows 2008 Server.

### Strumenti

Al alcuni strumenti sono utili per analizzare i file di registro:

* **Editor del Registro**: È installato in Windows. È un'interfaccia grafica per navigare attraverso il registro di Windows della sessione corrente.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Ti consente di caricare il file di registro e navigare attraverso di esso con un'interfaccia grafica. Contiene anche segnalibri che evidenziano le chiavi con informazioni interessanti.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ancora, ha un'interfaccia grafica che consente di navigare attraverso il registro caricato e contiene anche plugin che evidenziano informazioni interessanti all'interno del registro caricato.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Un'altra applicazione GUI in grado di estrarre le informazioni importanti dal registro caricato.

### Recupero di Elementi Eliminati

Quando una chiave viene eliminata, è contrassegnata come tale, ma finché lo spazio che occupa non è necessario, non verrà rimossa. Pertanto, utilizzando strumenti come **Registry Explorer** è possibile recuperare queste chiavi eliminate.

### Ultimo Tempo di Scrittura

Ogni Chiave-Valore contiene un **timestamp** che indica l'ultima volta che è stata modificata.

### SAM

Il file/hive **SAM** contiene gli **hash delle password degli utenti, dei gruppi e degli utenti** del sistema.

In `SAM\Domains\Account\Users` puoi ottenere il nome utente, il RID, l'ultimo accesso, l'ultimo accesso fallito, il contatore di accesso, la politica delle password e quando è stato creato l'account. Per ottenere gli **hash** hai anche **bisogno** del file/hive **SYSTEM**.

### Voci Interessanti nel Registro di Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programmi Eseguiti

### Processi Windows di Base

In [questo post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puoi scoprire i processi Windows comuni per rilevare comportamenti sospetti.

### APP Recenti di Windows

All'interno del registro `NTUSER.DAT` nel percorso `Software\Microsoft\Current Version\Search\RecentApps` puoi trovare sottochiavi con informazioni sull'**applicazione eseguita**, **ultima volta** che è stata eseguita e **numero di volte** che è stata avviata.

### BAM (Moderatore di Attività in Background)

Puoi aprire il file `SYSTEM` con un editor di registro e all'interno del percorso `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` puoi trovare informazioni sulle **applicazioni eseguite da ciascun utente** (nota il `{SID}` nel percorso) e **a che ora** sono state eseguite (l'ora è all'interno del valore Data del registro).

### Windows Prefetch

Il prefetching è una tecnica che consente a un computer di **recuperare silenziosamente le risorse necessarie per visualizzare contenuti** a cui un utente **potrebbe accedere nel prossimo futuro** in modo che le risorse possano essere accessibili più rapidamente.

Il prefetch di Windows consiste nella creazione di **cache dei programmi eseguiti** per poterli caricare più velocemente. Queste cache vengono create come file `.pf` all'interno del percorso: `C:\Windows\Prefetch`. C'è un limite di 128 file in XP/VISTA/WIN7 e 1024 file in Win8/Win10.

Il nome del file è creato come `{program_name}-{hash}.pf` (l'hash è basato sul percorso e sugli argomenti dell'eseguibile). In W10 questi file sono compressi. Nota che la sola presenza del file indica che **il programma è stato eseguito** a un certo punto.

Il file `C:\Windows\Prefetch\Layout.ini` contiene i **nomi delle cartelle dei file che sono stati prelevati**. Questo file contiene **informazioni sul numero delle esecuzioni**, **date** di esecuzione e **file** **aperti** dal programma.

Per ispezionare questi file puoi utilizzare lo strumento [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** ha lo stesso obiettivo del prefetch, **caricare i programmi più velocemente** prevedendo cosa verrà caricato successivamente. Tuttavia, non sostituisce il servizio di prefetch.\
Questo servizio genererà file di database in `C:\Windows\Prefetch\Ag*.db`.

In questi database puoi trovare il **nome** del **programma**, il **numero** di **esecuzioni**, i **file** **aperti**, il **volume** **accessed**, il **percorso** **completo**, i **tempi** e i **timestamp**.

Puoi accedere a queste informazioni utilizzando lo strumento [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

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

Puoi ottenere la data da questo file utilizzando lo strumento [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Il **AppCompatCache**, noto anche come **ShimCache**, fa parte del **Database di Compatibilità delle Applicazioni** sviluppato da **Microsoft** per affrontare problemi di compatibilità delle applicazioni. Questo componente di sistema registra vari pezzi di metadati dei file, che includono:

* Percorso completo del file
* Dimensione del file
* Ultima data di modifica sotto **$Standard\_Information** (SI)
* Ultima data di aggiornamento dello ShimCache
* Flag di esecuzione del processo

Tali dati sono memorizzati nel registro in posizioni specifiche in base alla versione del sistema operativo:

* Per XP, i dati sono memorizzati sotto `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` con una capacità di 96 voci.
* Per Server 2003, così come per le versioni di Windows 2008, 2012, 2016, 7, 8 e 10, il percorso di archiviazione è `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, che accoglie rispettivamente 512 e 1024 voci.

Per analizzare le informazioni memorizzate, si consiglia di utilizzare lo strumento [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

Il file **Amcache.hve** è essenzialmente un hive di registro che registra dettagli sulle applicazioni che sono state eseguite su un sistema. Si trova tipicamente in `C:\Windows\AppCompat\Programas\Amcache.hve`.

Questo file è notevole per memorizzare registrazioni di processi eseguiti di recente, inclusi i percorsi ai file eseguibili e i loro hash SHA1. Queste informazioni sono inestimabili per tracciare l'attività delle applicazioni su un sistema.

Per estrarre e analizzare i dati da **Amcache.hve**, è possibile utilizzare lo strumento [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Il seguente comando è un esempio di come utilizzare AmcacheParser per analizzare i contenuti del file **Amcache.hve** e restituire i risultati in formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Tra i file CSV generati, il `Amcache_Unassociated file entries` è particolarmente degno di nota per le ricche informazioni che fornisce sulle voci di file non associate.

Il file CVS più interessante generato è il `Amcache_Unassociated file entries`.

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

All'interno della tabella Applicazione di questo database, è possibile trovare le colonne: "Application ID", "PackageNumber" e "Display Name". Queste colonne contengono informazioni sulle applicazioni pre-installate e installate e possono indicare se alcune applicazioni sono state disinstallate, poiché gli ID delle applicazioni installate dovrebbero essere sequenziali.

È anche possibile **trovare applicazioni installate** all'interno del percorso del registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
E **applicazioni disinstallate** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventi di Windows

Le informazioni che appaiono all'interno degli eventi di Windows sono:

* Cosa è successo
* Timestamp (UTC + 0)
* Utenti coinvolti
* Host coinvolti (hostname, IP)
* Risorse accessibili (file, cartella, stampante, servizi)

I log si trovano in `C:\Windows\System32\config` prima di Windows Vista e in `C:\Windows\System32\winevt\Logs` dopo Windows Vista. Prima di Windows Vista, i log degli eventi erano in formato binario e dopo sono in **formato XML** e utilizzano l'estensione **.evtx**.

La posizione dei file di eventi può essere trovata nel registro SYSTEM in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Possono essere visualizzati dal Visualizzatore eventi di Windows (**`eventvwr.msc`**) o con altri strumenti come [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprendere il logging degli eventi di sicurezza di Windows

Gli eventi di accesso sono registrati nel file di configurazione della sicurezza situato in `C:\Windows\System32\winevt\Security.evtx`. La dimensione di questo file è regolabile e, quando la sua capacità è raggiunta, gli eventi più vecchi vengono sovrascritti. Gli eventi registrati includono accessi e disconnessioni degli utenti, azioni degli utenti e modifiche alle impostazioni di sicurezza, nonché accessi a file, cartelle e risorse condivise.

### ID evento chiave per l'autenticazione degli utenti:

* **EventID 4624**: Indica che un utente si è autenticato con successo.
* **EventID 4625**: Segnala un fallimento di autenticazione.
* **EventIDs 4634/4647**: Rappresentano eventi di disconnessione dell'utente.
* **EventID 4672**: Denota accesso con privilegi amministrativi.

#### Sottotipi all'interno di EventID 4634/4647:

* **Interattivo (2)**: Accesso diretto dell'utente.
* **Rete (3)**: Accesso a cartelle condivise.
* **Batch (4)**: Esecuzione di processi batch.
* **Servizio (5)**: Avvii di servizi.
* **Proxy (6)**: Autenticazione proxy.
* **Sblocco (7)**: Schermo sbloccato con una password.
* **Rete in chiaro (8)**: Trasmissione di password in chiaro, spesso da IIS.
* **Nuove credenziali (9)**: Utilizzo di credenziali diverse per l'accesso.
* **Interattivo remoto (10)**: Accesso remoto tramite desktop o servizi terminali.
* **Cache interattivo (11)**: Accesso con credenziali memorizzate senza contatto con il controller di dominio.
* **Cache interattivo remoto (12)**: Accesso remoto con credenziali memorizzate.
* **Sblocco memorizzato (13)**: Sblocco con credenziali memorizzate.

#### Codici di stato e sottostato per EventID 4625:

* **0xC0000064**: Il nome utente non esiste - Potrebbe indicare un attacco di enumerazione degli username.
* **0xC000006A**: Nome utente corretto ma password errata - Possibile tentativo di indovinare la password o attacco brute-force.
* **0xC0000234**: Account utente bloccato - Può seguire un attacco brute-force che ha portato a più accessi falliti.
* **0xC0000072**: Account disabilitato - Tentativi non autorizzati di accedere a account disabilitati.
* **0xC000006F**: Accesso al di fuori dell'orario consentito - Indica tentativi di accesso al di fuori delle ore di accesso impostate, un possibile segno di accesso non autorizzato.
* **0xC0000070**: Violazione delle restrizioni della workstation - Potrebbe essere un tentativo di accesso da una posizione non autorizzata.
* **0xC0000193**: Scadenza dell'account - Tentativi di accesso con account utente scaduti.
* **0xC0000071**: Password scaduta - Tentativi di accesso con password obsolete.
* **0xC0000133**: Problemi di sincronizzazione dell'ora - Grandi discrepanze di tempo tra client e server possono indicare attacchi più sofisticati come pass-the-ticket.
* **0xC0000224**: Cambio di password obbligatorio richiesto - Cambi frequenti obbligatori potrebbero suggerire un tentativo di destabilizzare la sicurezza dell'account.
* **0xC0000225**: Indica un bug di sistema piuttosto che un problema di sicurezza.
* **0xC000015b**: Tipo di accesso negato - Tentativo di accesso con tipo di accesso non autorizzato, come un utente che cerca di eseguire un accesso di servizio.

#### EventID 4616:

* **Cambio di ora**: Modifica dell'ora di sistema, potrebbe oscurare la cronologia degli eventi.

#### EventID 6005 e 6006:

* **Avvio e spegnimento del sistema**: L'EventID 6005 indica l'avvio del sistema, mentre l'EventID 6006 segna lo spegnimento.

#### EventID 1102:

* **Cancellazione del log**: I log di sicurezza vengono cancellati, il che è spesso un campanello d'allarme per coprire attività illecite.

#### EventIDs per il tracciamento dei dispositivi USB:

* **20001 / 20003 / 10000**: Prima connessione del dispositivo USB.
* **10100**: Aggiornamento del driver USB.
* **EventID 112**: Ora di inserimento del dispositivo USB.

Per esempi pratici su come simulare questi tipi di accesso e opportunità di dumping delle credenziali, fai riferimento alla [guida dettagliata di Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

I dettagli degli eventi, inclusi i codici di stato e sottostato, forniscono ulteriori informazioni sulle cause degli eventi, particolarmente notevoli nell'Event ID 4625.

### Recupero degli eventi di Windows

Per aumentare le possibilità di recuperare eventi di Windows cancellati, è consigliabile spegnere il computer sospetto scollegandolo direttamente. **Bulk\_extractor**, uno strumento di recupero che specifica l'estensione `.evtx`, è raccomandato per tentare di recuperare tali eventi.

### Identificazione degli attacchi comuni tramite eventi di Windows

Per una guida completa sull'utilizzo degli ID evento di Windows per identificare attacchi informatici comuni, visita [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Attacchi brute force

Identificabili da più registrazioni di EventID 4625, seguite da un EventID 4624 se l'attacco ha successo.

#### Cambio di ora

Registrato da EventID 4616, i cambiamenti all'ora di sistema possono complicare l'analisi forense.

#### Tracciamento dei dispositivi USB

Gli ID evento di sistema utili per il tracciamento dei dispositivi USB includono 20001/20003/10000 per l'uso iniziale, 10100 per aggiornamenti dei driver e EventID 112 da DeviceSetupManager per i timestamp di inserimento.

#### Eventi di alimentazione del sistema

L'EventID 6005 indica l'avvio del sistema, mentre l'EventID 6006 segna lo spegnimento.

#### Cancellazione del log

L'EventID di sicurezza 1102 segnala la cancellazione dei log, un evento critico per l'analisi forense.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
