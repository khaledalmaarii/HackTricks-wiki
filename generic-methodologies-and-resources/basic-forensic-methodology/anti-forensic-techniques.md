<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>


# Timestamp

Un attaccante potrebbe essere interessato a **modificare i timestamp dei file** per evitare di essere rilevato.\
È possibile trovare i timestamp all'interno del MFT negli attributi `$STANDARD_INFORMATION` __ e __ `$FILE_NAME`.

Entrambi gli attributi hanno 4 timestamp: **Modifica**, **accesso**, **creazione** e **modifica del registro MFT** (MACE o MACB).

**Windows Explorer** e altri strumenti mostrano le informazioni da **`$STANDARD_INFORMATION`**.

## TimeStomp - Strumento anti-forense

Questo strumento **modifica** le informazioni sui timestamp all'interno di **`$STANDARD_INFORMATION`** **ma non** le informazioni all'interno di **`$FILE_NAME`**. Pertanto, è possibile **identificare** **attività sospette**.

## Usnjrnl

Il **USN Journal** (Update Sequence Number Journal) è una caratteristica del file system NTFS (Windows NT) che tiene traccia delle modifiche al volume. Lo strumento [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) consente di esaminare queste modifiche.

![](<../../.gitbook/assets/image (449).png>)

L'immagine precedente è l'**output** mostrato dallo **strumento** in cui è possibile osservare che sono state eseguite alcune **modifiche al file**.

## $LogFile

**Tutte le modifiche ai metadati di un file system vengono registrate** in un processo noto come [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). I metadati registrati sono conservati in un file chiamato `**$LogFile**`, situato nella directory radice di un file system NTFS. Strumenti come [LogFileParser](https://github.com/jschicht/LogFileParser) possono essere utilizzati per analizzare questo file e identificare le modifiche.

![](<../../.gitbook/assets/image (450).png>)

Anche in output dello strumento è possibile vedere che sono state eseguite **alcune modifiche**.

Utilizzando lo stesso strumento è possibile identificare a **quale ora sono stati modificati i timestamp**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Ora di creazione del file
* ATIME: Ora di modifica del file
* MTIME: Ora di modifica del registro MFT del file
* RTIME: Ora di accesso al file

## Confronto tra `$STANDARD_INFORMATION` e `$FILE_NAME`

Un altro modo per identificare file modificati in modo sospetto sarebbe confrontare l'ora in entrambi gli attributi alla ricerca di **discrepanze**.

## Nanosecondi

I timestamp di **NTFS** hanno una **precisione** di **100 nanosecondi**. Trovare file con timestamp come 2010-10-10 10:10:**00.000:0000 è molto sospetto**.

## SetMace - Strumento anti-forense

Questo strumento può modificare entrambi gli attributi `$STARNDAR_INFORMATION` e `$FILE_NAME`. Tuttavia, a partire da Windows Vista, è necessario un sistema operativo in esecuzione per modificare queste informazioni.

# Nascondere dati

NTFS utilizza un cluster e la dimensione minima delle informazioni. Ciò significa che se un file occupa un cluster e mezzo, la **parte rimanente non verrà mai utilizzata** fino a quando il file non viene eliminato. Pertanto, è possibile **nascondere dati in questo spazio vuoto**.

Ci sono strumenti come slacker che consentono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi del `$logfile` e `$usnjrnl` può mostrare che sono stati aggiunti alcuni dati:

![](<../../.gitbook/assets/image (452).png>)

Pertanto, è possibile recuperare lo spazio vuoto utilizzando strumenti come FTK Imager. Notare che questo tipo di strumento può salvare il contenuto oscurato o addirittura crittografato.

# UsbKill

Questo è uno strumento che **spegne il computer se viene rilevata una modifica alle porte USB**.\
Un modo per scoprirlo sarebbe ispezionare i processi in esecuzione e **verificare ogni script Python in esecuzione**.

# Distribuzioni Linux in esecuzione

Queste distribuzioni sono **eseguite nella memoria RAM**. L'unico modo per rilevarle è **nel caso in cui il file system NTFS sia montato con permessi di scrittura**. Se viene montato solo con permessi di lettura, non sarà possibile rilevare l'intrusione.

# Cancellazione sicura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configurazione di Windows

È possibile disabilitare diversi metodi di registrazione di Windows per rendere molto più difficile l'indagine forense.

## Disabilita i timestamp - UserAssist

Si tratta di una chiave di registro che mantiene le date e le ore in cui ogni eseguibile è stato eseguito dall'utente.

La disabilitazione di UserAssist richiede due passaggi:

1. Impostare due chiavi di registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, entrambe a zero per segnalare che desideriamo disabilitare UserAssist.
2. Eliminare i sottoalberi del registro che assomigliano a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Disabilita i timestamp - Prefetch

Questo salva informazioni sulle applicazioni eseguite con l'obiettivo di migliorare le prestazioni del sistema Windows. Tuttavia, ciò può essere utile anche per le pratiche forensi.

* Esegui `regedit`
* Seleziona il percorso del file `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Fai clic con il pulsante destro su `EnablePrefetcher` e `EnableSuperfetch`
* Seleziona Modifica su ciascuno di questi per cambiare il valore da 1 (o 3) a 0
* Riavvia

## Disabilita i timestamp - Last Access Time

Ogni volta che una cartella viene aperta da un volume NTFS su un server Windows NT, il sistema impiega del tempo per **aggiornare un campo di timestamp su ogni cartella elencata**, chiamato last access time. Su un volume NTFS molto utilizzato, ciò può influire sulle prestazioni.

1. Apri l'Editor del Registro (Regedit.exe).
2. Passa a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Cerca `NtfsDisableLastAccessUpdate`. Se non esiste, aggiungi questo DWORD e imposta il suo valore su 1, che disabiliterà il processo.
4. Chiudi l'Editor del Registro e riavvia il server.
## Eliminare la cronologia delle USB

Tutte le **voci dei dispositivi USB** vengono memorizzate nel Registro di sistema di Windows sotto la chiave di registro **USBSTOR**, che contiene sottocchiavi create ogni volta che si collega un dispositivo USB al PC o al laptop. È possibile trovare questa chiave qui: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminando questa chiave**, si eliminerà la cronologia delle USB.\
È anche possibile utilizzare lo strumento [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) per assicurarsi di averle eliminate (e per eliminarle).

Un altro file che salva informazioni sulle USB è il file `setupapi.dev.log` all'interno di `C:\Windows\INF`. Anche questo dovrebbe essere eliminato.

## Disabilitare le copie shadow

**Elencare** le copie shadow con `vssadmin list shadowstorage`\
**Eliminarle** eseguendo `vssadmin delete shadow`

È anche possibile eliminarle tramite GUI seguendo i passaggi proposti in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Per disabilitare le copie shadow [seguire i passaggi da qui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Aprire il programma Servizi digitando "servizi" nella casella di ricerca di testo dopo aver cliccato sul pulsante di avvio di Windows.
2. Dalla lista, trovare "Volume Shadow Copy", selezionarlo e quindi accedere alle Proprietà facendo clic con il pulsante destro del mouse.
3. Scegliere Disabilitato dal menu a discesa "Tipo di avvio" e quindi confermare la modifica cliccando su Applica e OK.

È anche possibile modificare la configurazione dei file che verranno copiati nella copia shadow nel registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Sovrascrivere i file eliminati

* È possibile utilizzare uno **strumento di Windows**: `cipher /w:C`. Questo indicherà a Cipher di rimuovere tutti i dati dallo spazio su disco non utilizzato disponibile nell'unità C.
* È anche possibile utilizzare strumenti come [**Eraser**](https://eraser.heidi.ie)

## Eliminare i log degli eventi di Windows

* Windows + R --> eventvwr.msc --> Espandere "Registri di Windows" --> Fare clic con il pulsante destro del mouse su ogni categoria e selezionare "Cancella registro"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Disabilitare i log degli eventi di Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* All'interno della sezione dei servizi, disabilitare il servizio "Windows Event Log"
* `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

## Disabilitare $UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
