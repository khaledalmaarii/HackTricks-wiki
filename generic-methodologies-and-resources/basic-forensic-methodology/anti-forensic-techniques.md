# Tecniche Anti-Forensi

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Timestamp

Un attaccante potrebbe essere interessato a **cambiare i timestamp dei file** per evitare di essere rilevato.\
È possibile trovare i timestamp all'interno del MFT negli attributi `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Entrambi gli attributi hanno 4 timestamp: **Modifica**, **accesso**, **creazione** e **modifica del registro MFT** (MACE o MACB).

**Esplora file di Windows** e altri strumenti mostrano le informazioni da **`$STANDARD_INFORMATION`**.

### TimeStomp - Strumento Anti-forense

Questo strumento **modifica** le informazioni sui timestamp all'interno di **`$STANDARD_INFORMATION`** **ma** **non** le informazioni all'interno di **`$FILE_NAME`**. Pertanto, è possibile **identificare** **attività** **sospette**.

### Usnjrnl

Il **Registro USN** (Registro del Numero di Sequenza di Aggiornamento) è una funzionalità del NTFS (sistema di file Windows NT) che tiene traccia delle modifiche al volume. Lo strumento [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) consente di esaminare queste modifiche.

![](<../../.gitbook/assets/image (801).png>)

L'immagine precedente è l'**output** mostrato dallo **strumento** dove si può osservare che alcune **modifiche sono state effettuate** al file.

### $LogFile

**Tutte le modifiche ai metadati di un file system sono registrate** in un processo noto come [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging). I metadati registrati sono conservati in un file chiamato `**$LogFile**`, situato nella directory radice di un file system NTFS. Strumenti come [LogFileParser](https://github.com/jschicht/LogFileParser) possono essere utilizzati per analizzare questo file e identificare le modifiche.

![](<../../.gitbook/assets/image (137).png>)

Ancora una volta, nell'output dello strumento è possibile vedere che **alcune modifiche sono state effettuate**.

Utilizzando lo stesso strumento è possibile identificare **a quale ora sono stati modificati i timestamp**:

![](<../../.gitbook/assets/image (1089).png>)

* CTIME: Ora di creazione del file
* ATIME: Ora di modifica del file
* MTIME: Modifica del registro MFT del file
* RTIME: Ora di accesso del file

### Confronto tra `$STANDARD_INFORMATION` e `$FILE_NAME`

Un altro modo per identificare file modificati sospetti sarebbe confrontare il tempo su entrambi gli attributi cercando **disallineamenti**.

### Nanosecondi

I timestamp **NTFS** hanno una **precisione** di **100 nanosecondi**. Quindi, trovare file con timestamp come 2010-10-10 10:10:**00.000:0000 è molto sospetto**.

### SetMace - Strumento Anti-forense

Questo strumento può modificare entrambi gli attributi `$STARNDAR_INFORMATION` e `$FILE_NAME`. Tuttavia, a partire da Windows Vista, è necessario un OS live per modificare queste informazioni.

## Nascondere Dati

NFTS utilizza un cluster e la dimensione minima delle informazioni. Ciò significa che se un file occupa e utilizza un cluster e mezzo, la **metà rimanente non verrà mai utilizzata** fino a quando il file non viene eliminato. Quindi, è possibile **nascondere dati in questo spazio di slack**.

Ci sono strumenti come slacker che consentono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi del `$logfile` e del `$usnjrnl` può mostrare che alcuni dati sono stati aggiunti:

![](<../../.gitbook/assets/image (1060).png>)

Quindi, è possibile recuperare lo spazio di slack utilizzando strumenti come FTK Imager. Nota che questo tipo di strumento può salvare il contenuto offuscato o persino crittografato.

## UsbKill

Questo è uno strumento che **spegnerà il computer se viene rilevata qualsiasi modifica nelle porte USB**.\
Un modo per scoprirlo sarebbe ispezionare i processi in esecuzione e **rivedere ogni script python in esecuzione**.

## Distribuzioni Linux Live

Queste distro sono **eseguite all'interno della memoria RAM**. L'unico modo per rilevarle è **nel caso in cui il file system NTFS sia montato con permessi di scrittura**. Se è montato solo con permessi di lettura, non sarà possibile rilevare l'intrusione.

## Cancellazione Sicura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configurazione di Windows

È possibile disabilitare diversi metodi di registrazione di Windows per rendere l'indagine forense molto più difficile.

### Disabilita Timestamp - UserAssist

Questa è una chiave di registro che mantiene date e ore in cui ciascun eseguibile è stato eseguito dall'utente.

Disabilitare UserAssist richiede due passaggi:

1. Imposta due chiavi di registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, entrambe a zero per segnalare che vogliamo disabilitare UserAssist.
2. Cancella i tuoi sottoalberi di registro che sembrano `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disabilita Timestamp - Prefetch

Questo salverà informazioni sulle applicazioni eseguite con l'obiettivo di migliorare le prestazioni del sistema Windows. Tuttavia, questo può essere utile anche per pratiche forensi.

* Esegui `regedit`
* Seleziona il percorso del file `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Fai clic destro su `EnablePrefetcher` e `EnableSuperfetch`
* Seleziona Modifica su ciascuno di questi per cambiare il valore da 1 (o 3) a 0
* Riavvia

### Disabilita Timestamp - Ultimo Tempo di Accesso

Ogni volta che una cartella viene aperta da un volume NTFS su un server Windows NT, il sistema prende il tempo per **aggiornare un campo di timestamp su ciascuna cartella elencata**, chiamato ultimo tempo di accesso. Su un volume NTFS molto utilizzato, questo può influenzare le prestazioni.

1. Apri l'Editor del Registro (Regedit.exe).
2. Naviga a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Cerca `NtfsDisableLastAccessUpdate`. Se non esiste, aggiungi questo DWORD e imposta il suo valore a 1, il che disabiliterà il processo.
4. Chiudi l'Editor del Registro e riavvia il server.

### Elimina la Cronologia USB

Tutti gli **USB Device Entries** sono memorizzati nel Registro di Windows sotto la chiave di registro **USBSTOR** che contiene sottochiavi create ogni volta che colleghi un dispositivo USB al tuo PC o Laptop. Puoi trovare questa chiave qui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminando questo** eliminerai la cronologia USB.\
Puoi anche utilizzare lo strumento [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) per essere sicuro di averle eliminate (e per eliminarle).

Un altro file che salva informazioni sugli USB è il file `setupapi.dev.log` all'interno di `C:\Windows\INF`. Questo dovrebbe essere eliminato.

### Disabilita le Copie Shadow

**Elenca** le copie shadow con `vssadmin list shadowstorage`\
**Eliminale** eseguendo `vssadmin delete shadow`

Puoi anche eliminarle tramite GUI seguendo i passaggi proposti in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Per disabilitare le copie shadow [passaggi da qui](https://support.waters.com/KB\_Inf/Other/WKB15560\_How\_to\_disable\_Volume\_Shadow\_Copy\_Service\_VSS\_in\_Windows):

1. Apri il programma Servizi digitando "servizi" nella casella di ricerca dopo aver cliccato sul pulsante di avvio di Windows.
2. Dall'elenco, trova "Volume Shadow Copy", selezionalo e poi accedi alle Proprietà facendo clic destro.
3. Scegli Disabilitato dal menu a discesa "Tipo di avvio", e poi conferma la modifica facendo clic su Applica e OK.

È anche possibile modificare la configurazione di quali file verranno copiati nella copia shadow nel registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sovrascrivi i file eliminati

* Puoi utilizzare uno **strumento di Windows**: `cipher /w:C` Questo indicherà a cipher di rimuovere qualsiasi dato dallo spazio su disco inutilizzato disponibile all'interno dell'unità C.
* Puoi anche utilizzare strumenti come [**Eraser**](https://eraser.heidi.ie)

### Elimina i registri eventi di Windows

* Windows + R --> eventvwr.msc --> Espandi "Registri di Windows" --> Fai clic destro su ciascuna categoria e seleziona "Cancella registro"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disabilita i registri eventi di Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* All'interno della sezione servizi disabilita il servizio "Registro eventi di Windows"
* `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Disabilita $UsnJrnl

* `fsutil usn deletejournal /d c:`

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
