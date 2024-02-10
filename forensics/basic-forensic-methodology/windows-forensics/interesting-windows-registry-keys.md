# Interessanti Chiavi di Registro di Windows

### Interessanti Chiavi di Registro di Windows

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>


### **Versione di Windows e Informazioni sul Proprietario**
- Situato in **`Software\Microsoft\Windows NT\CurrentVersion`**, troverai la versione di Windows, il Service Pack, l'ora di installazione e il nome del proprietario registrato in modo diretto.

### **Nome del Computer**
- L'hostname si trova in **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Impostazione del Fuso Orario**
- Il fuso orario del sistema è memorizzato in **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Tracciamento dell'Ora di Accesso**
- Di default, il tracciamento dell'ora di accesso dell'ultimo accesso è disattivato (**`NtfsDisableLastAccessUpdate=1`**). Per abilitarlo, utilizza:
`fsutil behavior set disablelastaccess 0`

### Versioni di Windows e Service Pack
- La **versione di Windows** indica l'edizione (ad esempio, Home, Pro) e la sua release (ad esempio, Windows 10, Windows 11), mentre i **Service Pack** sono aggiornamenti che includono correzioni e, talvolta, nuove funzionalità.

### Abilitazione dell'Ora di Accesso dell'Ultimo Accesso
- L'abilitazione del tracciamento dell'ora di accesso dell'ultimo accesso consente di vedere quando i file sono stati aperti per l'ultima volta, il che può essere fondamentale per l'analisi forense o il monitoraggio del sistema.

### Dettagli sulle Informazioni di Rete
- Il registro contiene dati estesi sulle configurazioni di rete, inclusi **tipi di reti (wireless, cavo, 3G)** e **categorie di rete (Pubblica, Privata/Casa, Dominio/Lavoro)**, che sono fondamentali per la comprensione delle impostazioni di sicurezza e delle autorizzazioni di rete.

### Caching del Lato Client (CSC)
- **CSC** migliora l'accesso ai file offline memorizzando copie di file condivisi. Diverse impostazioni di **CSCFlags** controllano come e quali file vengono memorizzati nella cache, influenzando le prestazioni e l'esperienza dell'utente, specialmente in ambienti con connettività intermittente.

### Programmi di Avvio Automatico
- I programmi elencati in varie chiavi di registro `Run` e `RunOnce` vengono avviati automaticamente all'avvio, influenzando il tempo di avvio del sistema e potenzialmente rappresentando punti di interesse per l'individuazione di malware o software indesiderato.

### Shellbags
- Le **Shellbags** non solo memorizzano le preferenze per le visualizzazioni delle cartelle, ma forniscono anche prove forensi dell'accesso alle cartelle anche se la cartella non esiste più. Sono preziose per le indagini, rivelando l'attività dell'utente che non è evidente attraverso altri mezzi.

### Informazioni e Forensic sulle Periferiche USB
- I dettagli memorizzati nel registro sulle periferiche USB possono aiutare a tracciare quali periferiche sono state collegate a un computer, collegando potenzialmente una periferica a trasferimenti di file sensibili o incidenti di accesso non autorizzato.

### Numero di Serie del Volume
- Il **Numero di Serie del Volume** può essere cruciale per tracciare l'istanza specifica di un sistema di file, utile in scenari forensi in cui è necessario stabilire l'origine del file su diversi dispositivi.

### **Dettagli di Spegnimento**
- L'ora di spegnimento e il conteggio (solo per XP) vengono conservati in **`System\ControlSet001\Control\Windows`** e **`System\ControlSet001\Control\Watchdog\Display`**.

### **Configurazione di Rete**
- Per informazioni dettagliate sull'interfaccia di rete, fare riferimento a **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- I tempi di prima e ultima connessione di rete, inclusa la connessione VPN, vengono registrati in vari percorsi in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Cartelle Condivise**
- Le cartelle condivise e le impostazioni si trovano in **`System\ControlSet001\Services\lanmanserver\Shares`**. Le impostazioni di Caching del Lato Client (CSC) determinano la disponibilità dei file offline.

### **Programmi che si Avviano Automaticamente**
- Percorsi come **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** e voci simili in `Software\Microsoft\Windows\CurrentVersion` dettagliano i programmi impostati per l'avvio automatico.

### **Ricerche e Percorsi Digitati**
- Le ricerche dell'Esplora risorse e i percorsi digitati vengono tracciati nel registro in **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** per WordwheelQuery e TypedPaths, rispettivamente.

### **Documenti Recenti e File di Office**
- I documenti recenti e i file di Office a cui si è acceduto vengono registrati in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` e in percorsi specifici delle versioni di Office.

### **Elementi Utilizzati Più di Recente (MRU)**
- Le liste MRU, che indicano i percorsi e i comandi dei file recenti, vengono memorizzate in varie sottochiavi `ComDlg32` e `Explorer` in `NTUSER.DAT`.

### **Tracciamento dell'Attività dell'Utente**
- La funzionalità User Assist registra statistiche dettagliate sull'utilizzo delle applicazioni, inclusi il conteggio di esecuzione e l'ultima ora di esecuzione, in **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analisi delle Shellbags**
- Le Shellbags, che rivelano i dettagli dell'accesso alle cartelle, sono memorizzate in `USRCLASS.DAT` e `NTUSER.DAT` in `Software\Microsoft\Windows\Shell`. Utilizza **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** per l'analisi.

### **Cronologia delle Periferiche USB**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** e **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contengono dettagli completi sulle periferiche USB collegate, inclusi il produttore, il nome del prodotto e i timestamp di connessione.
- L'utente associato a una specifica periferica USB può essere individuato cercando nelle chiavi di registro `NTUSER.DAT` il **{GUID}** della periferica.
- L'ultima periferica montata e il suo numero di serie del volume possono essere tracciati tramite `System\MountedDevices` e `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, rispettivamente
