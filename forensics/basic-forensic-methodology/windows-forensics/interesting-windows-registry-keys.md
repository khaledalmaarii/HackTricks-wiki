# Interessanti Chiavi di Registro di Windows

### Interessanti Chiavi di Registro di Windows

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}

### **Versione di Windows e Informazioni sul Proprietario**
- Situato in **`Software\Microsoft\Windows NT\CurrentVersion`**, troverai la versione di Windows, il Service Pack, l'ora di installazione e il nome del proprietario registrato in modo diretto.

### **Nome del Computer**
- Il nome host si trova sotto **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Impostazione del Fuso Orario**
- Il fuso orario del sistema è memorizzato in **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Tracciamento dell'Ora di Accesso**
- Per impostazione predefinita, il tracciamento dell'ultima ora di accesso è disattivato (**`NtfsDisableLastAccessUpdate=1`**). Per abilitarlo, utilizza:
`fsutil behavior set disablelastaccess 0`

### Versioni di Windows e Service Pack
- La **versione di Windows** indica l'edizione (ad esempio, Home, Pro) e il suo rilascio (ad esempio, Windows 10, Windows 11), mentre i **Service Pack** sono aggiornamenti che includono correzioni e, talvolta, nuove funzionalità.

### Abilitazione dell'Ora di Accesso
- Abilitare il tracciamento dell'ultima ora di accesso consente di vedere quando i file sono stati aperti per l'ultima volta, il che può essere fondamentale per l'analisi forense o il monitoraggio del sistema.

### Dettagli delle Informazioni di Rete
- Il registro contiene dati estesi sulle configurazioni di rete, inclusi **tipi di reti (wireless, via cavo, 3G)** e **categorie di reti (Pubblica, Privata/Domestica, Dominio/Lavoro)**, che sono fondamentali per comprendere le impostazioni di sicurezza e le autorizzazioni di rete.

### Caching Lato Client (CSC)
- **CSC** migliora l'accesso ai file offline memorizzando copie di file condivisi. Diverse impostazioni di **CSCFlags** controllano come e quali file vengono memorizzati nella cache, influenzando le prestazioni e l'esperienza dell'utente, specialmente in ambienti con connettività intermittente.

### Programmi di Avvio Automatico
- I programmi elencati in varie chiavi di registro `Run` e `RunOnce` vengono avviati automaticamente all'avvio, influenzando il tempo di avvio del sistema e potenzialmente rappresentando punti di interesse per identificare malware o software indesiderato.

### Shellbags
- Le **Shellbags** non solo memorizzano le preferenze per le visualizzazioni delle cartelle, ma forniscono anche prove forensi dell'accesso alle cartelle anche se la cartella non esiste più. Sono preziose per le indagini, rivelando l'attività dell'utente che non è evidente attraverso altri mezzi.

### Informazioni USB e Forensica
- I dettagli memorizzati nel registro sui dispositivi USB possono aiutare a tracciare quali dispositivi sono stati collegati a un computer, collegando potenzialmente un dispositivo a trasferimenti di file sensibili o incidenti di accesso non autorizzato.

### Numero Seriale del Volume
- Il **Numero Seriale del Volume** può essere cruciale per tracciare l'istanza specifica di un sistema di file, utile in scenari forensi in cui è necessario stabilire l'origine del file su diversi dispositivi.

### **Dettagli dello Spegnimento**
- L'ora di spegnimento e il conteggio (solo per XP) sono conservati in **`System\ControlSet001\Control\Windows`** e **`System\ControlSet001\Control\Watchdog\Display`**.

### **Configurazione di Rete**
- Per informazioni dettagliate sull'interfaccia di rete, fare riferimento a **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Le prime e ultime ore di connessione di rete, inclusi le connessioni VPN, sono registrate in vari percorsi in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Cartelle Condivise**
- Le cartelle condivise e le impostazioni si trovano in **`System\ControlSet001\Services\lanmanserver\Shares`**. Le impostazioni di Caching Lato Client (CSC) dettano la disponibilità dei file offline.

### **Programmi che si Avviano Automaticamente**
- Percorsi come **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** e voci simili in `Software\Microsoft\Windows\CurrentVersion` dettagliano i programmi impostati per l'avvio automatico.

### **Ricerche e Percorsi Digitati**
- Le ricerche di Explorer e i percorsi digitati sono tracciati nel registro sotto **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** per WordwheelQuery e TypedPaths, rispettivamente.

### **Documenti Recenti e File di Office**
- I documenti recenti e i file di Office accessati sono annotati in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` e percorsi specifici delle versioni di Office.

### **Elementi Più Recenti Utilizzati (MRU)**
- Le liste MRU, che indicano percorsi e comandi di file recenti, sono memorizzate in varie sottochiavi `ComDlg32` e `Explorer` in `NTUSER.DAT`.

### **Tracciamento dell'Attività dell'Utente**
- La funzionalità User Assist registra statistiche dettagliate sull'uso delle applicazioni, inclusi il conteggio di esecuzione e l'ultima ora di esecuzione, in **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analisi delle Shellbags**
- Le Shellbags, che rivelano dettagli sull'accesso alle cartelle, sono memorizzate in `USRCLASS.DAT` e `NTUSER.DAT` sotto `Software\Microsoft\Windows\Shell`. Utilizza **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** per l'analisi.

### **Cronologia dei Dispositivi USB**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** e **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contengono dettagli completi sui dispositivi USB collegati, inclusi produttore, nome del prodotto e timestamp di connessione.
- L'utente associato a un dispositivo USB specifico può essere individuato cercando nei rami `NTUSER.DAT` per il **{GUID}** del dispositivo.
- L'ultimo dispositivo montato e il relativo numero seriale del volume possono essere tracciati attraverso `System\MountedDevices` e `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, rispettivamente.

Questa guida condensa i percorsi e i metodi cruciali per accedere a informazioni dettagliate sul sistema, sulla rete e sull'attività dell'utente nei sistemi Windows, puntando alla chiarezza e all'usabilità.



{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
