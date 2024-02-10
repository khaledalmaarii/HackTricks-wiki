# Attacchi fisici

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Recupero della password del BIOS e sicurezza del sistema

**Reimpostare il BIOS** può essere fatto in diversi modi. La maggior parte delle schede madri include una **batteria** che, se rimossa per circa **30 minuti**, reimposterà le impostazioni del BIOS, inclusa la password. In alternativa, è possibile regolare un **jumper sulla scheda madre** per ripristinare queste impostazioni collegando pin specifici.

Per situazioni in cui gli aggiustamenti hardware non sono possibili o pratici, gli **strumenti software** offrono una soluzione. Eseguire un sistema da un **Live CD/USB** con distribuzioni come **Kali Linux** fornisce accesso a strumenti come **_killCmos_** e **_CmosPWD_**, che possono aiutare nel recupero della password del BIOS.

Nei casi in cui la password del BIOS è sconosciuta, inserirla in modo errato **tre volte** di solito comporta un codice di errore. Questo codice può essere utilizzato su siti web come [https://bios-pw.org](https://bios-pw.org) per recuperare potenzialmente una password utilizzabile.

### Sicurezza UEFI

Per i sistemi moderni che utilizzano **UEFI** invece del BIOS tradizionale, lo strumento **chipsec** può essere utilizzato per analizzare e modificare le impostazioni UEFI, inclusa la disabilitazione del **Secure Boot**. Ciò può essere realizzato con il seguente comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analisi della RAM e attacchi Cold Boot

La RAM conserva i dati brevemente dopo l'interruzione dell'alimentazione, di solito per **1 o 2 minuti**. Questa persistenza può essere estesa a **10 minuti** applicando sostanze fredde, come azoto liquido. Durante questo periodo esteso, è possibile creare un **dump di memoria** utilizzando strumenti come **dd.exe** e **volatility** per l'analisi.

### Attacchi di Accesso Diretto alla Memoria (DMA)

**INCEPTION** è uno strumento progettato per la **manipolazione fisica della memoria** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Consente di bypassare le procedure di accesso effettuando una patch alla memoria per accettare qualsiasi password. Tuttavia, non è efficace contro i sistemi **Windows 10**.

### Live CD/USB per l'accesso al sistema

La modifica dei binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere utilizzati per modificare il file **SAM** di un'installazione di Windows, consentendo la modifica delle password.

**Kon-Boot** è uno strumento che facilita l'accesso ai sistemi Windows senza conoscere la password modificando temporaneamente il kernel di Windows o UEFI. Ulteriori informazioni possono essere trovate su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Gestione delle funzionalità di sicurezza di Windows

#### Scorciatoie di avvio e ripristino

- **Supr**: Accedere alle impostazioni del BIOS.
- **F8**: Accedere alla modalità di ripristino.
- Premere **Shift** dopo il banner di Windows può bypassare l'autologon.

#### Dispositivi BAD USB

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per la creazione di dispositivi **USB malevoli**, in grado di eseguire payload predefiniti quando collegati a un computer di destinazione.

#### Copia shadow del volume

I privilegi di amministratore consentono la creazione di copie di file sensibili, inclusi il file **SAM**, tramite PowerShell.

### Bypass dell'encryption BitLocker

L'encryption BitLocker può essere bypassata se la **password di ripristino** viene trovata all'interno di un file di dump di memoria (**MEMORY.DMP**). Strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** possono essere utilizzati per questo scopo.

### Ingegneria sociale per l'aggiunta di una chiave di ripristino

Una nuova chiave di ripristino di BitLocker può essere aggiunta tramite tattiche di ingegneria sociale, convincendo un utente ad eseguire un comando che aggiunge una nuova chiave di ripristino composta da zeri, semplificando così il processo di decrittazione.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
