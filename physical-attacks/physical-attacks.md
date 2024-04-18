# Attacchi Fisici

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è combattere i takeover degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

## Recupero Password BIOS e Sicurezza del Sistema

Il **reset del BIOS** può essere effettuato in diversi modi. La maggior parte delle schede madri include una **batteria** che, se rimossa per circa **30 minuti**, resetta le impostazioni del BIOS, inclusa la password. In alternativa, un **ponte sulla scheda madre** può essere regolato per ripristinare queste impostazioni collegando pin specifici.

Per situazioni in cui gli aggiustamenti hardware non sono possibili o pratici, gli **strumenti software** offrono una soluzione. Eseguire un sistema da un **Live CD/USB** con distribuzioni come **Kali Linux** fornisce accesso a strumenti come **_killCmos_** e **_CmosPWD_**, che possono aiutare nel recupero della password del BIOS.

Nei casi in cui la password del BIOS è sconosciuta, inserirla in modo errato **tre volte** di solito comporta un codice di errore. Questo codice può essere utilizzato su siti web come [https://bios-pw.org](https://bios-pw.org) per potenzialmente recuperare una password utilizzabile.

### Sicurezza UEFI

Per i sistemi moderni che utilizzano **UEFI** invece del tradizionale BIOS, lo strumento **chipsec** può essere utilizzato per analizzare e modificare le impostazioni UEFI, inclusa la disabilitazione del **Secure Boot**. Questo può essere realizzato con il seguente comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analisi RAM e Attacchi Cold Boot

La RAM conserva i dati brevemente dopo che l'alimentazione viene interrotta, di solito per **1 o 2 minuti**. Questa persistenza può essere estesa a **10 minuti** applicando sostanze fredde, come azoto liquido. Durante questo periodo prolungato, può essere creato un **dump di memoria** utilizzando strumenti come **dd.exe** e **volatility** per l'analisi.

### Attacchi Direct Memory Access (DMA)

**INCEPTION** è uno strumento progettato per la **manipolazione della memoria fisica** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Consente di bypassare le procedure di accesso patchando la memoria per accettare qualsiasi password. Tuttavia, è inefficace contro i sistemi **Windows 10**.

### Live CD/USB per l'Accesso al Sistema

La modifica dei binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere utilizzati per modificare il file **SAM** di un'installazione di Windows, consentendo modifiche alle password.

**Kon-Boot** è uno strumento che facilita l'accesso ai sistemi Windows senza conoscere la password modificando temporaneamente il kernel di Windows o UEFI. Ulteriori informazioni possono essere trovate su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Gestione delle Funzionalità di Sicurezza di Windows

#### Scorciatoie di Avvio e Ripristino

- **Supr**: Accedere alle impostazioni del BIOS.
- **F8**: Entrare in modalità di ripristino.
- Premere **Shift** dopo il banner di Windows può bypassare l'autologon.

#### Dispositivi BAD USB

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per la creazione di dispositivi **bad USB**, capaci di eseguire payload predefiniti quando collegati a un computer di destinazione.

#### Copia Shadow del Volume

I privilegi di amministratore consentono la creazione di copie di file sensibili, inclusi il file **SAM**, tramite PowerShell.

### Bypassare la Crittografia BitLocker

La crittografia BitLocker può potenzialmente essere bypassata se la **password di ripristino** viene trovata all'interno di un file di dump di memoria (**MEMORY.DMP**). Strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** possono essere utilizzati per questo scopo.

### Ingegneria Sociale per l'Aggiunta della Chiave di Ripristino

Una nuova chiave di ripristino BitLocker può essere aggiunta attraverso tattiche di ingegneria sociale, convincendo un utente ad eseguire un comando che aggiunge una nuova chiave di ripristino composta da zeri, semplificando così il processo di decrittazione.
