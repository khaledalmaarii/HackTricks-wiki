# Bypass del Sandbox di macOS Office

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Bypass del Sandbox di Word tramite Launch Agents

L'applicazione utilizza un **Sandbox personalizzato** utilizzando l'entitlement **`com.apple.security.temporary-exception.sbpl`** e questo Sandbox personalizzato consente di scrivere file ovunque purché il nome del file inizi con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Pertanto, l'escape è stato semplice come **scrivere un file `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Controlla il [**rapporto originale qui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass del Sandbox di Word tramite Login Items e zip

Ricorda che dal primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`, anche se dopo la patch della vulnerabilità precedente non era possibile scrivere in `/Library/Application Scripts` o in `/Library/LaunchAgents`.

È stato scoperto che all'interno del sandbox è possibile creare un **Login Item** (applicazioni che verranno eseguite quando l'utente accede). Tuttavia, queste app **non verranno eseguite** a meno che non siano **notarizzate** e non è possibile aggiungere argomenti (quindi non è possibile eseguire una reverse shell usando **`bash`**).

Dal precedente bypass del Sandbox, Microsoft ha disabilitato l'opzione di scrittura dei file in `~/Library/LaunchAgents`. Tuttavia, è stato scoperto che se si inserisce un **file zip come Login Item**, l'`Archive Utility` lo scompatterà nella sua posizione corrente. Quindi, poiché per impostazione predefinita la cartella `LaunchAgents` di `~/Library` non viene creata, è stato possibile **creare un file plist in `LaunchAgents/~$escape.plist`** e **posizionare** il file zip in **`~/Library`** in modo che, quando viene decompresso, raggiunga la destinazione di persistenza.

Controlla il [**rapporto originale qui**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass del Sandbox di Word tramite Login Items e .zshenv

(Ricorda che dal primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`).

Tuttavia, la tecnica precedente aveva una limitazione: se la cartella **`~/Library/LaunchAgents`** esiste perché è stata creata da un altro software, il bypass fallirebbe. Quindi è stata scoperta una catena di Login Items diversa per questo caso.

Un attaccante potrebbe creare i file **`.bash_profile`** e **`.zshenv`** con il payload da eseguire e quindi comprimerli in un file zip e **scrivere il file zip nella cartella** dell'utente vittima: **`~/~$escape.zip`**.

Successivamente, aggiungi il file zip ai **Login Items** e quindi all'app **`Terminal`**. Quando l'utente effettua nuovamente l'accesso, il file zip verrà decompresso nella cartella dell'utente, sovrascrivendo **`.bash_profile`** e **`.zshenv** e quindi il terminale eseguirà uno di questi file (a seconda se viene utilizzato bash o zsh).

Controlla il [**rapporto originale qui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass del Sandbox di Word con Open e variabili di ambiente

Dai processi sandboxed è ancora possibile invocare altri processi utilizzando l'utilità **`open`**. Inoltre, questi processi verranno eseguiti **all'interno del proprio sandbox**.

È stato scoperto che l'utilità open ha l'opzione **`--env`** per eseguire un'app con **specifiche variabili di ambiente**. Pertanto, è stato possibile creare il file **`.zshenv`** all'interno di una cartella **all'interno** del **sandbox** e utilizzare `open` con `--env` impostando la variabile **`HOME`** su quella cartella aprendo l'app **Terminal**, che eseguirà il file `.zshenv` (per qualche motivo era anche necessario impostare la variabile `__OSINSTALL_ENVIROMENT`).

Controlla il [**rapporto originale qui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass del Sandbox di Word con Open e stdin

L'utilità **`open`** supporta anche il parametro **`--stdin`** (e dopo il bypass precedente non era più possibile utilizzare `--env`).

Il punto è che anche se **`python`** è firmato da Apple, **non eseguirà** uno script con l'attributo **`quarantine`**. Tuttavia, era possibile passargli uno script da stdin in modo che non controllasse se era stato messo in quarantena o meno:&#x20;

1. Crea un file **`~$exploit.py`** con comandi Python arbitrari.
2. Esegui _open_ **`–stdin='~$exploit.py' -a Python`**, che esegue l'app Python con il nostro file inserito come input standard. Python esegue tranquillamente il nostro codice e poiché è un processo figlio di _launchd_, non è vincolato alle regole del sandbox di Word.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
