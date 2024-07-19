# macOS Office Sandbox Bypasses

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

### Bypass della Sandbox di Word tramite Launch Agents

L'applicazione utilizza una **Sandbox personalizzata** usando il diritto **`com.apple.security.temporary-exception.sbpl`** e questa sandbox personalizzata consente di scrivere file ovunque purché il nome del file inizi con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Pertanto, l'escape era facile come **scrivere un `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Controlla il [**report originale qui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass della Sandbox di Word tramite Login Items e zip

Ricorda che dal primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`, anche se dopo la patch della vulnerabilità precedente non era possibile scrivere in `/Library/Application Scripts` o in `/Library/LaunchAgents`.

È stato scoperto che dall'interno della sandbox è possibile creare un **Login Item** (app che verranno eseguite quando l'utente accede). Tuttavia, queste app **non verranno eseguite a meno che** non siano **notarizzate** e **non è possibile aggiungere argomenti** (quindi non puoi semplicemente eseguire una reverse shell usando **`bash`**).

Dalla precedente bypass della Sandbox, Microsoft ha disabilitato l'opzione di scrivere file in `~/Library/LaunchAgents`. Tuttavia, è stato scoperto che se si mette un **file zip come Login Item**, l'`Archive Utility` semplicemente **decomprimerà** il file nella sua posizione attuale. Quindi, poiché per impostazione predefinita la cartella `LaunchAgents` di `~/Library` non viene creata, è stato possibile **zipare un plist in `LaunchAgents/~$escape.plist`** e **posizionare** il file zip in **`~/Library`** in modo che, quando viene decompresso, raggiunga la destinazione di persistenza.

Controlla il [**report originale qui**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass della Sandbox di Word tramite Login Items e .zshenv

(Ricorda che dal primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`).

Tuttavia, la tecnica precedente aveva una limitazione, se la cartella **`~/Library/LaunchAgents`** esiste perché qualche altro software l'ha creata, fallirebbe. Quindi è stata scoperta una diversa catena di Login Items per questo.

Un attaccante potrebbe creare i file **`.bash_profile`** e **`.zshenv`** con il payload da eseguire e poi zipparli e **scrivere lo zip nella cartella** dell'utente vittima: **`~/~$escape.zip`**.

Poi, aggiungere il file zip ai **Login Items** e poi all'app **`Terminal`**. Quando l'utente effettua nuovamente il login, il file zip verrebbe decompresso nella cartella dell'utente, sovrascrivendo **`.bash_profile`** e **`.zshenv`** e quindi, il terminale eseguirà uno di questi file (a seconda se viene utilizzato bash o zsh).

Controlla il [**report originale qui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass della Sandbox di Word con Open e variabili env

Dai processi sandboxed è ancora possibile invocare altri processi utilizzando l'utility **`open`**. Inoltre, questi processi verranno eseguiti **all'interno della propria sandbox**.

È stato scoperto che l'utility open ha l'opzione **`--env`** per eseguire un'app con **variabili env** specifiche. Pertanto, è stato possibile creare il **file `.zshenv`** all'interno di una cartella **dentro** la **sandbox** e utilizzare `open` con `--env` impostando la **variabile `HOME`** su quella cartella aprendo l'app `Terminal`, che eseguirà il file `.zshenv` (per qualche motivo era anche necessario impostare la variabile `__OSINSTALL_ENVIROMENT`).

Controlla il [**report originale qui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass della Sandbox di Word con Open e stdin

L'utility **`open`** supportava anche il parametro **`--stdin`** (e dopo il bypass precedente non era più possibile utilizzare `--env`).

Il fatto è che anche se **`python`** era firmato da Apple, **non eseguirà** uno script con l'attributo **`quarantine`**. Tuttavia, era possibile passargli uno script da stdin in modo che non controllasse se fosse stato quarantinato o meno:&#x20;

1. Creare un file **`~$exploit.py`** con comandi Python arbitrari.
2. Eseguire _open_ **`–stdin='~$exploit.py' -a Python`**, che esegue l'app Python con il nostro file creato come input standard. Python esegue felicemente il nostro codice e, poiché è un processo figlio di _launchd_, non è vincolato alle regole della sandbox di Word.

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
