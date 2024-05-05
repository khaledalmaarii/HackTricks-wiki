# Protezioni di sicurezza di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Gatekeeper

Gatekeeper è solitamente usato per fare riferimento alla combinazione di **Quarantena + Gatekeeper + XProtect**, 3 moduli di sicurezza di macOS che cercheranno di **evitare che gli utenti eseguano software potenzialmente dannoso scaricato**.

Maggiori informazioni in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitanti dei processi

### SIP - Protezione dell'integrità di sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

La Sandbox di macOS **limita le applicazioni** in esecuzione all'interno della sandbox alle **azioni consentite specificate nel profilo della Sandbox** con cui l'applicazione sta funzionando. Questo aiuta a garantire che **l'applicazione acceda solo alle risorse previste**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Trasparenza, Consenso e Controllo**

**TCC (Trasparenza, Consenso e Controllo)** è un framework di sicurezza. È progettato per **gestire le autorizzazioni** delle applicazioni, regolando in particolare il loro accesso alle funzionalità sensibili. Questo include elementi come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. TCC garantisce che le app possano accedere a queste funzionalità solo dopo aver ottenuto il consenso esplicito dell'utente, rafforzando così la privacy e il controllo sui dati personali.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Vincoli di avvio/Ambiente e Cache di fiducia

I vincoli di avvio in macOS sono una funzionalità di sicurezza per **regolare l'avvio dei processi** definendo **chi può avviare** un processo, **come**, e **da dove**. Introdotte in macOS Ventura, categorizzano i binari di sistema in categorie di vincoli all'interno di una **cache di fiducia**. Ogni binario eseguibile ha regole impostate per il suo avvio, inclusi vincoli **self**, **parent** e **responsible**. Estesi alle app di terze parti come Vincoli di **Ambiente** in macOS Sonoma, queste funzionalità aiutano a mitigare potenziali sfruttamenti di sistema regolando le condizioni di avvio dei processi.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Strumento di rimozione malware

Lo Strumento di Rimozione Malware (MRT) è un'altra parte dell'infrastruttura di sicurezza di macOS. Come suggerisce il nome, la funzione principale di MRT è quella di **rimuovere malware conosciuti dai sistemi infetti**.

Una volta rilevato il malware su un Mac (sia da XProtect che da altri mezzi), MRT può essere utilizzato per **rimuovere automaticamente il malware**. MRT opera in modo silenzioso sullo sfondo e di solito viene eseguito ogni volta che il sistema viene aggiornato o quando viene scaricata una nuova definizione di malware (sembra che le regole che MRT deve seguire per rilevare il malware siano all'interno del binario).

Mentre sia XProtect che MRT fanno parte delle misure di sicurezza di macOS, svolgono funzioni diverse:

* **XProtect** è uno strumento preventivo. **Controlla i file durante il download** (tramite determinate applicazioni) e se rileva tipi di malware conosciuti, **impedisce l'apertura del file**, evitando così che il malware infetti il sistema in primo luogo.
* **MRT**, d'altra parte, è uno **strumento reattivo**. Opera dopo che il malware è stato rilevato su un sistema, con l'obiettivo di rimuovere il software offensivo per ripulire il sistema.

L'applicazione MRT si trova in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestione dei compiti in background

**macOS** ora **avverte** ogni volta che un tool utilizza una tecnica ben nota per **persistere nell'esecuzione del codice** (come Elementi di accesso, Daemon...), in modo che l'utente sappia meglio **quale software sta persistendo**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Questo avviene con un **daemon** situato in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e l'**agente** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Il modo in cui **`backgroundtaskmanagementd`** sa che qualcosa è installato in una cartella persistente è tramite **l'ottenimento degli FSEvents** e la creazione di alcuni **gestori** per quelli.

Inoltre, c'è un file plist che contiene **applicazioni ben note** che persistono frequentemente mantenute da Apple situato in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumerazione

È possibile **enumerare tutti** gli elementi di background configurati in esecuzione con lo strumento cli di Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Inoltre, è possibile elencare queste informazioni con [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Queste informazioni vengono memorizzate in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e il Terminale necessita di FDA.

### Manipolazione di BTM

Quando viene trovata una nuova persistenza, viene generato un evento di tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Quindi, qualsiasi modo per **prevenire** l'invio di questo **evento** o per **evitare che l'agente avvisi** l'utente aiuterà un attaccante a _**bypassare**_ BTM.

* **Reimpostare il database**: Eseguire il seguente comando reimposterà il database (dovrebbe ricostruirlo da zero), tuttavia, per qualche motivo, dopo aver eseguito questo passaggio, **nessuna nuova persistenza verrà segnalata fino al riavvio del sistema**.
* È richiesto l'utente **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Arresta l'Agente**: È possibile inviare un segnale di arresto all'agente in modo che **non avvisi l'utente** quando vengono trovate nuove rilevazioni.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Bug**: Se il **processo che ha creato la persistenza esiste velocemente subito dopo**, il demone cercherà di **ottenere informazioni** su di esso, **fallirà**, e **non sarà in grado di inviare l'evento** che indica che una nuova cosa sta persistendo.

Riferimenti e **ulteriori informazioni su BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository github di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
