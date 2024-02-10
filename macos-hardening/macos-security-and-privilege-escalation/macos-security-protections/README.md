# Protezioni di sicurezza di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Gatekeeper

Gatekeeper è solitamente utilizzato per fare riferimento alla combinazione di **Quarantine + Gatekeeper + XProtect**, 3 moduli di sicurezza di macOS che cercheranno di **impedire agli utenti di eseguire software potenzialmente dannoso scaricato**.

Ulteriori informazioni in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitazioni dei processi

### SIP - Protezione dell'integrità del sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

La Sandbox di macOS **limita le applicazioni** in esecuzione all'interno della sandbox alle **azioni consentite specificate nel profilo della Sandbox** con cui l'app viene eseguita. Ciò aiuta a garantire che **l'applicazione acceda solo alle risorse previste**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Trasparenza, consenso e controllo**

**TCC (Trasparenza, consenso e controllo)** è un framework di sicurezza. È progettato per **gestire le autorizzazioni** delle applicazioni, regolando specificamente il loro accesso alle funzioni sensibili. Ciò include elementi come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. TCC garantisce che le app possano accedere a queste funzioni solo dopo aver ottenuto il consenso esplicito dell'utente, rafforzando così la privacy e il controllo sui dati personali.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Vincoli di avvio/ambiente e cache di fiducia

I vincoli di avvio in macOS sono una funzionalità di sicurezza per **regolare l'avvio dei processi** definendo **chi può avviare** un processo, **come** e **da dove**. Introdotto in macOS Ventura, categorizza i binari di sistema in categorie di vincoli all'interno di una **cache di fiducia**. Ogni binario eseguibile ha regole impostate per il suo avvio, inclusi vincoli **self**, **parent** e **responsible**. Estesi alle app di terze parti come Vincoli di **Ambiente** in macOS Sonoma, queste funzionalità aiutano a mitigare potenziali sfruttamenti del sistema governando le condizioni di avvio dei processi.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Strumento di rimozione malware

Lo Strumento di rimozione malware (MRT) è un'altra parte dell'infrastruttura di sicurezza di macOS. Come suggerisce il nome, la funzione principale di MRT è **rimuovere il malware noto dai sistemi infetti**.

Una volta rilevato il malware su un Mac (sia da XProtect che da altri mezzi), MRT può essere utilizzato per **rimuovere automaticamente il malware**. MRT opera in modo silenzioso in background e di solito viene eseguito ogni volta che il sistema viene aggiornato o quando viene scaricata una nuova definizione di malware (sembra che le regole che MRT ha per rilevare il malware siano all'interno del binario).

Mentre sia XProtect che MRT fanno parte delle misure di sicurezza di macOS, svolgono funzioni diverse:

* **XProtect** è uno strumento preventivo. **Controlla i file durante il download** (tramite determinate applicazioni) e se rileva tipi di malware noti, **impedisce l'apertura del file**, evitando così che il malware infetti il sistema in primo luogo.
* **MRT**, d'altra parte, è uno strumento **reattivo**. Opera dopo che il malware è stato rilevato su un sistema, con l'obiettivo di rimuovere il software dannoso per ripulire il sistema.

L'applicazione MRT si trova in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestione delle attività in background

**macOS** ora **avverte** ogni volta che un tool utilizza una nota **tecnica per persistere l'esecuzione del codice** (come Login Items, Daemons...), in modo che l'utente sappia meglio **quali software stanno persistendo**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Ciò avviene con un **daemon** situato in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e l'**agente** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Il modo in cui **`backgroundtaskmanagementd`** sa che qualcosa è installato in una cartella persistente è **ottenendo gli FSEvents** e creando alcuni **gestori** per quelli.

Inoltre, c'è un file plist che contiene **applicazioni ben note** che persistono frequentemente mantenute da Apple, situato in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

È possibile **enumerare tutti** gli elementi di sfondo configurati in esecuzione tramite lo strumento cli di Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Inoltre, è anche possibile elencare queste informazioni con [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Questa informazione viene memorizzata in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e il Terminale ha bisogno di FDA.

### Manipolazione di BTM

Quando viene trovata una nuova persistenza, viene generato un evento di tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Quindi, qualsiasi modo per **prevenire** l'invio di questo **evento** o per impedire all'agente di **avvisare** l'utente aiuterà un attaccante a _**eludere**_ BTM.

* **Ripristino del database**: Eseguendo il seguente comando verrà ripristinato il database (dovrebbe essere ricostruito da zero), tuttavia, per qualche motivo, dopo aver eseguito questo comando, **nessuna nuova persistenza verrà segnalata fino al riavvio del sistema**.
* È richiesto l'accesso **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Arrestare l'Agente**: È possibile inviare un segnale di arresto all'agente in modo che **non avvisi l'utente** quando vengono rilevate nuove minacce.
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
* **Bug**: Se il **processo che ha creato la persistenza esiste velocemente dopo**, il demone cercherà di **ottenere informazioni** su di esso, **fallirà** e **non sarà in grado di inviare l'evento** che indica che qualcosa di nuovo sta persistendo.

Riferimenti e **ulteriori informazioni su BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
