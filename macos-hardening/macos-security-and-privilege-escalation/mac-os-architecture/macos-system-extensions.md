# Estensioni di sistema macOS

{% hint style="success" %}
Impara e pratica l'hacking di AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking di GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di GitHub.

</details>
{% endhint %}

## Estensioni di Sistema / Framework di Sicurezza degli Endpoint

A differenza delle Estensioni del Kernel, **le Estensioni di Sistema vengono eseguite nello spazio utente** invece che nello spazio kernel, riducendo il rischio di un arresto del sistema dovuto al malfunzionamento dell'estensione.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Ci sono tre tipi di estensioni di sistema: Estensioni **DriverKit**, Estensioni di **Rete** e Estensioni di **Sicurezza degli Endpoint**.

### **Estensioni DriverKit**

DriverKit è un sostituto delle estensioni del kernel che **fornisce supporto hardware**. Consente ai driver dei dispositivi (come USB, Seriale, NIC e driver HID) di essere eseguiti nello spazio utente anziché nello spazio kernel. Il framework DriverKit include **versioni nello spazio utente di alcune classi di I/O Kit**, e il kernel inoltra gli eventi normali di I/O Kit allo spazio utente, offrendo un ambiente più sicuro per l'esecuzione di questi driver.

### **Estensioni di Rete**

Le Estensioni di Rete forniscono la possibilità di personalizzare i comportamenti di rete. Ci sono diversi tipi di Estensioni di Rete:

* **Proxy dell'Applicazione**: Questo viene utilizzato per creare un client VPN che implementa un protocollo VPN personalizzato orientato al flusso. Ciò significa che gestisce il traffico di rete in base alle connessioni (o flussi) anziché ai singoli pacchetti.
* **Tunnel di Pacchetti**: Questo viene utilizzato per creare un client VPN che implementa un protocollo VPN personalizzato orientato al pacchetto. Ciò significa che gestisce il traffico di rete in base ai singoli pacchetti.
* **Dati di Filtraggio**: Questo viene utilizzato per filtrare "flussi" di rete. Può monitorare o modificare i dati di rete a livello di flusso.
* **Pacchetto di Filtraggio**: Questo viene utilizzato per filtrare singoli pacchetti di rete. Può monitorare o modificare i dati di rete a livello di pacchetto.
* **Proxy DNS**: Questo viene utilizzato per creare un provider DNS personalizzato. Può essere utilizzato per monitorare o modificare le richieste e le risposte DNS.

## Framework di Sicurezza degli Endpoint

La Sicurezza degli Endpoint è un framework fornito da Apple in macOS che fornisce un insieme di API per la sicurezza del sistema. È destinato all'uso da parte di **fornitori di sicurezza e sviluppatori per creare prodotti in grado di monitorare e controllare l'attività di sistema** per identificare e proteggere contro attività dannose.

Questo framework fornisce una **raccolta di API per monitorare e controllare l'attività di sistema**, come esecuzioni di processi, eventi del file system, eventi di rete ed eventi del kernel.

Il nucleo di questo framework è implementato nel kernel, come un'estensione del kernel (KEXT) situata in **`/System/Library/Extensions/EndpointSecurity.kext`**. Questo KEXT è composto da diversi componenti chiave:

* **EndpointSecurityDriver**: Agisce come "punto di ingresso" per l'estensione del kernel. È il principale punto di interazione tra il sistema operativo e il framework di Sicurezza degli Endpoint.
* **EndpointSecurityEventManager**: Questo componente è responsabile dell'implementazione degli hook del kernel. Gli hook del kernel consentono al framework di monitorare gli eventi di sistema intercettando le chiamate di sistema.
* **EndpointSecurityClientManager**: Gestisce la comunicazione con i client nello spazio utente, tenendo traccia dei client connessi che necessitano di ricevere notifiche sugli eventi.
* **EndpointSecurityMessageManager**: Invia messaggi e notifiche sugli eventi ai client nello spazio utente.

Gli eventi che il framework di Sicurezza degli Endpoint può monitorare sono categorizzati in:

* Eventi del file
* Eventi del processo
* Eventi del socket
* Eventi del kernel (come il caricamento/scaricamento di un'estensione del kernel o l'apertura di un dispositivo I/O Kit)

### Architettura del Framework di Sicurezza degli Endpoint

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicazione nello spazio utente** con il framework di Sicurezza degli Endpoint avviene attraverso la classe IOUserClient. Vengono utilizzate due diverse sottoclassi, a seconda del tipo di chiamante:

* **EndpointSecurityDriverClient**: Richiede l'abilitazione `com.apple.private.endpoint-security.manager`, che è detenuta solo dal processo di sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Richiede l'abilitazione `com.apple.developer.endpoint-security.client`. Questo sarebbe tipicamente utilizzato da software di sicurezza di terze parti che devono interagire con il framework di Sicurezza degli Endpoint.

Le Estensioni di Sicurezza degli Endpoint: **`libEndpointSecurity.dylib`** è la libreria C che le estensioni di sistema utilizzano per comunicare con il kernel. Questa libreria utilizza l'I/O Kit (`IOKit`) per comunicare con il KEXT di Sicurezza degli Endpoint.

**`endpointsecurityd`** è un demone di sistema chiave coinvolto nella gestione e nell'avvio delle estensioni di sistema di sicurezza degli endpoint, in particolare durante il processo di avvio iniziale. **Solo le estensioni di sistema** contrassegnate con **`NSEndpointSecurityEarlyBoot`** nel loro file `Info.plist` ricevono questo trattamento di avvio anticipato.

Un altro demone di sistema, **`sysextd`**, **convalida le estensioni di sistema** e le sposta nelle posizioni di sistema appropriate. Chiede quindi al demone rilevante di caricare l'estensione. Il **`SystemExtensions.framework`** è responsabile dell'attivazione e della disattivazione delle estensioni di sistema.

## Bypassare ESF

ESF è utilizzato da strumenti di sicurezza che cercheranno di rilevare un red teamer, quindi qualsiasi informazione su come questo potrebbe essere evitato suona interessante.

### CVE-2021-30965

La questione è che l'applicazione di sicurezza deve avere le **autorizzazioni di Accesso Completo al Disco**. Quindi se un attaccante potesse rimuoverle, potrebbe impedire l'esecuzione del software:
```bash
tccutil reset All
```
Per **ulteriori informazioni** su questo bypass e quelli correlati, controlla il talk [#OBTS v5.0: "Il tallone d'Achille della sicurezza degli endpoint" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Alla fine questo è stato risolto concedendo il nuovo permesso **`kTCCServiceEndpointSecurityClient`** all'applicazione di sicurezza gestita da **`tccd`** in modo che `tccutil` non cancelli i suoi permessi impedendogli di eseguirsi.

## Riferimenti

* [**OBTS v3.0: "Sicurezza e insicurezza degli endpoint" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
