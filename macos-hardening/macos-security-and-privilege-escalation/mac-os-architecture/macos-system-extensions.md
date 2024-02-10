# Estensioni di sistema macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di GitHub.

</details>

## Estensioni di sistema / Framework di sicurezza degli endpoint

A differenza delle estensioni del kernel, le **estensioni di sistema vengono eseguite nello spazio utente** anziché nello spazio del kernel, riducendo il rischio di un arresto anomalo del sistema a causa di un malfunzionamento dell'estensione.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Ci sono tre tipi di estensioni di sistema: estensioni **DriverKit**, estensioni **Network** ed estensioni **Endpoint Security**.

### **Estensioni DriverKit**

DriverKit è un sostituto delle estensioni del kernel che **fornisce supporto hardware**. Consente ai driver dei dispositivi (come USB, Serial, NIC e HID) di essere eseguiti nello spazio utente anziché nello spazio del kernel. Il framework DriverKit include **versioni nello spazio utente di alcune classi I/O Kit**, e il kernel inoltra gli eventi normali di I/O Kit allo spazio utente, offrendo un ambiente più sicuro per l'esecuzione di questi driver.

### **Estensioni di rete**

Le estensioni di rete forniscono la possibilità di personalizzare i comportamenti di rete. Ci sono diversi tipi di estensioni di rete:

* **App Proxy**: viene utilizzato per creare un client VPN che implementa un protocollo VPN personalizzato orientato al flusso. Ciò significa che gestisce il traffico di rete in base alle connessioni (o flussi) anziché ai singoli pacchetti.
* **Packet Tunnel**: viene utilizzato per creare un client VPN che implementa un protocollo VPN personalizzato orientato al pacchetto. Ciò significa che gestisce il traffico di rete in base ai singoli pacchetti.
* **Filter Data**: viene utilizzato per filtrare i "flussi" di rete. Può monitorare o modificare i dati di rete a livello di flusso.
* **Filter Packet**: viene utilizzato per filtrare i singoli pacchetti di rete. Può monitorare o modificare i dati di rete a livello di pacchetto.
* **DNS Proxy**: viene utilizzato per creare un provider DNS personalizzato. Può essere utilizzato per monitorare o modificare le richieste e le risposte DNS.

## Framework di sicurezza degli endpoint

Endpoint Security è un framework fornito da Apple in macOS che fornisce un insieme di API per la sicurezza del sistema. È destinato all'uso da parte di **fornitori di sicurezza e sviluppatori per creare prodotti in grado di monitorare e controllare l'attività di sistema** per identificare e proteggere contro attività dannose.

Questo framework fornisce una **raccolta di API per monitorare e controllare l'attività di sistema**, come l'esecuzione dei processi, gli eventi del file system, gli eventi di rete e del kernel.

Il nucleo di questo framework è implementato nel kernel, come estensione del kernel (KEXT) situata in **`/System/Library/Extensions/EndpointSecurity.kext`**. Questa KEXT è composta da diversi componenti chiave:

* **EndpointSecurityDriver**: agisce come "punto di ingresso" per l'estensione del kernel. È il punto principale di interazione tra il sistema operativo e il framework Endpoint Security.
* **EndpointSecurityEventManager**: questo componente è responsabile dell'implementazione dei hook del kernel. I hook del kernel consentono al framework di monitorare gli eventi di sistema intercettando le chiamate di sistema.
* **EndpointSecurityClientManager**: gestisce la comunicazione con i client nello spazio utente, tenendo traccia dei client connessi che devono ricevere notifiche sugli eventi.
* **EndpointSecurityMessageManager**: invia messaggi e notifiche sugli eventi ai client nello spazio utente.

Gli eventi che il framework Endpoint Security può monitorare sono categorizzati in:

* Eventi del file
* Eventi del processo
* Eventi del socket
* Eventi del kernel (come caricamento/spegnimento di un'estensione del kernel o apertura di un dispositivo I/O Kit)

### Architettura del framework di sicurezza degli endpoint

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicazione nello spazio utente** con il framework Endpoint Security avviene tramite la classe IOUserClient. Vengono utilizzate due diverse sottoclassi, a seconda del tipo di chiamante:

* **EndpointSecurityDriverClient**: richiede l'abilitazione `com.apple.private.endpoint-security.manager`, che è detenuta solo dal processo di sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: richiede l'abilitazione `com.apple.developer.endpoint-security.client`. Questa sarebbe tipicamente utilizzata da software di sicurezza di terze parti che devono interagire con il framework Endpoint Security.

Le estensioni di sicurezza degli endpoint:**`libEndpointSecurity.dylib`** è la libreria C che le estensioni di sistema utilizzano per comunicare con il kernel. Questa libreria utilizza l'I/O Kit (`IOKit`) per comunicare con la KEXT Endpoint Security.

**`endpointsecurityd`** è un demone di sistema chiave coinvolto nella gestione e nell'avvio delle estensioni di sicurezza degli endpoint, in particolare durante il processo di avvio iniziale. Solo le estensioni di sistema contrassegnate con **`NSEndpointSecurityEarlyBoot`** nel loro file `Info.plist` ricevono questo trattamento di avvio iniziale.

Un altro demone di sistema, **`sysextd`**, **convalida le estensioni di sistema** e le sposta nelle posizioni di sistema corrette. Quindi chiede al demone pertinente di caricare l'estensione. Il **`SystemExtensions.framework`** è responsabile dell'attivazione e della disattivazione delle estensioni di sistema.

## Bypassare ESF

ESF viene utilizzato da strumenti di sicurezza che cercheranno di rilevare un red teamer, quindi qualsiasi informazione su come evitare ciò suona interessante.

### CVE-2021-30965

La cosa è che l'applicazione di sicurezza deve avere **permessi di accesso completo al disco**. Quindi, se un attaccante potesse rimuoverlo, potrebbe impedire l'esecuzione del software:
```bash
tccutil reset All
```
Per **ulteriori informazioni** su questo bypass e quelli correlati, consulta la presentazione [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Alla fine, questo è stato risolto concedendo il nuovo permesso **`kTCCServiceEndpointSecurityClient`** all'app di sicurezza gestita da **`tccd`**, in modo che `tccutil` non cancelli i suoi permessi impedendone l'esecuzione.

## Riferimenti

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
