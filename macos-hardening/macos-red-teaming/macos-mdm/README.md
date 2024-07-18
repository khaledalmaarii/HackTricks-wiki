# macOS MDM

{% hint style="success" %}
Impara e pratica l'hacking di AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking di GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository github di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

**Per saperne di più sui macOS MDM, controlla:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Concetti di base

### **Panoramica di MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) è utilizzato per gestire vari dispositivi per utenti finali come smartphone, laptop e tablet. In particolare per le piattaforme Apple (iOS, macOS, tvOS), coinvolge un insieme di funzionalità specializzate, API e pratiche. Il funzionamento di MDM si basa su un server MDM compatibile, che può essere commerciale o open-source, e deve supportare il [Protocollo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). I punti chiave includono:

* Controllo centralizzato sui dispositivi.
* Dipendenza da un server MDM che rispetti il protocollo MDM.
* Capacità del server MDM di inviare vari comandi ai dispositivi, ad esempio cancellazione remota dei dati o installazione di configurazioni.

### **Fondamenti di DEP (Device Enrollment Program)**

Il [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) offerto da Apple semplifica l'integrazione del Mobile Device Management (MDM) facilitando la configurazione senza intervento per i dispositivi iOS, macOS e tvOS. DEP automatizza il processo di registrazione, consentendo ai dispositivi di essere operativi immediatamente, con minima intervento dell'utente o amministrativo. Aspetti essenziali includono:

* Consente ai dispositivi di registrarsi autonomamente con un server MDM predefinito durante l'attivazione iniziale.
* Principalmente utile per i dispositivi nuovi di zecca, ma applicabile anche ai dispositivi in fase di riconfigurazione.
* Agevola una configurazione semplice, rendendo i dispositivi pronti per l'uso organizzativo rapidamente.

### **Considerazioni sulla sicurezza**

È fondamentale notare che la facilità di registrazione fornita da DEP, sebbene vantaggiosa, può anche comportare rischi per la sicurezza. Se le misure di protezione non vengono adeguatamente applicate per la registrazione MDM, gli attaccanti potrebbero sfruttare questo processo semplificato per registrare il proprio dispositivo sul server MDM dell'organizzazione, fingendo di essere un dispositivo aziendale.

{% hint style="danger" %}
**Avviso di sicurezza**: La registrazione semplificata di DEP potrebbe potenzialmente consentire la registrazione non autorizzata di dispositivi sul server MDM dell'organizzazione se non sono in atto adeguate misure di sicurezza.
{% endhint %}

### Cosa è SCEP (Simple Certificate Enrolment Protocol)?

* Un protocollo relativamente vecchio, creato prima che TLS e HTTPS fossero diffusi.
* Fornisce ai client un modo standardizzato per inviare una **Richiesta di Firma del Certificato** (CSR) allo scopo di ottenere un certificato. Il client chiederà al server di fornirgli un certificato firmato.

### Cosa sono i Profili di Configurazione (noti anche come mobileconfigs)?

* Modo ufficiale di **impostare/imporre la configurazione di sistema** di Apple.
* Formato file che può contenere più carichi.
* Basato su elenchi di proprietà (quelli di tipo XML).
* "possono essere firmati e crittografati per convalidare la loro origine, garantire la loro integrità e proteggere i loro contenuti." Fondamenti - Pagina 70, Guida alla sicurezza di iOS, gennaio 2018.

## Protocolli

### MDM

* Combinazione di APNs (**server Apple**) + API RESTful (**server fornitore MDM**)
* La **comunicazione** avviene tra un **dispositivo** e un server associato a un **prodotto di gestione dei dispositivi**
* I **comandi** vengono inviati dall'MDM al dispositivo in **dizionari codificati in plist**
* Tutto su **HTTPS**. I server MDM possono essere (e di solito sono) pinnati.
* Apple concede al fornitore MDM un **certificato APNs** per l'autenticazione

### DEP

* **3 API**: 1 per i rivenditori, 1 per i fornitori MDM, 1 per l'identità del dispositivo (non documentata):
* La cosiddetta [API del "servizio cloud" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Questa viene utilizzata dai server MDM per associare i profili DEP a dispositivi specifici.
* L'[API DEP utilizzata dai Rivenditori Autorizzati Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) per registrare dispositivi, controllare lo stato della registrazione e lo stato della transazione.
* L'API DEP privata non documentata. Questa viene utilizzata dai dispositivi Apple per richiedere il proprio profilo DEP. Su macOS, il binario `cloudconfigurationd` è responsabile della comunicazione su questa API.
* Più moderno e basato su **JSON** (rispetto a plist)
* Apple concede un **token OAuth** al fornitore MDM

**API del "servizio cloud" DEP**

* RESTful
* sincronizza i record dei dispositivi da Apple al server MDM
* sincronizza i "profili DEP" da Apple al server MDM (consegnati da Apple al dispositivo in seguito)
* Un "profilo" DEP contiene:
* URL del server del fornitore MDM
* Certificati aggiuntivi fidati per l'URL del server (pinnaggio opzionale)
* Impostazioni aggiuntive (ad es. quali schermate saltare nell'Assistente di configurazione)

## Numero di serie

I dispositivi Apple prodotti dopo il 2010 hanno generalmente **numeri di serie alfanumerici di 12 caratteri**, con i **primi tre cifre che rappresentano il luogo di produzione**, le **due** seguenti che indicano l'**anno** e la **settimana** di produzione, le **tre** cifre successive che forniscono un **identificatore univoco**, e gli **ultimi** **quattro** cifre che rappresentano il **numero di modello**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Passaggi per la registrazione e la gestione

1. Creazione del record del dispositivo (Rivenditore, Apple): Viene creato il record per il nuovo dispositivo
2. Assegnazione del record del dispositivo (Cliente): Il dispositivo viene assegnato a un server MDM
3. Sincronizzazione del record del dispositivo (Fornitore MDM): MDM sincronizza i record dei dispositivi e invia i profili DEP ad Apple
4. Check-in DEP (Dispositivo): Il dispositivo riceve il suo profilo DEP
5. Recupero del profilo (Dispositivo)
6. Installazione del profilo (Dispositivo) a. incl. carichi MDM, SCEP e root CA
7. Emissione di comandi MDM (Dispositivo)

![](<../../../.gitbook/assets/image (694).png>)

Il file `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` esporta funzioni che possono essere considerate **"passaggi" di alto livello** del processo di registrazione.
### Passo 4: Controllo DEP - Ottenere il Record di Attivazione

Questa parte del processo avviene quando un **utente avvia un Mac per la prima volta** (o dopo un wipe completo)

![](<../../../.gitbook/assets/image (1044).png>)

o eseguendo `sudo profiles show -type enrollment`

* Determinare se il dispositivo è abilitato al **DEP**
* Il Record di Attivazione è il nome interno del **"profilo" DEP**
* Inizia non appena il dispositivo è connesso a Internet
* Gestito da **`CPFetchActivationRecord`**
* Implementato da **`cloudconfigurationd`** tramite XPC. Il **"Setup Assistant"** (quando il dispositivo viene avviato per la prima volta) o il comando **`profiles`** contatteranno questo demone per recuperare il record di attivazione.
* LaunchDaemon (eseguito sempre come root)

Segue alcuni passaggi per ottenere il Record di Attivazione eseguito da **`MCTeslaConfigurationFetcher`**. Questo processo utilizza una crittografia chiamata **Absinthe**

1. Recupera il **certificato**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inizializza** lo stato dal certificato (**`NACInit`**)
1. Utilizza vari dati specifici del dispositivo (ad esempio il **Numero di Serie tramite `IOKit`**)
3. Recupera la **chiave di sessione**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stabilisce la sessione (**`NACKeyEstablishment`**)
5. Effettua la richiesta
1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) inviando i dati `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Il payload JSON è crittografato utilizzando Absinthe (**`NACSign`**)
3. Tutte le richieste sono su HTTPs, vengono utilizzati certificati radice incorporati

![](<../../../.gitbook/assets/image (566) (1).png>)

La risposta è un dizionario JSON con alcuni dati importanti come:

* **url**: URL dell'host del fornitore MDM per il profilo di attivazione
* **anchor-certs**: Array di certificati DER utilizzati come anchor fidati

### **Passo 5: Recupero del Profilo**

![](<../../../.gitbook/assets/image (444).png>)

* Richiesta inviata all'**URL fornito nel profilo DEP**.
* I **certificati anchor** vengono utilizzati per **valutare la fiducia** se forniti.
* Promemoria: la proprietà **anchor\_certs** del profilo DEP
* **La richiesta è un semplice .plist** con l'identificazione del dispositivo
* Esempi: **UDID, versione del SO**.
* Firmato CMS, codificato DER
* Firmato utilizzando il **certificato di identità del dispositivo (da APNS)**
* **La catena di certificati** include il certificato scaduto **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Passo 6: Installazione del Profilo

* Una volta recuperato, il **profilo viene memorizzato nel sistema**
* Questo passaggio inizia automaticamente (se nel **setup assistant**)
* Gestito da **`CPInstallActivationProfile`**
* Implementato da mdmclient tramite XPC
* LaunchDaemon (come root) o LaunchAgent (come utente), a seconda del contesto
* I profili di configurazione hanno più payload da installare
* Il framework ha un'architettura basata su plugin per l'installazione dei profili
* Ogni tipo di payload è associato a un plugin
* Può essere XPC (nel framework) o Cocoa classico (in ManagedClient.app)
* Esempio:
* I Payload dei Certificati utilizzano CertificateService.xpc

Tipicamente, il **profilo di attivazione** fornito da un fornitore MDM includerà i seguenti payload:

* `com.apple.mdm`: per **registrare** il dispositivo in MDM
* `com.apple.security.scep`: per fornire in modo sicuro un **certificato client** al dispositivo.
* `com.apple.security.pem`: per **installare certificati CA fidati** nella System Keychain del dispositivo.
* Installando il payload MDM equivalente al **check-in MDM nella documentazione**
* Il payload **contiene proprietà chiave**:
*
* URL di Check-In MDM (**`CheckInURL`**)
* URL di Polling dei Comandi MDM (**`ServerURL`**) + argomento APNs per attivarlo
* Per installare il payload MDM, viene inviata una richiesta a **`CheckInURL`**
* Implementato in **`mdmclient`**
* Il payload MDM può dipendere da altri payload
* Consente di **vincolare le richieste a certificati specifici**:
* Proprietà: **`CheckInURLPinningCertificateUUIDs`**
* Proprietà: **`ServerURLPinningCertificateUUIDs`**
* Consegnato tramite payload PEM
* Consente al dispositivo di essere attribuito con un certificato di identità:
* Proprietà: IdentityCertificateUUID
* Consegnato tramite payload SCEP

### **Passo 7: Ascolto dei Comandi MDM**

* Dopo che il check-in MDM è completato, il fornitore può **emettere notifiche push utilizzando APNs**
* Alla ricezione, gestito da **`mdmclient`**
* Per interrogare i comandi MDM, viene inviata una richiesta a ServerURL
* Utilizza il payload MDM precedentemente installato:
* **`ServerURLPinningCertificateUUIDs`** per vincolare la richiesta
* **`IdentityCertificateUUID`** per il certificato client TLS

## Attacchi

### Registrazione di Dispositivi in Altre Organizzazioni

Come già commentato, per cercare di registrare un dispositivo in un'organizzazione **è necessario solo un Numero di Serie appartenente a quella Organizzazione**. Una volta che il dispositivo è registrato, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe essere un punto di ingresso pericoloso per gli attaccanti se il processo di registrazione non è correttamente protetto:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
