# macOS MDM

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

**Per saperne di più sugli MDM di macOS controlla:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Concetti di base

### **Panoramica di MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) viene utilizzato per gestire diversi dispositivi utente come smartphone, laptop e tablet. In particolare per le piattaforme Apple (iOS, macOS, tvOS), implica una serie di funzionalità specializzate, API e pratiche. Il funzionamento di MDM si basa su un server MDM compatibile, disponibile commercialmente o open-source, e deve supportare il [Protocollo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). I punti chiave includono:

* Controllo centralizzato dei dispositivi.
* Dipendenza da un server MDM che aderisce al protocollo MDM.
* Capacità del server MDM di inviare vari comandi ai dispositivi, ad esempio cancellazione remota dei dati o installazione di configurazioni.

### **Concetti di base di DEP (Device Enrollment Program)**

Il [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) offerto da Apple semplifica l'integrazione di Mobile Device Management (MDM) facilitando la configurazione senza intervento umano per dispositivi iOS, macOS e tvOS. DEP automatizza il processo di registrazione, consentendo ai dispositivi di essere operativi fin dal primo utilizzo, con un intervento minimo da parte dell'utente o dell'amministratore. Aspetti essenziali includono:

* Consente ai dispositivi di registrarsi autonomamente presso un server MDM predefinito al momento dell'attivazione iniziale.
* Principalmente vantaggioso per i dispositivi nuovi di zecca, ma applicabile anche ai dispositivi sottoposti a riconfigurazione.
* Agevola una configurazione semplice, rendendo i dispositivi pronti per l'uso organizzativo rapidamente.

### **Considerazioni sulla sicurezza**

È fondamentale notare che la facilità di registrazione fornita da DEP, sebbene vantaggiosa, può anche comportare rischi per la sicurezza. Se le misure di protezione non vengono adeguatamente applicate per la registrazione MDM, gli attaccanti potrebbero sfruttare questo processo semplificato per registrare il proprio dispositivo sul server MDM dell'organizzazione, fingendosi un dispositivo aziendale.

{% hint style="danger" %}
**Allerta di sicurezza**: La registrazione semplificata di DEP potrebbe consentire potenzialmente la registrazione non autorizzata di dispositivi sul server MDM dell'organizzazione se non sono in atto adeguate misure di sicurezza.
{% endhint %}

### Concetti di base Cosa è SCEP (Simple Certificate Enrolment Protocol)?

* Un protocollo relativamente vecchio, creato prima che TLS e HTTPS fossero diffusi.
* Fornisce ai client un modo standardizzato per inviare una **Richiesta di Firma del Certificato** (CSR) allo scopo di ottenere un certificato. Il client chiederà al server di fornirgli un certificato firmato.

### Cosa sono i profili di configurazione (aka mobileconfigs)?

* Il modo ufficiale di Apple per **impostare/imporre la configurazione di sistema**.
* Formato di file che può contenere più carichi utili.
* Basato su liste di proprietà (quello XML).
* "possono essere firmati e crittografati per convalidare la loro origine, garantire la loro integrità e proteggere i loro contenuti." Concetti di base - Pagina 70, iOS Security Guide, gennaio 2018.

## Protocolli

### MDM

* Combinazione di APNs (**server Apple**) + API RESTful (**server del fornitore MDM**)
* **Comunicazione** avviene tra un **dispositivo** e un server associato a un **prodotto di gestione dei dispositivi**
* **Comandi** inviati dal MDM al dispositivo in dizionari codificati in plist
* Tutto su **HTTPS**. I server MDM possono essere (e di solito sono) fissati.
* Apple concede al fornitore MDM un **certificato APNs** per l'autenticazione

### DEP

* **3 API**: 1 per i rivenditori, 1 per i fornitori MDM, 1 per l'identità del dispositivo (non documentata):
* La cosiddetta [API "servizio cloud" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Viene utilizzata dai server MDM per associare i profili DEP a dispositivi specifici.
* L'[API DEP utilizzata dai rivenditori autorizzati Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) per registrare dispositivi, verificare lo stato di registrazione e verificare lo stato della transazione.
* L'API DEP privata non documentata. Viene utilizzata dai dispositivi Apple per richiedere il proprio profilo DEP. Su macOS, il binario `cloudconfigurationd` è responsabile della comunicazione tramite questa API.
* Più moderno e basato su **JSON** (rispetto a plist)
* Apple concede al fornitore MDM un **token OAuth**

**API "servizio cloud" DEP**

* RESTful
* sincronizza i record dei dispositivi da Apple al server MDM
* sincronizza i "profili DEP" da Apple al server MDM (consegnati successivamente al dispositivo da Apple)
* Un "profilo" DEP contiene:
* URL del server del fornitore MDM
* Certificati di fiducia aggiuntivi per l'URL del server (pinning opzionale)
* Impostazioni aggiuntive (ad esempio, quali schermate saltare nell'Assistente di configurazione)

## Numero di serie

I dispositivi Apple prodotti dopo il 2010 generalmente hanno numeri di serie alfanumerici di **12 caratteri**, con i **primi tre** cifre che rappresentano il luogo di produzione, le **due** successive che indicano l'anno e la settimana di produzione, le **tre** successive che forniscono un **identificatore univoco**, e le **ultime quattro** cifre che rappresentano il numero di modello.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Passaggi per l'iscrizione e la gestione

1. Creazione del record del dispositivo (Rivenditore, Apple): Viene creato il record per il nuovo dispositivo
2. Assegnazione del record del dispositivo (Cliente): Il dispositivo viene assegnato a un server MDM
3. Sincronizzazione del record del dispositivo (Fornitore MDM): MDM sincronizza i record dei dispositivi e invia i profili DEP ad Apple
4. Check-in DEP (Dispositivo): Il dispositivo ottiene il suo profilo DEP
5. Recupero del profilo (Dispositivo)
6. Installazione del profilo (Dispositivo) a. incl. carichi utili MDM, SCEP e root CA
7. Emissione di comandi MDM (Dispositivo)

![](<../../../.gitbook/assets/image (564).png>)

Il file `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` esporta funzioni che possono essere considerate **"passaggi"** di alto livello del processo di iscrizione.

### Passo 4: Controllo DEP - Ottenere il Record di Attivazione

Questa parte del processo avviene quando un **utente avvia un Mac per la prima volta** (o dopo un'eliminazione completa)

![](<../../../.gitbook/assets/image (568).png>)

o quando si esegue `sudo profiles show -type enrollment`

* Determinare se il dispositivo è abilitato a DEP
* Activation Record è il nome interno del "profilo" DEP
* Inizia non appena il dispositivo è connesso a Internet
* Guidato da **`CPFetchActivationRecord`**
* Implementato da **`cloudconfigurationd`** tramite XPC. Il "Setup Assistant" (quando il dispositivo viene avviato per la prima volta) o il comando **`profiles`** contatteranno questo demone per recuperare il record di attivazione.
* LaunchDaemon (eseguito sempre come root)

Segue alcuni passaggi per ottenere il Record di Attivazione eseguito da **`MCTeslaConfigurationFetcher`**. Questo processo utilizza una crittografia chiamata **Absinthe**

1. Recupera il **certificato**
2. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
3. Inizializza lo stato dal certificato (**`NACInit`**)
4. Utilizza vari dati specifici del dispositivo (ad esempio **Numero di serie tramite `IOKit`**)
5. Recupera la **chiave di sessione**
6. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
7. Stabilisce la sessione (**`NACKeyEstablishment`**)
8. Effettua la richiesta
9. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) inviando i dati `{ "action": "RequestProfileConfiguration", "sn": "" }`
10. Il payload JSON è crittografato utilizzando Absinthe (**`NACSign`**)
11. Tutte le richieste tramite HTTPs, vengono utilizzati certificati radice incorporati

![](<../../../.gitbook/assets/image (566).png>)

La risposta è un dizionario JSON con alcuni dati importanti come:

* **url**: URL dell'host del fornitore MDM per il profilo di attivazione
* **anchor-certs**: Array di certificati DER utilizzati come anchor fidati

### **Passo 5: Recupero del Profilo**

![](<../../../.gitbook/assets/image (567).png>)

* Richiesta inviata all'**URL fornito nel profilo DEP**.
* Vengono utilizzati **certificati anchor** per **valutare la fiducia** se forniti.
* Promemoria: la proprietà **anchor\_certs** del profilo DEP
* La richiesta è un semplice file .plist con l'identificazione del dispositivo
* Esempi: **UDID, versione del sistema operativo**.
* Firmato CMS, codificato DER
* Firmato utilizzando il **certificato di identità del dispositivo (da APNS)**
* La **catena di certificati** include **Apple iPhone Device CA** scaduto

![](https://github.com/carlospolop/hacktricks/blob/it/.gitbook/assets/image%20\(567\)%20\(1\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(7\).png)

### Passo 6: Installazione del Profilo

* Una volta recuperato, il **profilo viene memorizzato nel sistema**
* Questo passaggio inizia automaticamente (se nel **setup assistant**)
* Guidato da **`CPInstallActivationProfile`**
* Implementato da mdmclient tramite XPC
* LaunchDaemon (come root) o LaunchAgent (come utente), a seconda del contesto
* I profili di configurazione hanno più payload da installare
* Il framework ha un'architettura basata su plugin per l'installazione dei profili
* Ogni tipo di payload è associato a un plugin
* Può essere XPC (nel framework) o classico Cocoa (in ManagedClient.app)
* Esempio:
* I payload del certificato utilizzano CertificateService.xpc

Tipicamente, il **profilo di attivazione** fornito da un fornitore MDM includerà i seguenti payload:

* `com.apple.mdm`: per **registrare** il dispositivo in MDM
* `com.apple.security.scep`: per fornire in modo sicuro un **certificato client** al dispositivo.
* `com.apple.security.pem`: per **installare certificati CA fidati** nella System Keychain del dispositivo.
* Installazione del payload MDM equivalente al **check-in MDM nella documentazione**
* Il payload **contiene proprietà chiave**:
*
* URL di check-in MDM (**`CheckInURL`**)
* URL di polling dei comandi MDM (**`ServerURL`**) + argomento APNs per attivarlo
* Per installare il payload MDM, viene inviata una richiesta a **`CheckInURL`**
* Implementato in **`mdmclient`**
* Il payload MDM può dipendere da altri payload
* Consente di **associare le richieste a certificati specifici**:
* Proprietà: **`CheckInURLPinningCertificateUUIDs`**
* Proprietà: **`ServerURLPinningCertificateUUIDs`**
* Consegnato tramite payload PEM
* Consente di attribuire al dispositivo un certificato di identità:
* Proprietà: IdentityCertificateUUID
* Consegnato tramite payload SCEP

### **Passo 7: Ascolto dei comandi MDM**

* Dopo che il check-in MDM è completo, il fornitore può **emettere notifiche push utilizzando APNs**
* Alla ricezione, gestito da **`mdmclient`**
* Per richiedere i comandi MDM, viene inviata una richiesta a ServerURL
* Utilizza il payload MDM precedentemente installato:
* **`ServerURLPinningCertificateUUIDs`** per la richiesta di pinning
* **`IdentityCertificateUUID`** per il certificato client TLS

## Attacchi

### Iscrizione di dispositivi in altre organizzazioni

Come già commentato, per cercare di iscrivere un dispositivo in un'organizzazione **è necessario solo un Numero di Serie appartenente a quella Organizzazione**. Una volta iscritto, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe essere un punto di ingresso pericoloso per gli attaccanti se il processo di iscrizione non è correttamente protetto:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
