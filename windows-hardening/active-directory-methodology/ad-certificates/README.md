# Certificati AD

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Introduzione

### Componenti di un certificato

- Il **Soggetto** del certificato indica il suo proprietario.
- Una **Chiave Pubblica** è associata a una chiave privata per collegare il certificato al suo legittimo proprietario.
- Il **Periodo di Validità**, definito dalle date **NotBefore** e **NotAfter**, indica la durata effettiva del certificato.
- Un **Numero Seriale** univoco, fornito dall'Autorità di Certificazione (CA), identifica ogni certificato.
- L'**Emittente** si riferisce alla CA che ha emesso il certificato.
- **SubjectAlternativeName** consente nomi aggiuntivi per il soggetto, migliorando la flessibilità di identificazione.
- **Vincoli di Base** identificano se il certificato è per una CA o un'entità finale e definiscono le restrizioni di utilizzo.
- **Usi Estesi delle Chiavi (EKUs)** delimitano gli scopi specifici del certificato, come la firma del codice o la crittografia delle email, attraverso gli Identificatori degli Oggetti (OID).
- L'**Algoritmo di Firma** specifica il metodo per firmare il certificato.
- La **Firma**, creata con la chiave privata dell'emittente, garantisce l'autenticità del certificato.

### Considerazioni speciali

- **Subject Alternative Names (SAN)** ampliano l'applicabilità di un certificato a identità multiple, fondamentali per i server con più domini. Processi di emissione sicuri sono vitali per evitare rischi di impersonificazione da parte di attaccanti che manipolano la specifica SAN.

### Autorità di Certificazione (CA) in Active Directory (AD)

AD CS riconosce i certificati CA in un dominio AD attraverso contenitori designati, ognuno con ruoli unici:

- Il contenitore **Certification Authorities** contiene i certificati CA radice fidati.
- Il contenitore **Enrolment Services** dettaglia le CA aziendali e i relativi modelli di certificato.
- L'oggetto **NTAuthCertificates** include i certificati CA autorizzati per l'autenticazione AD.
- Il contenitore **AIA (Authority Information Access)** facilita la validazione della catena di certificati con certificati intermedi e cross CA.

### Acquisizione del certificato: flusso di richiesta del certificato client

1. Il processo di richiesta inizia con i client che trovano una CA aziendale.
2. Viene creata una CSR, contenente una chiave pubblica e altri dettagli, dopo la generazione di una coppia di chiavi pubblica-privata.
3. La CA valuta la CSR rispetto ai modelli di certificato disponibili, emettendo il certificato in base alle autorizzazioni del modello.
4. Dopo l'approvazione, la CA firma il certificato con la propria chiave privata e lo restituisce al client.

### Modelli di certificato

Definiti all'interno di AD, questi modelli delineano le impostazioni e le autorizzazioni per l'emissione dei certificati, inclusi gli EKU consentiti e i diritti di registrazione o modifica, fondamentali per la gestione dell'accesso ai servizi di certificazione.

## Registrazione del certificato

Il processo di registrazione dei certificati viene avviato da un amministratore che **crea un modello di certificato**, che viene quindi **pubblicato** da un'Enterprise Certificate Authority (CA). Ciò rende il modello disponibile per la registrazione del client, un passaggio che si ottiene aggiungendo il nome del modello al campo `certificatetemplates` di un oggetto Active Directory.

Perché un client possa richiedere un certificato, devono essere concessi **diritti di registrazione**. Questi diritti sono definiti da descrittori di sicurezza sul modello di certificato e sulla stessa Enterprise CA. Le autorizzazioni devono essere concesse in entrambe le posizioni affinché una richiesta abbia successo.

### Diritti di registrazione del modello

Questi diritti sono specificati tramite Voci di Controllo di Accesso (ACE), che dettagliano le autorizzazioni come:
- Diritti di **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifiche.
- **ExtendedRights**, che consentono tutte le autorizzazioni estese.
- **FullControl/GenericAll**, che fornisce il controllo completo sul modello.

### Diritti di registrazione dell'Enterprise CA

I diritti della CA sono definiti nel suo descrittore di sicurezza, accessibile tramite la console di gestione dell'Autorità di Certificazione. Alcune impostazioni consentono persino agli utenti a basso privilegio l'accesso remoto, il che potrebbe rappresentare un problema di sicurezza.

### Controlli di emissione aggiuntivi

Possono essere applicati determinati controlli, come:
- **Approvazione del responsabile**: mette le richieste in uno stato di attesa fino all'approvazione da parte di un responsabile dei certificati.
- **Agenti di registrazione e firme autorizzate**: specificano il numero di firme richieste su una CSR e le necessarie Application Policy OIDs.

### Metodi per richiedere certificati

I certificati possono essere richiesti tramite:
1. **Protocollo di registrazione del certificato client di Windows** (MS-WCCE), utilizzando interfacce DCOM.
2. **Protocollo remoto ICertPassage** (MS-ICPR), tramite named pipe o TCP/IP.
3. L'**interfaccia web di registrazione del certificato**, con il ruolo di registrazione web dell'Autorità di Certificazione installato.
4. Il **Servizio di Registrazione del Certificato** (CES), in collaborazione con il servizio di Politica di Registrazione del Certificato (CEP).
5. Il **Servizio di Registrazione dei Dispositivi di Rete** (NDES) per i dispositivi di rete, utilizzando il Protocollo di Registrazione Semplice dei Certificati (SCEP).

Gli utenti di Windows possono anche richiedere certificati tramite l'interfaccia grafica (`certmgr.msc` o `certlm.msc`) o strumenti da riga di comando (`certreq.exe` o il comando `Get-Certificate` di PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta di un Ticket Granting Ticket (TGT) da parte di un utente viene firmata utilizzando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse validazioni da parte del domain controller, tra cui la **validità**, il **percorso** e lo **stato di revoca** del certificato. Le validazioni includono anche la verifica che il certificato provenga da una fonte affidabile e la conferma della presenza dell'emittente nel **certificato NTAUTH store**. Le validazioni riuscite comportano l'emissione di un TGT. L'oggetto **`NTAuthCertificates`** in AD, che si trova in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è fondamentale per stabilire la fiducia nell'autenticazione tramite certificato.

### Autenticazione del canale sicuro (Schannel)

Schannel facilita le connessioni sicure TLS/SSL, in cui durante una handshake, il client presenta un certificato che, se convalidato con successo, autorizza l'accesso. La mappatura di un certificato a un account AD può coinvolgere la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.

### Enumerazione dei servizi di certificazione AD

I servizi di certificazione di AD possono essere enumerati tramite query LDAP, rivelando informazioni su **Enterprise Certificate Authorities (CA)** e le loro configurazioni. Questo è accessibile da qualsiasi utente autenticato nel dominio senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono utilizzati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

I comandi per l'utilizzo di questi strumenti includono:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Riferimenti

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
