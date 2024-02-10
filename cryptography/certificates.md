# Certificati

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare flussi di lavoro** con gli strumenti comunitari più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Cos'è un Certificato

Un **certificato di chiave pubblica** è un'identità digitale utilizzata in crittografia per dimostrare che qualcuno possiede una chiave pubblica. Include i dettagli della chiave, l'identità del proprietario (il soggetto) e una firma digitale da un'autorità fidata (l'emittente). Se il software si fida dell'emittente e la firma è valida, è possibile comunicare in modo sicuro con il proprietario della chiave.

I certificati sono principalmente emessi da [autorità di certificazione](https://en.wikipedia.org/wiki/Certificate_authority) (CA) in un'infrastruttura a chiave pubblica (PKI). Un altro metodo è la [rete di fiducia](https://en.wikipedia.org/wiki/Web_of_trust), in cui gli utenti verificano direttamente le chiavi degli altri. Il formato comune per i certificati è [X.509](https://en.wikipedia.org/wiki/X.509), che può essere adattato per esigenze specifiche come descritto nella RFC 5280.

## Campi Comuni in x509 Certificates

### **Campi Comuni nei Certificati x509**

Nei certificati x509, diversi **campi** svolgono un ruolo critico nel garantire la validità e la sicurezza del certificato. Ecco una panoramica di questi campi:

- Il **Numero di Versione** indica la versione del formato x509.
- Il **Numero di Serie** identifica in modo univoco il certificato all'interno del sistema di una Autorità di Certificazione (CA), principalmente per il tracciamento delle revocazioni.
- Il campo **Soggetto** rappresenta il proprietario del certificato, che può essere una macchina, un individuo o un'organizzazione. Include dettagli di identificazione dettagliati come:
- **Nome Comune (CN)**: Domini coperti dal certificato.
- **Paese (C)**, **Località (L)**, **Stato o Provincia (ST, S o P)**, **Organizzazione (O)** e **Unità Organizzativa (OU)** forniscono dettagli geografici e organizzativi.
- **Nome Distinto (DN)** racchiude l'intera identificazione del soggetto.
- **Emittente** indica chi ha verificato e firmato il certificato, includendo sottocampi simili al Soggetto per la CA.
- Il **Periodo di Validità** è contrassegnato da timestamp **Non Prima di** e **Non Dopo**, garantendo che il certificato non venga utilizzato prima o dopo una determinata data.
- La sezione **Chiave Pubblica**, fondamentale per la sicurezza del certificato, specifica l'algoritmo, la dimensione e altri dettagli tecnici della chiave pubblica.
- Le **estensioni x509v3** migliorano la funzionalità del certificato, specificando **Utilizzo Chiave**, **Utilizzo Esteso Chiave**, **Nome Alternativo del Soggetto** e altre proprietà per ottimizzare l'applicazione del certificato.

#### **Utilizzo Chiave ed Estensioni**

- **Utilizzo Chiave** identifica le applicazioni crittografiche della chiave pubblica, come la firma digitale o la cifratura delle chiavi.
- **Utilizzo Esteso Chiave** restringe ulteriormente i casi d'uso del certificato, ad esempio per l'autenticazione del server TLS.
- **Nome Alternativo del Soggetto** e **Vincolo di Base** definiscono ulteriori nomi host coperti dal certificato e se si tratta di un certificato CA o di un'entità finale, rispettivamente.
- Identificatori come **Identificatore Chiave Soggetto** e **Identificatore Chiave Autorità** garantiscono l'unicità e la tracciabilità delle chiavi.
- **Accesso alle Informazioni dell'Autorità** e **Punti di Distribuzione CRL** forniscono percorsi per verificare l'emittente CA e verificare lo stato di revoca del certificato.
- **CT Precertificate SCTs** offrono registri di trasparenza, fondamentali per la fiducia pubblica nel certificato.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Differenza tra OCSP e CRL Distribution Points**

**OCSP** (**RFC 2560**) coinvolge un client e un responder che lavorano insieme per verificare se un certificato digitale a chiave pubblica è stato revocato, senza la necessità di scaricare l'intera **CRL**. Questo metodo è più efficiente rispetto alla tradizionale **CRL**, che fornisce un elenco di numeri di serie di certificati revocati ma richiede il download di un file potenzialmente grande. Le CRL possono includere fino a 512 voci. Ulteriori dettagli sono disponibili [qui](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Cos'è la Trasparenza dei Certificati**

La Trasparenza dei Certificati aiuta a contrastare le minacce legate ai certificati garantendo che l'emissione e l'esistenza dei certificati SSL siano visibili ai proprietari di domini, alle CA e agli utenti. I suoi obiettivi sono:

* Prevenire alle CA di emettere certificati SSL per un dominio senza la conoscenza del proprietario del dominio.
* Stabilire un sistema di audit aperto per tracciare certificati emessi per errore o in modo malevolo.
* Proteggere gli utenti da certificati fraudolenti.

#### **Log dei Certificati**

I log dei certificati sono registri pubblicamente verificabili e aggiornabili dei certificati, mantenuti da servizi di rete. Questi log forniscono prove crittografiche per scopi di audit. Sia le autorità di emissione che il pubblico possono inviare certificati a questi log o interrogarli per la verifica. Sebbene il numero esatto di server di log non sia fisso, si prevede che sia inferiore a mille a livello globale. Questi server possono essere gestiti in modo indipendente da CA, ISP o da qualsiasi entità interessata.

#### **Interrogazione**

Per esplorare i log di Trasparenza dei Certificati per un determinato dominio, visita [https://crt.sh/](https://crt.sh).

Esistono diversi formati per la memorizzazione dei certificati, ognuno con le proprie applicazioni e compatibilità. Questo riassunto copre i principali formati e fornisce indicazioni sulla conversione tra di essi.

## **Formati**

### **Formato PEM**
- Il formato più ampiamente utilizzato per i certificati.
- Richiede file separati per i certificati e le chiavi private, codificati in Base64 ASCII.
- Estensioni comuni: .cer, .crt, .pem, .key.
- Principalmente utilizzato da Apache e server simili.

### **Formato DER**
- Un formato binario dei certificati.
- Non include le dichiarazioni "BEGIN/END CERTIFICATE" presenti nei file PEM.
- Estensioni comuni: .cer, .der.
- Spesso utilizzato con piattaforme Java.

### **Formato P7B/PKCS#7**
- Memorizzato in Base64 ASCII, con estensioni .p7b o .p7c.
- Contiene solo certificati e certificati di catena, escludendo la chiave privata.
- Supportato da Microsoft Windows e Java Tomcat.

### **Formato PFX/P12/PKCS#12**
- Un formato binario che racchiude certificati del server, certificati intermedi e chiavi private in un unico file.
- Estensioni: .pfx, .p12.
- Principalmente utilizzato su Windows per l'importazione ed esportazione di certificati.

### **Conversione dei Formati**

Le **conversioni PEM** sono essenziali per la compatibilità:

- **x509 a PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM to DER**

- **PEM to DER**

La conversione da formato PEM a formato DER può essere effettuata utilizzando il comando `openssl`. Di seguito è riportato l'esempio di un comando per eseguire questa conversione:

```plaintext
openssl x509 -outform der -in certificate.pem -out certificate.der
```

Assicurati di sostituire `certificate.pem` con il percorso e il nome del tuo certificato PEM. Il certificato convertito verrà salvato come `certificate.der`.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER to PEM**

- **DER to PEM**

- **DER to PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM to P7B**

- **PEM to P7B**

La conversione da formato PEM a formato P7B è un processo comune nel campo della crittografia. Il formato PEM (Privacy Enhanced Mail) è un formato di file ASCII che viene utilizzato per rappresentare certificati digitali e chiavi private. D'altra parte, il formato P7B (PKCS#7) è un formato di file binario che viene utilizzato per archiviare certificati digitali in un pacchetto crittografato.

Per convertire un file PEM in un file P7B, è possibile utilizzare strumenti come OpenSSL. Di seguito è riportato un esempio di comando da utilizzare:

```plaintext
openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b
```

Assicurarsi di sostituire "certificate.pem" con il percorso e il nome del file PEM che si desidera convertire e "certificate.p7b" con il percorso e il nome desiderati per il file P7B di output.

Una volta eseguito il comando, il file PEM verrà convertito nel formato P7B e sarà pronto per essere utilizzato secondo le proprie esigenze crittografiche.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 to PEM**

- **PKCS7 a PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Conversioni PFX** sono cruciali per la gestione dei certificati su Windows:

- **PFX to PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX to PKCS#8** coinvolge due passaggi:
1. Convertire PFX in PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convertire PEM in PKCS8

Per convertire un file PEM in formato PKCS8, è possibile utilizzare il seguente comando:

```plaintext
openssl pkcs8 -topk8 -inform PEM -outform DER -in input.pem -out output.pk8 -nocrypt
```

Questo comando converte il file PEM di input nel formato PKCS8 DER e lo salva nel file di output specificato. L'opzione `-nocrypt` indica che non viene utilizzata alcuna crittografia per proteggere la chiave privata durante la conversione.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B to PFX** richiede anche due comandi:
1. Converti P7B in CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Convertire CER e Chiave Privata in PFX

Per convertire un certificato CER e una chiave privata in un file PFX, è possibile utilizzare lo strumento OpenSSL. Ecco i passaggi da seguire:

1. Assicurarsi di avere OpenSSL installato sul proprio sistema.
2. Aprire una finestra del terminale e spostarsi nella directory in cui si trovano il certificato CER e la chiave privata.
3. Eseguire il seguente comando per creare un file PFX:

```plaintext
openssl pkcs12 -export -out certificate.pfx -inkey privatekey.key -in certificate.cer
```

Assicurarsi di sostituire "privatekey.key" con il nome del file della chiave privata e "certificate.cer" con il nome del file del certificato CER.
4. Verrà richiesto di inserire una password per proteggere il file PFX. Scegliere una password sicura e memorizzarla in un luogo sicuro.
5. Una volta completato il comando, verrà creato un nuovo file chiamato "certificate.pfx" che conterrà il certificato e la chiave privata convertiti.

Ora è possibile utilizzare il file PFX per scopi come l'installazione del certificato su un server o l'importazione in un browser.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
