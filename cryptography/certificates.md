# Certificati

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Cos'è un Certificato

Un **certificato di chiave pubblica** è un'identità digitale utilizzata in crittografia per dimostrare che qualcuno possiede una chiave pubblica. Include i dettagli della chiave, l'identità del proprietario (il soggetto) e una firma digitale da un'autorità fidata (l'emittente). Se il software si fida dell'emittente e la firma è valida, è possibile comunicare in modo sicuro con il proprietario della chiave.

I certificati sono principalmente emessi da [autorità di certificazione](https://en.wikipedia.org/wiki/Certificate\_authority) (CA) in un'infrastruttura a chiave pubblica (PKI). Un altro metodo è la [rete di fiducia](https://en.wikipedia.org/wiki/Web\_of\_trust), dove gli utenti verificano direttamente le chiavi degli altri. Il formato comune per i certificati è [X.509](https://en.wikipedia.org/wiki/X.509), che può essere adattato per esigenze specifiche come descritto in RFC 5280.

## Campi Comuni di x509

### **Campi Comuni nei Certificati x509**

Nei certificati x509, diversi **campi** svolgono ruoli critici per garantire la validità e la sicurezza del certificato. Ecco una panoramica di questi campi:

* Il **Numero di Versione** indica la versione del formato x509.
* Il **Numero Seriale** identifica univocamente il certificato all'interno del sistema di un'Authority di Certificazione (CA), principalmente per il tracciamento delle revocazioni.
* Il campo **Soggetto** rappresenta il proprietario del certificato, che potrebbe essere una macchina, un individuo o un'organizzazione. Include dettagliati identificativi come:
* **Nome Comune (CN)**: Domini coperti dal certificato.
* **Paese (C)**, **Località (L)**, **Stato o Provincia (ST, S, o P)**, **Organizzazione (O)** e **Unità Organizzativa (OU)** forniscono dettagli geografici e organizzativi.
* Il **Nome Distinto (DN)** racchiude l'identificazione completa del soggetto.
* **Emittente** dettaglia chi ha verificato e firmato il certificato, inclusi sottocampi simili al Soggetto per la CA.
* Il **Periodo di Validità** è contrassegnato dai timestamp **Non Prima di** e **Non Dopo**, garantendo che il certificato non venga utilizzato prima o dopo una certa data.
* La sezione **Chiave Pubblica**, cruciale per la sicurezza del certificato, specifica l'algoritmo, le dimensioni e altri dettagli tecnici della chiave pubblica.
* Le **estensioni x509v3** migliorano la funzionalità del certificato, specificando **Utilizzo Chiave**, **Utilizzo Esteso Chiave**, **Nome Alternativo Soggetto** e altre proprietà per ottimizzare l'applicazione del certificato.

#### **Utilizzo Chiave ed Estensioni**

* **Utilizzo Chiave** identifica le applicazioni crittografiche della chiave pubblica, come firma digitale o cifratura chiave.
* **Utilizzo Esteso Chiave** restringe ulteriormente i casi d'uso del certificato, ad esempio per l'autenticazione del server TLS.
* **Nome Alternativo Soggetto** e **Vincolo di Base** definiscono ulteriori nomi host coperti dal certificato e se si tratta di un certificato CA o di entità finale, rispettivamente.
* Gli identificatori come **Identificatore Chiave Soggetto** e **Identificatore Chiave Autorità** garantiscono l'unicità e la tracciabilità delle chiavi.
* **Accesso alle Informazioni dell'Autorità** e **Punti di Distribuzione CRL** forniscono percorsi per verificare l'emittente CA e controllare lo stato di revoca del certificato.
* **CT Precertificate SCTs** offrono registri di trasparenza, cruciali per la fiducia pubblica nel certificato.
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
### **Differenza tra punti di distribuzione OCSP e CRL**

**OCSP** (**RFC 2560**) coinvolge un client e un responder che lavorano insieme per verificare se un certificato di chiave pubblica digitale è stato revocato, senza la necessità di scaricare l'intero **CRL**. Questo metodo è più efficiente rispetto al tradizionale **CRL**, che fornisce un elenco di numeri seriali di certificati revocati ma richiede il download di un file potenzialmente grande. I CRL possono includere fino a 512 voci. Ulteriori dettagli sono disponibili [qui](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Cos'è la Trasparenza del Certificato**

La Trasparenza del Certificato aiuta a contrastare le minacce legate ai certificati garantendo che l'emissione e l'esistenza dei certificati SSL siano visibili ai proprietari di domini, alle CA e agli utenti. I suoi obiettivi sono:

* Impedire alle CA di rilasciare certificati SSL per un dominio senza il consenso del proprietario del dominio.
* Stabilire un sistema di audit aperto per tracciare certificati rilasciati per errore o in modo malevolo.
* Proteggere gli utenti dai certificati fraudolenti.

#### **Log dei Certificati**

I log dei certificati sono registri pubblicamente verificabili e aggiornabili solo in appendice dei certificati, mantenuti da servizi di rete. Questi log forniscono prove crittografiche a fini di audit. Sia le autorità di emissione che il pubblico possono inviare certificati a questi log o interrogarli per la verifica. Sebbene il numero esatto di server di log non sia fisso, ci si aspetta che sia inferiore a mille a livello globale. Questi server possono essere gestiti in modo indipendente da CA, ISP o qualsiasi entità interessata.

#### **Interrogazione**

Per esplorare i log di Trasparenza del Certificato per un qualsiasi dominio, visita [https://crt.sh/](https://crt.sh).

Esistono formati diversi per memorizzare i certificati, ognuno con i propri casi d'uso e compatibilità. Questo riassunto copre i principali formati e fornisce indicazioni sulla conversione tra di essi.

## **Formati**

### **Formato PEM**

* Formato più ampiamente usato per i certificati.
* Richiede file separati per i certificati e le chiavi private, codificati in Base64 ASCII.
* Estensioni comuni: .cer, .crt, .pem, .key.
* Principalmente usato da Apache e server simili.

### **Formato DER**

* Un formato binario dei certificati.
* Manca delle dichiarazioni "BEGIN/END CERTIFICATE" presenti nei file PEM.
* Estensioni comuni: .cer, .der.
* Spesso usato con piattaforme Java.

### **Formato P7B/PKCS#7**

* Memorizzato in Base64 ASCII, con estensioni .p7b o .p7c.
* Contiene solo certificati e certificati di catena, escludendo la chiave privata.
* Supportato da Microsoft Windows e Java Tomcat.

### **Formato PFX/P12/PKCS#12**

* Un formato binario che racchiude certificati del server, certificati intermedi e chiavi private in un unico file.
* Estensioni: .pfx, .p12.
* Principalmente usato su Windows per l'importazione ed esportazione di certificati.

### **Conversione dei Formati**

Le **conversioni PEM** sono essenziali per la compatibilità:

* **x509 in PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM to DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER to PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM to P7B**  
  * **PEM to P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 to PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Conversioni PFX** sono cruciali per gestire i certificati su Windows:

* **PFX to PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** coinvolge due passaggi:
1. Convertire PFX in PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convert PEM to PKCS8

### Convert PEM to PKCS8

To convert a PEM (Privacy-Enhanced Mail) formatted file to PKCS8 (Public-Key Cryptography Standards #8) format, you can use the following OpenSSL command:

```bash
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.pkcs8 -nocrypt
```

This command will convert the private key in the `private.pem` file from PEM format to PKCS8 format and save it in the `private.pkcs8` file.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **Da P7B a PFX** richiede anche due comandi:
1. Converti P7B in CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Converti il file CER e la chiave privata in formato PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità **più avanzati al mondo**.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
