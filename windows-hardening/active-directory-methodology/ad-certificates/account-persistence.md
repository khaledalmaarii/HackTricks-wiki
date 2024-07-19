# AD CS Account Persistence

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

**Questa è una piccola sintesi dei capitoli sulla persistenza della macchina della fantastica ricerca di [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Comprendere il furto delle credenziali utente attive con i certificati – PERSIST1**

In uno scenario in cui un certificato che consente l'autenticazione del dominio può essere richiesto da un utente, un attaccante ha l'opportunità di **richiedere** e **rubare** questo certificato per **mantenere la persistenza** su una rete. Per impostazione predefinita, il modello `User` in Active Directory consente tali richieste, anche se a volte può essere disabilitato.

Utilizzando uno strumento chiamato [**Certify**](https://github.com/GhostPack/Certify), è possibile cercare certificati validi che abilitano l'accesso persistente:
```bash
Certify.exe find /clientauth
```
È evidenziato che il potere di un certificato risiede nella sua capacità di **autenticarsi come l'utente** a cui appartiene, indipendentemente da eventuali cambiamenti di password, finché il certificato rimane **valido**.

I certificati possono essere richiesti tramite un'interfaccia grafica utilizzando `certmgr.msc` o tramite la riga di comando con `certreq.exe`. Con **Certify**, il processo per richiedere un certificato è semplificato come segue:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Al termine della richiesta, viene generato un certificato insieme alla sua chiave privata in formato `.pem`. Per convertire questo in un file `.pfx`, utilizzabile sui sistemi Windows, viene utilizzato il seguente comando:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Il file `.pfx` può quindi essere caricato su un sistema target e utilizzato con uno strumento chiamato [**Rubeus**](https://github.com/GhostPack/Rubeus) per richiedere un Ticket Granting Ticket (TGT) per l'utente, estendendo l'accesso dell'attaccante per tutto il tempo in cui il certificato è **valido** (tipicamente un anno):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Un avviso importante viene condiviso su come questa tecnica, combinata con un altro metodo delineato nella sezione **THEFT5**, consenta a un attaccante di ottenere in modo persistente l'**NTLM hash** di un account senza interagire con il Local Security Authority Subsystem Service (LSASS) e da un contesto non elevato, fornendo un metodo più furtivo per il furto di credenziali a lungo termine.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Un altro metodo prevede l'iscrizione dell'account macchina di un sistema compromesso per un certificato, utilizzando il modello predefinito `Machine` che consente tali azioni. Se un attaccante ottiene privilegi elevati su un sistema, può utilizzare l'account **SYSTEM** per richiedere certificati, fornendo una forma di **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Questo accesso consente all'attaccante di autenticarsi a **Kerberos** come account macchina e utilizzare **S4U2Self** per ottenere ticket di servizio Kerberos per qualsiasi servizio sull'host, concedendo effettivamente all'attaccante accesso persistente alla macchina.

## **Estensione della Persistenza Tramite Rinnovo del Certificato - PERSIST3**

Il metodo finale discusso implica l'utilizzo dei **periodi di validità** e **rinnovo** dei modelli di certificato. Rinnovando un certificato prima della sua scadenza, un attaccante può mantenere l'autenticazione ad Active Directory senza la necessità di ulteriori registrazioni di ticket, che potrebbero lasciare tracce sul server dell'Autorità di Certificazione (CA).

Questo approccio consente un metodo di **persistenza estesa**, riducendo il rischio di rilevamento attraverso interazioni minori con il server CA e evitando la generazione di artefatti che potrebbero allertare gli amministratori sull'intrusione.
