# Persistenza dell'account AD CS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Questo è un breve riassunto dei capitoli sulla persistenza della macchina della fantastica ricerca di [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Comprensione del furto delle credenziali utente attive con certificati - PERSIST1**

In uno scenario in cui un utente può richiedere un certificato che consente l'autenticazione di dominio, un attaccante ha l'opportunità di **richiedere** e **rubare** questo certificato per **mantenere la persistenza** in una rete. Per impostazione predefinita, il modello `User` in Active Directory consente tali richieste, anche se a volte può essere disabilitato.

Utilizzando uno strumento chiamato [**Certify**](https://github.com/GhostPack/Certify), è possibile cercare certificati validi che consentono l'accesso persistente:
```bash
Certify.exe find /clientauth
```
È evidenziato che il potere di un certificato risiede nella sua capacità di **autenticarsi come l'utente** a cui appartiene, indipendentemente da eventuali modifiche della password, purché il certificato rimanga **valido**.

I certificati possono essere richiesti tramite un'interfaccia grafica utilizzando `certmgr.msc` o tramite la riga di comando con `certreq.exe`. Con **Certify**, il processo per richiedere un certificato viene semplificato come segue:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Una volta effettuata una richiesta di successo, viene generato un certificato insieme alla sua chiave privata nel formato `.pem`. Per convertire questo in un file `.pfx`, utilizzabile su sistemi Windows, viene utilizzato il seguente comando:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Il file `.pfx` può quindi essere caricato su un sistema di destinazione e utilizzato con uno strumento chiamato [**Rubeus**](https://github.com/GhostPack/Rubeus) per richiedere un Ticket Granting Ticket (TGT) per l'utente, estendendo l'accesso dell'attaccante per tutto il tempo in cui il certificato è **valido** (tipicamente un anno):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Viene condiviso un importante avviso su come questa tecnica, combinata con un'altra metodo descritto nella sezione **THEFT5**, permetta a un attaccante di ottenere in modo persistente l'hash **NTLM** di un account senza interagire con il servizio Local Security Authority Subsystem (LSASS), e da un contesto non elevato, fornendo un metodo più stealth per il furto di credenziali a lungo termine.

## **Ottenere Persistenza sulla Macchina con Certificati - PERSIST2**

Un altro metodo prevede l'iscrizione dell'account macchina di un sistema compromesso per un certificato, utilizzando il modello predefinito `Machine` che consente tali azioni. Se un attaccante ottiene privilegi elevati su un sistema, può utilizzare l'account **SYSTEM** per richiedere certificati, fornendo una forma di **persistenza**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Questo accesso consente all'attaccante di autenticarsi a **Kerberos** come account della macchina e utilizzare **S4U2Self** per ottenere i biglietti di servizio Kerberos per qualsiasi servizio sull'host, concedendo effettivamente all'attaccante un accesso persistente alla macchina.

## **Estendere la persistenza tramite il rinnovo dei certificati - PERSIST3**

Il metodo finale discusso coinvolge l'utilizzo dei periodi di **validità** e **rinnovo** dei modelli di certificato. Rinnovando un certificato prima della sua scadenza, un attaccante può mantenere l'autenticazione a Active Directory senza la necessità di ulteriori registrazioni dei ticket, che potrebbero lasciare tracce sul server dell'Autorità di Certificazione (CA).

Questo approccio consente un metodo di **persistenza estesa**, riducendo il rischio di rilevamento attraverso meno interazioni con il server CA e evitando la generazione di artefatti che potrebbero avvisare gli amministratori dell'intrusione.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
