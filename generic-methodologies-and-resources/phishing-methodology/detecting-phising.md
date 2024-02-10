# Rilevare il Phishing

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Introduzione

Per rilevare un tentativo di phishing è importante **comprendere le tecniche di phishing che vengono utilizzate al giorno d'oggi**. Nella pagina principale di questo post, puoi trovare queste informazioni, quindi se non sei a conoscenza delle tecniche attualmente utilizzate, ti consiglio di andare alla pagina principale e leggere almeno quella sezione.

Questo post si basa sull'idea che gli **attaccanti cercheranno in qualche modo di imitare o utilizzare il nome di dominio della vittima**. Se il tuo dominio si chiama `esempio.com` e sei vittima di phishing utilizzando un nome di dominio completamente diverso per qualche motivo, come `hainovintolalotteria.com`, queste tecniche non lo scopriranno.

## Variazioni del nome di dominio

È abbastanza **facile** scoprire quei tentativi di **phishing** che utilizzeranno un **nome di dominio simile** all'interno dell'email.\
È sufficiente **generare una lista dei nomi di phishing più probabili** che un attaccante potrebbe utilizzare e **verificare** se è **registrato** o semplicemente verificare se c'è qualche **IP** che lo utilizza.

### Trovare domini sospetti

A tale scopo, puoi utilizzare uno qualsiasi degli strumenti seguenti. Nota che questi strumenti effettueranno automaticamente anche richieste DNS per verificare se il dominio ha un IP assegnato:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Puoi trovare una breve spiegazione di questa tecnica nella pagina principale. Oppure leggi la ricerca originale su [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

Ad esempio, una modifica di 1 bit nel dominio microsoft.com può trasformarlo in _windnws.com._\
**Gli attaccanti possono registrare quanti più domini di bit-flipping possibile correlati alla vittima per reindirizzare gli utenti legittimi alla propria infrastruttura**.

**Tutti i possibili nomi di dominio di bit-flipping dovrebbero essere monitorati anche.**

### Verifiche di base

Una volta che hai una lista di potenziali nomi di dominio sospetti, dovresti **verificarli** (principalmente le porte HTTP e HTTPS) per **vedere se stanno utilizzando un modulo di accesso simile** a quello del dominio della vittima.\
Potresti anche verificare la porta 3333 per vedere se è aperta ed esegue un'istanza di `gophish`.\
È interessante anche sapere **da quanto tempo è stato scoperto ogni dominio sospetto**, più è giovane, più è rischioso.\
Puoi anche ottenere **screenshot** della pagina web sospetta HTTP e/o HTTPS per vedere se è sospetta e in tal caso **accedervi per approfondire**.

### Verifiche avanzate

Se vuoi andare un passo avanti, ti consiglierei di **monitorare quei domini sospetti e cercarne altri** di tanto in tanto (ogni giorno? ci vogliono solo pochi secondi/minuti). Dovresti anche **verificare** le **porte aperte** degli IP correlati e **cercare istanze di `gophish` o strumenti simili** (sì, anche gli attaccanti commettono errori) e **monitorare le pagine web HTTP e HTTPS dei domini e sottodomini sospetti** per vedere se hanno copiato qualche modulo di accesso dalle pagine web della vittima.\
Per **automatizzare questo**, ti consiglierei di avere una lista di moduli di accesso dei domini della vittima, eseguire uno spider delle pagine web sospette e confrontare ogni modulo di accesso trovato all'interno dei domini sospetti con ogni modulo di accesso del dominio della vittima utilizzando qualcosa come `ssdeep`.\
Se hai individuato i moduli di accesso dei domini sospetti, puoi provare a **inviare credenziali fasulle** e **verificare se ti reindirizza al dominio della vittima**.

## Nomi di dominio che utilizzano parole chiave

La pagina principale menziona anche una tecnica di variazione del nome di dominio che consiste nel mettere il **nome di dominio della vittima all'interno di un dominio più grande** (ad esempio paypal-financial.com per paypal.com).

### Trasparenza del certificato

Non è possibile adottare l'approccio precedente "Brute-Force", ma in realtà è **possibile scoprire tali tentativi di phishing** anche grazie alla trasparenza del certificato. Ogni volta che un certificato viene emesso da una CA, i dettagli vengono resi pubblici. Ciò significa che leggendo la trasparenza del certificato o addirittura monitorandola, è **possibile trovare domini che utilizzano una parola chiave nel proprio nome**. Ad esempio, se un attaccante genera un certificato di [https://paypal-financial.com](https://paypal-financial.com), osservando il certificato è possibile trovare la parola chiave "paypal" e sapere che viene utilizzata una email sospetta.

Il post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggerisce di utilizzare Censys per cercare certificati che interessano una specifica parola chiave e filtrare per data (solo certificati "nuovi") e per l'emittente CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

Tuttavia, puoi fare "la stessa cosa" utilizzando il sito web gratuito [**crt.sh**](https://crt.sh). Puoi **cercare la parola chiave** e **filtrare** i risultati **per data e CA** se lo desideri.

![](<../../.gitbook/assets/image (391).png>)

Utilizzando questa ultima opzione, puoi anche utilizzare il campo Matching Identities per vedere se qualche identità del dominio reale corrisponde a uno dei domini sospetti (nota che un dominio sospetto può essere un falso positivo).

**Un'altra alternativa** è il fantastico progetto chiamato [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fornisce uno stream in tempo reale dei certificati appena generati che puoi utilizzare per rilevare parole chiave specificate in tempo (quasi) reale. Infatti, esiste un progetto chiamato [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) che fa proprio questo.
### **Nuovi domini**

**Un'ultima alternativa** è raccogliere un elenco di **domini appena registrati** per alcuni TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornisce tale servizio) e **verificare le parole chiave in questi domini**. Tuttavia, i domini lunghi di solito utilizzano uno o più sottodomini, quindi la parola chiave non apparirà all'interno del FLD e non sarà possibile trovare il sottodominio di phishing.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>
