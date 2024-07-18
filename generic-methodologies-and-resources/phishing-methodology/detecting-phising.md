# Rilevamento del Phishing

{% hint style="success" %}
Impara e pratica il Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Introduzione

Per rilevare un tentativo di phishing è importante **comprendere le tecniche di phishing che vengono utilizzate al giorno d'oggi**. Nella pagina principale di questo post, puoi trovare queste informazioni, quindi se non sei a conoscenza delle tecniche utilizzate oggi ti consiglio di andare alla pagina principale e leggere almeno quella sezione.

Questo post si basa sull'idea che gli **attaccanti cercheranno in qualche modo di imitare o utilizzare il nome di dominio della vittima**. Se il tuo dominio si chiama `example.com` e sei stato vittima di phishing utilizzando un nome di dominio completamente diverso per qualche motivo come `youwonthelottery.com`, queste tecniche non lo scopriranno.

## Variazioni del nome di dominio

È piuttosto **facile** **scoprire** quei **tentativi di phishing** che utilizzeranno un **nome di dominio simile** all'interno dell'email.\
È sufficiente **generare un elenco dei nomi di phishing più probabili** che un attaccante potrebbe utilizzare e **controllare** se è **registrato** o semplicemente controllare se c'è qualche **IP** che lo utilizza.

### Trovare domini sospetti

A questo scopo, puoi utilizzare uno dei seguenti strumenti. Nota che questi strumenti eseguiranno anche richieste DNS automaticamente per controllare se il dominio ha qualche IP assegnato:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Puoi trovare una breve spiegazione di questa tecnica nella pagina principale. Oppure leggi la ricerca originale in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Ad esempio, una modifica di 1 bit nel dominio microsoft.com può trasformarlo in _windnws.com._\
**Gli attaccanti possono registrare quanti più domini di bit-flipping possibile relativi alla vittima per reindirizzare gli utenti legittimi alla loro infrastruttura**.

**Tutti i possibili nomi di dominio di bit-flipping dovrebbero essere monitorati.**

### Controlli di base

Una volta che hai un elenco di potenziali nomi di dominio sospetti dovresti **controllarli** (principalmente le porte HTTP e HTTPS) per **vedere se stanno utilizzando qualche modulo di accesso simile** a quello di uno dei domini della vittima.\
Potresti anche controllare la porta 3333 per vedere se è aperta e sta eseguendo un'istanza di `gophish`.\
È anche interessante sapere **quanto è vecchio ciascun dominio sospetto scoperto**, più è giovane più è rischioso.\
Puoi anche ottenere **screenshot** della pagina web sospetta HTTP e/o HTTPS per vedere se è sospetta e in tal caso **accedervi per dare un'occhiata più approfondita**.

### Controlli avanzati

Se vuoi fare un passo in più ti consiglio di **monitorare quei domini sospetti e cercarne di più** di tanto in tanto (ogni giorno? ci vogliono solo pochi secondi/minuti). Dovresti anche **controllare** le **porte** aperte degli IP correlati e **cercare istanze di `gophish` o strumenti simili** (sì, anche gli attaccanti commettono errori) e **monitorare le pagine web HTTP e HTTPS dei domini e sottodomini sospetti** per vedere se hanno copiato qualche modulo di accesso dalle pagine web della vittima.\
Per **automatizzare questo** ti consiglio di avere un elenco di moduli di accesso dei domini della vittima, eseguire lo spidering delle pagine web sospette e confrontare ciascun modulo di accesso trovato all'interno dei domini sospetti con ciascun modulo di accesso del dominio della vittima utilizzando qualcosa come `ssdeep`.\
Se hai localizzato i moduli di accesso dei domini sospetti, puoi provare a **inviare credenziali spazzatura** e **controllare se ti reindirizza al dominio della vittima**.

## Nomi di dominio che utilizzano parole chiave

La pagina principale menziona anche una tecnica di variazione del nome di dominio che consiste nel mettere il **nome di dominio della vittima all'interno di un dominio più grande** (ad es. paypal-financial.com per paypal.com).

### Trasparenza del certificato

Non è possibile adottare il precedente approccio "Brute-Force", ma è effettivamente **possibile scoprire tali tentativi di phishing** anche grazie alla trasparenza del certificato. Ogni volta che un certificato viene emesso da un CA, i dettagli vengono resi pubblici. Questo significa che leggendo la trasparenza del certificato o anche monitorandola, è **possibile trovare domini che utilizzano una parola chiave all'interno del loro nome**. Ad esempio, se un attaccante genera un certificato per [https://paypal-financial.com](https://paypal-financial.com), vedendo il certificato è possibile trovare la parola chiave "paypal" e sapere che un'email sospetta viene utilizzata.

Il post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggerisce che puoi utilizzare Censys per cercare certificati che riguardano una parola chiave specifica e filtrare per data (solo certificati "nuovi") e per l'emittente CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

Tuttavia, puoi fare "la stessa cosa" utilizzando il web gratuito [**crt.sh**](https://crt.sh). Puoi **cercare la parola chiave** e **filtrare** i risultati **per data e CA** se lo desideri.

![](<../../.gitbook/assets/image (519).png>)

Utilizzando quest'ultima opzione puoi persino utilizzare il campo Identità corrispondenti per vedere se qualche identità del dominio reale corrisponde a uno dei domini sospetti (nota che un dominio sospetto può essere un falso positivo).

**Un'altra alternativa** è il fantastico progetto chiamato [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fornisce un flusso in tempo reale di certificati appena generati che puoi utilizzare per rilevare parole chiave specificate in tempo (quasi) reale. Infatti, c'è un progetto chiamato [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) che fa proprio questo.

### **Nuovi domini**

**Un'ultima alternativa** è raccogliere un elenco di **domini appena registrati** per alcuni TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornisce tale servizio) e **controllare le parole chiave in questi domini**. Tuttavia, i domini lunghi di solito utilizzano uno o più sottodomini, quindi la parola chiave non apparirà all'interno del FLD e non sarai in grado di trovare il sottodominio di phishing.

{% hint style="success" %}
Impara e pratica il Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
