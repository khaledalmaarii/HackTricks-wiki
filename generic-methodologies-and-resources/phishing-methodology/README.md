# Metodologia di Phishing

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Metodologia

1. Ricognizione della vittima
1. Seleziona il **dominio della vittima**.
2. Esegui una enumerazione web di base **cercando portali di accesso** utilizzati dalla vittima e **decidi** quale **impersonare**.
3. Utilizza un po' di **OSINT** per **trovare email**.
2. Prepara l'ambiente
1. **Acquista il dominio** che utilizzerai per la valutazione del phishing
2. **Configura il servizio email** record correlati (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **modello di email**
2. Prepara la **pagina web** per rubare le credenziali
4. Lanciare la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di Variazione del Nome di Dominio

* **Parola chiave**: Il nome di dominio **contiene** una parola chiave importante del dominio originale (ad es., zelster.com-management.com).
* **Sottodominio con trattino**: Cambia il **punto con un trattino** di un sottodominio (ad es., www-zelster.com).
* **Nuovo TLD**: Stesso dominio utilizzando un **nuovo TLD** (ad es., zelster.org)
* **Omofono**: Sostituisce una lettera nel nome di dominio con **lettere simili** (ad es., zelfser.com).
* **Trasposizione**: Scambia due lettere all'interno del nome di dominio (ad es., zelsetr.com).
* **Singolarizzazione/Pluralizzazione**: Aggiunge o rimuove "s" alla fine del nome di dominio (ad es., zeltsers.com).
* **Omissione**: Rimuove una delle lettere dal nome di dominio (ad es., zelser.com).
* **Ripetizione**: Ripete una delle lettere nel nome di dominio (ad es., zeltsser.com).
* **Sostituzione**: Come omofono ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, forse con una lettera vicina alla lettera originale sulla tastiera (ad es., zektser.com).
* **Sottodominiato**: Introduce un **punto** all'interno del nome di dominio (ad es., ze.lster.com).
* **Inserimento**: **Inserisce una lettera** nel nome di dominio (ad es., zerltser.com).
* **Punto mancante**: Aggiungi il TLD al nome di dominio. (ad es., zelstercom.com)

**Strumenti Automatici**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti Web**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che uno o alcuni bit memorizzati o in comunicazione possano essere automaticamente invertiti** a causa di vari fattori come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso del dominio richiesto inizialmente.

Ad esempio, una modifica di un singolo bit nel dominio "windows.com" può cambiarlo in "windnws.com."

Gli attaccanti possono **approfittarne registrando più domini con bit-flipping** simili al dominio della vittima. La loro intenzione è di reindirizzare gli utenti legittimi alla propria infrastruttura.

Per ulteriori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acquista un dominio affidabile

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti utilizzare.\
Per assicurarti che il dominio scaduto che stai per acquistare **abbia già un buon SEO** puoi verificare come è categorizzato in:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoperta delle Email

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già scoperto, puoi verificare se puoi effettuare un attacco di forza bruta ai server smtp della vittima. [Scopri come verificare/scoprire l'indirizzo email qui](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti utilizzano **qualsiasi portale web per accedere alle loro email**, puoi verificare se è vulnerabile a **forza bruta sul nome utente**, ed sfruttare la vulnerabilità se possibile.

## Configurazione di GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decompattalo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'utente admin sulla porta 3333 nell'output. Quindi, accedi a quella porta e utilizza quelle credenziali per cambiare la password dell'admin. Potresti aver bisogno di tunnelare quella porta in locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **già aver acquistato il dominio** che stai per utilizzare e deve essere **puntato** all'**IP del VPS** dove stai configurando **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Configurazione della posta**

Inizia l'installazione: `apt-get install postfix`

Quindi aggiungi il dominio ai seguenti file:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Modifica anche i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il nome del tuo dominio e **riavvia il tuo VPS.**

Ora, crea un **record A DNS** di `mail.<domain>` che punta all'**indirizzo IP** del VPS e un record **MX DNS** che punta a `mail.<domain>`

Ora proviamo a inviare un'email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Interrompere l'esecuzione di gophish e procedere con la configurazione.\
Modificare `/opt/gophish/config.json` come segue (notare l'uso di https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Configurare il servizio gophish**

Per creare il servizio gophish in modo che possa essere avviato automaticamente e gestito come servizio, è possibile creare il file `/etc/init.d/gophish` con il seguente contenuto:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Completa la configurazione del servizio e controlla facendo:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Configurazione del server di posta e del dominio

### Attendere e essere legittimi

Più vecchio è un dominio, meno probabile è che venga considerato spam. Quindi è consigliabile attendere il più a lungo possibile (almeno 1 settimana) prima dell'assessment di phishing. Inoltre, se si inserisce una pagina su un settore reputazionale, si otterrà una migliore reputazione.

Nota che anche se devi aspettare una settimana, puoi finire di configurare tutto adesso.

### Configurare il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS al nome di dominio.

### Record del Framework di Politica del Mittente (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/#spf).

Puoi utilizzare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua politica SPF (utilizza l'IP della macchina VPS)

![](<../../.gitbook/assets/image (388).png>)

Questo è il contenuto che deve essere impostato all'interno di un record TXT all'interno del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record di Autenticazione, Reporting e Conformità dei Messaggi Basato sul Dominio (DMARC)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<dominio>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Devi concatenare entrambi i valori B64 che la chiave DKIM genera:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Testa il punteggio della configurazione della tua email

Puoi farlo utilizzando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta accedere alla pagina e inviare un'email all'indirizzo che ti viene fornito:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **controllare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e visualizzare la risposta nel file _/var/mail/root_ se invii l'email come root).\
Verifica di superare tutti i test:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Puoi anche inviare un **messaggio a un account Gmail sotto il tuo controllo**, e controllare gli **intestazioni dell'email** nella tua casella di posta Gmail, `dkim=pass` dovrebbe essere presente nel campo dell'intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Rimozione dalla lista nera di Spamhouse

La pagina [www.mail-tester.com](www.mail-tester.com) può indicarti se il tuo dominio è bloccato da Spamhouse. Puoi richiedere la rimozione del tuo dominio/IP su: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla lista nera di Microsoft

Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Creare e Lanciare una Campagna di Phishing con GoPhish

### Profilo di Invio

* Imposta un **nome per identificare** il profilo del mittente
* Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
* Puoi lasciare vuoti il nome utente e la password, ma assicurati di controllare l'opzione Ignora gli errori del certificato

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Si consiglia di utilizzare la funzionalità "**Invia Email di Test**" per verificare che tutto funzioni correttamente.\
Consiglio di **inviare le email di test agli indirizzi email temporanei** per evitare di finire in blacklist durante i test.
{% endhint %}

### Modello di Email

* Imposta un **nome per identificare** il modello
* Poi scrivi un **oggetto** (niente di strano, solo qualcosa che ti aspetteresti di leggere in una normale email)
* Assicurati di aver selezionato "**Aggiungi Immagine di Tracciamento**"
* Scrivi il **modello di email** (puoi utilizzare variabili come nell'esempio seguente):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Nota che **per aumentare la credibilità dell'email**, è consigliabile utilizzare una firma da un'email del cliente. Suggerimenti:

* Invia un'email a un **indirizzo inesistente** e controlla se la risposta ha una firma.
* Cerca **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e invia loro un'email in attesa di risposta.
* Prova a contattare **alcune email valide scoperte** e attendi la risposta

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Il Modello di Email consente anche di **allegare file da inviare**. Se desideri rubare le sfide NTLM utilizzando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Pagina di Atterraggio

* Scrivi un **nome**
* **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
* Seleziona **Cattura Dati Inviati** e **Cattura Password**
* Imposta un **reindirizzamento**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Di solito sarà necessario modificare il codice HTML della pagina e fare alcuni test in locale (magari utilizzando un server Apache) **fino a ottenere i risultati desiderati**. Successivamente, inserisci quel codice HTML nella casella.\
Nota che se hai bisogno di **utilizzare risorse statiche** per l'HTML (forse alcune pagine CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Per il reindirizzamento potresti **reindirizzare gli utenti alla pagina web principale legittima** della vittima, o reindirizzarli a _/static/migration.html_ ad esempio, mettere una **rotella che gira (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.
{% endhint %}

### Utenti e Gruppi

* Imposta un nome
* **Importa i dati** (nota che per utilizzare il modello per l'esempio hai bisogno del nome, cognome e indirizzo email di ciascun utente)

![](<../../.gitbook/assets/image (395).png>)

### Campagna

Infine, crea una campagna selezionando un nome, il modello di email, la pagina di atterraggio, l'URL, il profilo di invio e il gruppo. Nota che l'URL sarà il link inviato alle vittime

Nota che il **Profilo di Invio permette di inviare un'email di test per vedere come apparirà l'email di phishing finale**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Consiglio di **inviare le email di test a indirizzi email temporanei** per evitare di finire in blacklist durante i test.
{% endhint %}

Una volta che tutto è pronto, avvia semplicemente la campagna!

## Clonazione del Sito Web

Se per qualche motivo desideri clonare il sito web, controlla la seguente pagina:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documenti e File con Backdoor

In alcune valutazioni di phishing (principalmente per Red Team) vorrai anche **inviare file contenenti qualche tipo di backdoor** (forse un C2 o forse qualcosa che attiverà un'autenticazione).\
Consulta la seguente pagina per alcuni esempi:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Tramite Proxy MitM

L'attacco precedente è piuttosto intelligente poiché stai falsificando un sito web reale e raccogliendo le informazioni inserite dall'utente. Purtroppo, se l'utente non ha inserito la password corretta o se l'applicazione che hai falsificato è configurata con l'autenticazione a due fattori, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo strumento ti permetterà di generare un attacco tipo MitM. Fondamentalmente, l'attacco funziona nel seguente modo:

1. **Impersoni il modulo di login** della pagina web reale.
2. L'utente **invia** le **proprie credenziali** alla tua pagina falsa e lo strumento le invia alla pagina reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM chiederà di inserirlo e una volta che l'**utente lo inserisce**, lo strumento lo invierà alla pagina web reale.
4. Una volta autenticato l'utente, tu (come attaccante) avrai **catturato le credenziali, il 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento sta eseguendo un MitM.

### Tramite VNC

E se invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto di quella originale, la invii a una **sessione VNC con un browser connesso alla pagina web reale**? Sarai in grado di vedere cosa fa, rubare la password, il MFA utilizzato, i cookie...\
Puoi fare ciò con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Rilevare il Rilevamento

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se compare, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio appare in una qualsiasi blacklist è utilizzare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per sapere se la vittima sta **cercando attivamente attività di phishing sospette in rete** come spiegato in:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Puoi **acquistare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te **contenente** la **parola chiave** del dominio della vittima. Se la **vittima** effettua qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che **sta cercando attivamente** domini sospetti e dovrai essere molto stealth.

### Valutare il Phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam o se verrà bloccata o avrà successo.

## Riferimenti

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
